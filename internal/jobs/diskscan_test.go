package jobs

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/distro"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

func testLimits() DiskScanLimits {
	l := DefaultDiskScanLimits()
	l.SnapshotWait = time.Minute
	return l
}

func clock() time.Time { return fakeNow }

// ---- plan ----

func vmAsset(id, vol, conn string, extra map[string]string) asset.Asset {
	meta := map[string]string{"root_volume_id": vol, "prov_connector_id": conn, "image_id": "ami-1"}
	for k, v := range extra {
		meta[k] = v
	}
	return asset.Asset{ID: id, Type: "ec2_instance", Region: "eu-west-1", Metadata: meta}
}

func TestPlan_EnqueuesVolumesInTheRunTransactionAndSkipsWhatIsKnownOrRecent(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.enabled = []diskscan.ConnectorSettings{{ConnectorID: "c1", Type: "aws", Mode: diskscan.DiskScanModeExistingSnapshots}}
	svc.latest["vm-recent"] = diskscan.VolumeResult{VolumeRef: "vol-recent", InventoryKnown: true, ObservedAt: fakeNow.Add(-time.Hour)}
	svc.latest["vm-old"] = diskscan.VolumeResult{VolumeRef: "vol-old", InventoryKnown: true, ObservedAt: fakeNow.Add(-48 * time.Hour)}
	svc.latest["vm-gap"] = diskscan.VolumeResult{VolumeRef: "vol-gap", Gap: diskscan.GapReadError, ObservedAt: fakeNow.Add(-time.Hour)}
	assets := fakeAssets{byType: map[string][]asset.Asset{
		"ec2_instance": {
			vmAsset("vm-new", "vol-new", "c1", nil),
			vmAsset("vm-recent", "vol-recent", "c1", nil),
			vmAsset("vm-old", "vol-old", "c1", nil),
			vmAsset("vm-gap", "vol-gap", "c1", nil),
			vmAsset("vm-ssm", "vol-ssm", "c1", map[string]string{asset.MetaPackageInventory: asset.PackageInventorySSM}),
			vmAsset("vm-other", "vol-other", "c2", nil),
			vmAsset("vm-novol", "", "c1", nil),
		},
		"ebs_volume": {{ID: "vol-new", Metadata: map[string]string{"size_gb": "40"}}},
	}}
	ins, clouds := &fakeDiskInserter{}, &fakeClouds{}
	w := &DiskScanPlanWorker{svc: svc, assets: assets, clouds: clouds, inserts: ins, limits: testLimits(), now: clock}

	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanPlanArgs]{}))

	var got []string
	for _, p := range ins.params {
		a := p.Args.(DiskScanVolumeArgs)
		got = append(got, a.AssetID)
		require.Equal(t, "run-1", a.RunID)
		require.Equal(t, 2, a.Planned)
		require.Equal(t, []byte("sealed"), a.Sealed)
	}
	require.ElementsMatch(t, []string{"vm-new", "vm-old"}, got,
		"unknown inventory and a stale known result are planned; a recent result, SSM, another connector and no volume are not")
	require.Equal(t, 40, ins.params[0].Args.(DiskScanVolumeArgs).SizeGiB)
	require.Equal(t, []string{"c1|run-1"}, clouds.sealedFor, "credentials are sealed once per run, bound to it")
}

func TestPlan_SealsCredentialsForTheConfiguredLifetime(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.enabled = []diskscan.ConnectorSettings{{ConnectorID: "c1", Type: "aws", Mode: diskscan.DiskScanModeExistingSnapshots}}
	clouds := &fakeClouds{}
	lim := testLimits()
	lim.CredentialLifetime = 20 * time.Minute
	w := &DiskScanPlanWorker{svc: svc, assets: fakeAssets{byType: map[string][]asset.Asset{"ec2_instance": {vmAsset("vm", "vol", "c1", nil)}}},
		clouds: clouds, inserts: &fakeDiskInserter{}, limits: lim, now: clock}
	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanPlanArgs]{}))
	require.Equal(t, []time.Time{fakeNow.Add(20 * time.Minute)}, clouds.sealedExp)
	require.GreaterOrEqual(t, DefaultDiskScanLimits().CredentialLifetime, 15*time.Minute)
	require.LessOrEqual(t, DefaultDiskScanLimits().CredentialLifetime, time.Hour)
}

func TestPlan_ARunStillInFlightIsNotPlannedAgain(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.enabled = []diskscan.ConnectorSettings{{ConnectorID: "c1", Type: "aws", Mode: diskscan.DiskScanModeExistingSnapshots}}
	svc.runs = []diskscan.DiskScanRun{{ID: "live", Status: diskscan.StatusRunning, StartedAt: fakeNow.Add(-10 * time.Minute)}}
	ins := &fakeDiskInserter{}
	w := &DiskScanPlanWorker{svc: svc, assets: fakeAssets{byType: map[string][]asset.Asset{"ec2_instance": {vmAsset("vm", "vol", "c1", nil)}}},
		clouds: &fakeClouds{}, inserts: ins, limits: testLimits(), now: clock}
	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanPlanArgs]{}))
	require.Empty(t, ins.params, "its jobs hold credentials that are about to run out")
	require.Empty(t, svc.finished)
}

func TestPlan_AStaleGapIsPlannedAgainAtOnce(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.enabled = []diskscan.ConnectorSettings{{ConnectorID: "c1", Type: "aws", Mode: diskscan.DiskScanModeExistingSnapshots}}
	svc.latest["vm"] = diskscan.VolumeResult{VolumeRef: "vol", Gap: diskscan.GapStale, ObservedAt: fakeNow.Add(-time.Minute)}
	ins := &fakeDiskInserter{}
	w := &DiskScanPlanWorker{svc: svc, assets: fakeAssets{byType: map[string][]asset.Asset{"ec2_instance": {vmAsset("vm", "vol", "c1", nil)}}},
		clouds: &fakeClouds{}, inserts: ins, limits: testLimits(), now: clock}
	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanPlanArgs]{}))
	require.Len(t, ins.params, 1, "expired credentials say nothing about the disk")
}

func TestPlan_NoTargetsOpensNoRun(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.enabled = []diskscan.ConnectorSettings{{ConnectorID: "c1", Type: "aws", Mode: diskscan.DiskScanModeExistingSnapshots}}
	w := &DiskScanPlanWorker{svc: svc, assets: fakeAssets{}, clouds: &fakeClouds{}, inserts: &fakeDiskInserter{}, limits: testLimits(), now: clock}
	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanPlanArgs]{}))
	require.Zero(t, svc.planned)
}

func TestPlan_ClosesStaleRunsPartial(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.enabled = []diskscan.ConnectorSettings{{ConnectorID: "c1", Type: "aws", Mode: diskscan.DiskScanModeExistingSnapshots}}
	svc.runs = []diskscan.DiskScanRun{
		{ID: "old", Status: diskscan.StatusRunning, StartedAt: fakeNow.Add(-13 * time.Hour)},
		{ID: "fresh", Status: diskscan.StatusRunning, StartedAt: fakeNow.Add(-time.Hour)},
		{ID: "done", Status: diskscan.StatusSucceeded, StartedAt: fakeNow.Add(-30 * time.Hour)},
	}
	w := &DiskScanPlanWorker{svc: svc, assets: fakeAssets{}, clouds: &fakeClouds{}, inserts: &fakeDiskInserter{}, limits: testLimits(), now: clock}
	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanPlanArgs]{}))
	require.Equal(t, []string{"old"}, svc.finished)
}

func TestPlan_CapsVolumesPerRun(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.enabled = []diskscan.ConnectorSettings{{ConnectorID: "c1", Type: "aws", Mode: diskscan.DiskScanModeExistingSnapshots}}
	var vms []asset.Asset
	for _, n := range []string{"a", "b", "c"} {
		vms = append(vms, vmAsset("vm-"+n, "vol-"+n, "c1", nil))
	}
	lim := testLimits()
	lim.MaxVolumesPerRun = 2
	ins := &fakeDiskInserter{}
	w := &DiskScanPlanWorker{svc: svc, assets: fakeAssets{byType: map[string][]asset.Asset{"ec2_instance": vms}},
		clouds: &fakeClouds{}, inserts: ins, limits: lim, now: clock}
	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanPlanArgs]{}))
	require.Len(t, ins.params, 2)
}

// ---- volume ----

func volumeJob(attempt int) *river.Job[DiskScanVolumeArgs] {
	return &river.Job[DiskScanVolumeArgs]{
		JobRow: &rivertype.JobRow{Attempt: attempt, MaxAttempts: 3},
		Args: DiskScanVolumeArgs{
			RunID: "run-1", AssetID: "vm-1", VolumeRef: "vol-1", ConnectorID: "c1", Provider: "aws",
			Region: "eu-west-1", Planned: 1, Sealed: []byte("sealed"),
		},
	}
}

func knownScan(pkgs int) func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error) {
	return func(_ context.Context, src engine.BlockSource, _ engine.Limits) (engine.DiskResult, error) {
		_, _ = src.ReadAt(make([]byte, 512), 1024)
		out := engine.DiskResult{Ecosystem: "Debian:12", InventoryKnown: true}
		for i := range pkgs {
			out.Packages = append(out.Packages, pkginventory.InstalledPackage{Ecosystem: "Debian:12", Name: "pkg" + string(rune('a'+i)), Version: "1", SourceName: "src"})
		}
		return out, nil
	}
}

func gapScan(gap string) func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error) {
	return func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error) {
		return engine.DiskResult{Gap: gap}, nil
	}
}

func newVolumeWorker(svc *fakeDiskSvc, cloud *fakeCloud, role string, scan func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error)) *DiskScanVolumeWorker {
	return &DiskScanVolumeWorker{
		svc: svc, clouds: &fakeClouds{cloud: cloud, role: role, others: []string{"collection-role"}},
		advisory: distro.Sources{distro.SourceOSV: true}, limits: testLimits(), now: clock, scanDisk: scan,
	}
}

var snapOld = engine.Snapshot{ID: "snap-1", Provider: "aws", Region: "eu-west-1", VolumeID: "vol-1", CreatedAt: fakeNow.Add(-2 * time.Hour)}

func TestVolume_ExistingSnapshotIsReadAndNeverCreatesOne(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	cloud := &fakeCloud{snaps: []engine.Snapshot{snapOld}}
	w := newVolumeWorker(svc, cloud, "", knownScan(2))

	require.NoError(t, w.Work(context.Background(), volumeJob(1)))

	require.Zero(t, cloud.created)
	require.Empty(t, cloud.deleted)
	require.Len(t, svc.recorded, 1)
	res := svc.recorded[0]
	require.True(t, res.InventoryKnown)
	require.Equal(t, diskscan.SourceReused, res.SnapshotSource)
	require.Equal(t, 2, res.PackageCount)
	require.Equal(t, snapOld.CreatedAt, res.ObservedAt, "the capture time, not when the job looked")
	require.True(t, res.CVEMatchableKnown, "Debian:12 with OSV on and source names present")
	require.Equal(t, []string{"packages", "record:"}, svc.events, "packages are stored before the result that vouches for them")
	require.Equal(t, []string{"run-1"}, svc.finished, "the last planned volume closes the run")
	require.Contains(t, svc.cache, "aws|snap-1", "a reused snapshot's result is cached")
}

func TestVolume_ModeOffRecordsNotEnabledWithoutTouchingTheCloud(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeOff)
	cloud := &fakeCloud{snaps: []engine.Snapshot{snapOld}}
	require.NoError(t, newVolumeWorker(svc, cloud, "role", knownScan(1)).Work(context.Background(), volumeJob(1)))
	require.Equal(t, diskscan.GapNotEnabled, svc.recorded[0].Gap)
	require.False(t, svc.recorded[0].InventoryKnown)
	require.Zero(t, cloud.listCalls)
	require.Zero(t, cloud.created)
}

func TestVolume_NoSnapshotAvailableInExistingMode(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	cloud := &fakeCloud{}
	require.NoError(t, newVolumeWorker(svc, cloud, "role", knownScan(1)).Work(context.Background(), volumeJob(1)))
	require.Equal(t, diskscan.GapNoSnapshotAvailable, svc.recorded[0].Gap)
	require.Zero(t, cloud.created, "existing_snapshots mode never creates")
}

func TestVolume_PermissionDeniedIsRecordedCachedAndNotRetried(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	cloud := &fakeCloud{listErr: ErrDiskPermissionDenied}
	require.NoError(t, newVolumeWorker(svc, cloud, "", knownScan(1)).Work(context.Background(), volumeJob(1)),
		"a denial is a recorded state, not an error to retry")
	require.Equal(t, diskscan.GapPermissionDenied, svc.recorded[0].Gap)
	e, ok := svc.cache["aws|denied:c1"]
	require.True(t, ok)
	require.Equal(t, fakeNow.Add(24*time.Hour), e.ExpiresAt)
}

func TestVolume_EnvelopeUnusableIsAGapNotARetry(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	w := newVolumeWorker(svc, &fakeCloud{}, "", knownScan(1))
	w.clouds = &fakeClouds{openErr: ErrDiskEnvelope}
	require.NoError(t, w.Work(context.Background(), volumeJob(1)))
	require.Equal(t, diskscan.GapReadError, svc.recorded[0].Gap)
}

func TestVolume_NothingReadableIsNeverClean(t *testing.T) {
	for _, tc := range []struct {
		name string
		scan func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error)
		want string
	}{
		{"unsupported filesystem", gapScan(diskscan.GapUnsupportedFS), diskscan.GapUnsupportedFS},
		{"a known read of zero packages", func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error) {
			return engine.DiskResult{InventoryKnown: true, Ecosystem: "Debian:12"}, nil
		}, diskscan.GapReadError},
		{"a gap with no reason", gapScan(""), diskscan.GapReadError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
			cloud := &fakeCloud{snaps: []engine.Snapshot{snapOld}}
			require.NoError(t, newVolumeWorker(svc, cloud, "", tc.scan).Work(context.Background(), volumeJob(1)))
			res := svc.recorded[0]
			require.False(t, res.InventoryKnown)
			require.False(t, res.CVEMatchableKnown)
			require.Zero(t, res.PackageCount)
			require.Equal(t, tc.want, res.Gap)
			require.Empty(t, svc.packages)
		})
	}
}

func TestVolume_EncryptedWithoutKeyIsItsOwnGap(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	cloud := &fakeCloud{snaps: []engine.Snapshot{snapOld}, openErr: ErrDiskEncryptedNoKey}
	require.NoError(t, newVolumeWorker(svc, cloud, "", knownScan(1)).Work(context.Background(), volumeJob(1)))
	require.Equal(t, diskscan.GapEncryptedNoKey, svc.recorded[0].Gap)
	require.True(t, svc.recorded[0].Encrypted)
}

func TestVolume_TransientErrorRetriesThenRecordsReadErrorOnTheLastAttempt(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	cloud := &fakeCloud{snaps: []engine.Snapshot{snapOld}, openErr: errors.New("connection reset")}
	w := newVolumeWorker(svc, cloud, "", knownScan(1))

	require.Error(t, w.Work(context.Background(), volumeJob(1)), "an early attempt returns the error so River retries")
	require.Empty(t, svc.recorded)

	require.NoError(t, w.Work(context.Background(), volumeJob(3)))
	require.Equal(t, diskscan.GapReadError, svc.recorded[0].Gap, "out of attempts, the volume reads unknown and the run can close")
	require.Equal(t, []string{"run-1"}, svc.finished)
}

func TestVolume_ReusesACachedResultWithoutReadingTheDisk(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.cache["aws|snap-1"] = diskscan.CacheEntry{Provider: "aws", SnapshotID: "snap-1",
		Result: diskscan.VolumeResult{InventoryKnown: true, CVEMatchableKnown: true, PackageCount: 3}}
	svc.packages = []diskscan.PackageSet{{AssetID: "vm-1", VolumeRef: "vol-1", SnapshotID: "snap-1", Packages: []pkginventory.InstalledPackage{{Name: "a"}}}}
	scans := 0
	w := newVolumeWorker(svc, &fakeCloud{snaps: []engine.Snapshot{snapOld}}, "", func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error) {
		scans++
		return engine.DiskResult{}, nil
	})
	require.NoError(t, w.Work(context.Background(), volumeJob(1)))
	require.Zero(t, scans)
	require.True(t, svc.recorded[0].InventoryKnown)
	require.Equal(t, 3, svc.recorded[0].PackageCount)
}

func TestVolume_CachedKnownResultWithoutItsPackagesIsReadAgain(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	svc.cache["aws|snap-1"] = diskscan.CacheEntry{Provider: "aws", SnapshotID: "snap-1",
		Result: diskscan.VolumeResult{InventoryKnown: true, PackageCount: 3}}
	scans := 0
	scan := knownScan(1)
	w := newVolumeWorker(svc, &fakeCloud{snaps: []engine.Snapshot{snapOld}}, "", func(c context.Context, s engine.BlockSource, l engine.Limits) (engine.DiskResult, error) {
		scans++
		return scan(c, s, l)
	})
	require.NoError(t, w.Work(context.Background(), volumeJob(1)))
	require.Equal(t, 1, scans, "a verdict is never applied without the package list it vouches for")
}

func TestVolume_ChangedBlocksOutsideTheTouchedExtentsReuseThePreviousResult(t *testing.T) {
	prev := engine.Snapshot{ID: "snap-0", Provider: "aws", Region: "eu-west-1", VolumeID: "vol-1", CreatedAt: fakeNow.Add(-72 * time.Hour)}
	for _, tc := range []struct {
		name    string
		changed []engine.Extent
		scans   int
	}{
		{"change elsewhere on the disk", []engine.Extent{{Offset: 1 << 30, Length: 4096}}, 0},
		{"change inside a block the scan read", []engine.Extent{{Offset: 1024, Length: 512}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
			svc.latest["vm-1"] = diskscan.VolumeResult{VolumeRef: "vol-1", SnapshotID: "snap-0", InventoryKnown: true, PackageCount: 1}
			svc.cache["aws|snap-0"] = diskscan.CacheEntry{Provider: "aws", SnapshotID: "snap-0",
				Extents: []engine.Extent{{Offset: 0, Length: 4096}}, Result: diskscan.VolumeResult{InventoryKnown: true, PackageCount: 1}}
			svc.packages = []diskscan.PackageSet{{AssetID: "vm-1", VolumeRef: "vol-1", SnapshotID: "snap-0", Ecosystem: "Debian:12", Packages: []pkginventory.InstalledPackage{{Name: "a"}}}}
			cloud := &fakeCloud{snaps: []engine.Snapshot{snapOld, prev}, changed: tc.changed}
			if tc.name == "change elsewhere on the disk" {
				cloud.changed = tc.changed
			}
			scans := 0
			scan := knownScan(1)
			w := newVolumeWorker(svc, cloud, "", func(c context.Context, s engine.BlockSource, l engine.Limits) (engine.DiskResult, error) {
				scans++
				return scan(c, s, l)
			})
			require.NoError(t, w.Work(context.Background(), volumeJob(1)))
			require.Equal(t, tc.scans, scans)
			require.True(t, svc.recorded[0].InventoryKnown)
			require.Equal(t, "snap-1", svc.recorded[0].SnapshotID)
		})
	}
}

// ---- expired credentials ----

func TestVolume_ExpiredCredentialsAreAGapNeverARetryLoop(t *testing.T) {
	t.Run("sealed envelope already expired", func(t *testing.T) {
		svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
		cloud := &fakeCloud{}
		w := createWorker(svc, cloud, knownScan(1))
		w.clouds = &fakeClouds{openErr: ErrDiskCredentialsExpired}
		require.NoError(t, w.Work(context.Background(), volumeJob(1)))
		require.Equal(t, diskscan.GapStale, svc.recorded[0].Gap)
		require.False(t, svc.recorded[0].InventoryKnown)
		require.Zero(t, cloud.created)
		require.Equal(t, []string{"run-1"}, svc.finished, "the run still closes")
	})
	t.Run("expire while listing", func(t *testing.T) {
		svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
		cloud := &fakeCloud{listErr: ErrDiskCredentialsExpired}
		require.NoError(t, newVolumeWorker(svc, cloud, "", knownScan(1)).Work(context.Background(), volumeJob(1)))
		require.Equal(t, diskscan.GapStale, svc.recorded[0].Gap)
	})
	t.Run("expire while creating", func(t *testing.T) {
		svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
		cloud := &fakeCloud{createErr: ErrDiskCredentialsExpired}
		require.NoError(t, createWorker(svc, cloud, knownScan(1)).Work(context.Background(), volumeJob(1)))
		require.Equal(t, diskscan.GapStale, svc.recorded[0].Gap)
		require.Zero(t, cloud.created)
	})
	t.Run("expire mid-scan: the snapshot is left to the sweep", func(t *testing.T) {
		svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
		cloud := &fakeCloud{deleteErr: ErrDiskCredentialsExpired, openErr: ErrDiskCredentialsExpired}
		require.NoError(t, createWorker(svc, cloud, knownScan(1)).Work(context.Background(), volumeJob(1)))
		require.Equal(t, diskscan.GapStale, svc.recorded[0].Gap)
		require.Empty(t, svc.markedIntent, "an undeleted snapshot keeps its intent for the sweep")
	})
}

// ---- Azure-style read grants ----

func TestVolume_ReadOptInHoldsInBothModesAndNeverCreates(t *testing.T) {
	for _, mode := range []diskscan.DiskScanMode{diskscan.DiskScanModeExistingSnapshots, diskscan.DiskScanModeCreateSnapshots} {
		t.Run(string(mode), func(t *testing.T) {
			svc := newFakeDiskSvc(mode)
			cloud := &fakeCloud{snaps: []engine.Snapshot{snapOld}}
			require.NoError(t, newVolumeWorker(svc, cloud, "client-ds", knownScan(2)).Work(context.Background(), volumeJob(1)))

			require.True(t, svc.recorded[0].InventoryKnown)
			require.Zero(t, cloud.created, "an existing snapshot is read, never created")
			require.Empty(t, cloud.deleted)
			require.Equal(t, 1, cloud.grants)
			require.Equal(t, cloud.grants, cloud.revokes, "every read grant is revoked")
			for _, ins := range cloud.providerIns {
				require.True(t, ins.Read.Valid(), "the read opt-in is minted in both modes")
				require.Equal(t, mode == diskscan.DiskScanModeCreateSnapshots, ins.Create.Valid(),
					"the create opt-in exists only in create_snapshots mode")
			}
		})
	}
}

func TestVolume_AzureExistingSnapshots_GrantIsRevokedOnEveryPath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cloud   *fakeCloud
		scan    func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error)
		wantErr bool
	}{
		{"read ok", &fakeCloud{snaps: []engine.Snapshot{snapOld}}, knownScan(1), false},
		{"unreadable disk", &fakeCloud{snaps: []engine.Snapshot{snapOld}}, gapScan(diskscan.GapUnsupportedFS), false},
		{"open fails after the grant", &fakeCloud{snaps: []engine.Snapshot{snapOld}, openErr: errors.New("boom")}, knownScan(1), true},
		{"scan fails", &fakeCloud{snaps: []engine.Snapshot{snapOld}}, func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error) {
			return engine.DiskResult{}, errors.New("boom")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
			err := newVolumeWorker(svc, tc.cloud, "client-ds", tc.scan).Work(context.Background(), volumeJob(1))
			require.Equal(t, tc.wantErr, err != nil)
			require.Equal(t, 1, tc.cloud.grants)
			require.Equal(t, tc.cloud.grants, tc.cloud.revokes, "the grant is always revoked")
			require.Zero(t, tc.cloud.created, "no snapshot is ever created")
			require.Empty(t, tc.cloud.deleted, "no snapshot is ever deleted")
		})
	}
}

func TestVolume_NoPrincipalMeansNoReadOptIn(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeExistingSnapshots)
	cloud := &fakeCloud{snaps: []engine.Snapshot{snapOld}}
	require.NoError(t, newVolumeWorker(svc, cloud, "", knownScan(1)).Work(context.Background(), volumeJob(1)))
	require.Zero(t, cloud.grants, "AWS-style existing mode reads with no opt-in at all")
	for _, ins := range cloud.providerIns {
		require.False(t, ins.Read.Valid())
		require.False(t, ins.Create.Valid())
	}
}

// ---- create path ----

func createWorker(svc *fakeDiskSvc, cloud *fakeCloud, scan func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error)) *DiskScanVolumeWorker {
	return newVolumeWorker(svc, cloud, "disk-scan-role", scan)
}

func TestVolume_CreatePathRegistersIntentFirstAndAlwaysCleansUp(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cloud     *fakeCloud
		scan      func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error)
		wantErr   bool
		wantKnown bool
		wantGap   string
	}{
		{"success", &fakeCloud{}, knownScan(1), false, true, ""},
		{"unreadable disk", &fakeCloud{}, gapScan(diskscan.GapUnsupportedFS), false, false, diskscan.GapUnsupportedFS},
		{"open fails", &fakeCloud{openErr: errors.New("boom")}, knownScan(1), true, false, ""},
		{"wait fails", &fakeCloud{waitErr: errors.New("boom")}, knownScan(1), true, false, ""},
		{"scan fails", &fakeCloud{}, func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error) {
			return engine.DiskResult{}, errors.New("boom")
		}, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
			err := createWorker(svc, tc.cloud, tc.scan).Work(context.Background(), volumeJob(1))
			require.Equal(t, tc.wantErr, err != nil)

			require.Equal(t, 1, tc.cloud.created)
			require.Equal(t, []string{"snap-new-1"}, tc.cloud.deleted, "every path deletes the snapshot it created")
			require.Equal(t, []string{"intent-vol-1"}, svc.markedIntent)
			require.Equal(t, "intent", svc.events[0], "the intent row is written before the create call")
			if !tc.wantErr {
				require.Equal(t, tc.wantKnown, svc.recorded[0].InventoryKnown)
				require.Equal(t, tc.wantGap, svc.recorded[0].Gap)
				require.Equal(t, diskscan.SourceCreated, svc.recorded[0].SnapshotSource)
			}
			require.NotContains(t, svc.cache, "aws|snap-new-1", "a snapshot about to be deleted is not cached")
		})
	}
}

func TestVolume_CleanupRunsOnAFreshContextWhenTheJobIsCancelled(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
	cloud := &fakeCloud{}
	ctx, cancel := context.WithCancel(context.Background())
	w := createWorker(svc, cloud, func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error) {
		cancel()
		return engine.DiskResult{}, ctx.Err()
	})
	require.Error(t, w.Work(ctx, volumeJob(1)))
	require.Equal(t, []string{"snap-new-1"}, cloud.deleted)
}

func TestVolume_ARetryAfterACrashFindsTheSnapshotInsteadOfCreatingAnother(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
	svc.intents["run-1|vol-1"] = &diskscan.SnapshotIntent{ID: "intent-vol-1", RunID: "run-1", VolumeRef: "vol-1", ConnectorID: "c1", Provider: "aws"}
	left := engine.Snapshot{ID: "snap-left", Provider: "aws", Region: "eu-west-1", VolumeID: "vol-1", Ephemeral: true, CreatedAt: fakeNow}
	cloud := &fakeCloud{existing: &left}

	require.NoError(t, createWorker(svc, cloud, knownScan(1)).Work(context.Background(), volumeJob(2)))

	require.Zero(t, cloud.created, "no second snapshot")
	require.Equal(t, []string{"snap-left"}, cloud.deleted, "the one the crash left is used and then deleted")
	require.True(t, svc.recorded[0].InventoryKnown)
	require.NotContains(t, svc.events, "intent", "the existing intent row is reused")
}

func TestVolume_ARunThatAlreadyCleanedUpDoesNotSnapshotTwice(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
	svc.intents["run-1|vol-1"] = &diskscan.SnapshotIntent{ID: "i", RunID: "run-1", VolumeRef: "vol-1", DeletedAt: fakeNow}
	cloud := &fakeCloud{}
	require.NoError(t, createWorker(svc, cloud, knownScan(1)).Work(context.Background(), volumeJob(2)))
	require.Zero(t, cloud.created)
	require.Equal(t, diskscan.GapReadError, svc.recorded[0].Gap)
}

func TestVolume_CreatePermissionDeniedIsCachedAndNotRetried(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
	cloud := &fakeCloud{createErr: ErrDiskPermissionDenied}
	require.NoError(t, createWorker(svc, cloud, knownScan(1)).Work(context.Background(), volumeJob(1)))
	require.Equal(t, diskscan.GapPermissionDenied, svc.recorded[0].Gap)
	require.Contains(t, svc.cache, "aws|denied:c1")
	require.Equal(t, []string{"intent-vol-1"}, svc.markedIntent, "a create that failed for certain closes its intent")

	// The next volume of the connector does not even try.
	svc2 := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
	svc2.cache = svc.cache
	cloud2 := &fakeCloud{}
	require.NoError(t, createWorker(svc2, cloud2, knownScan(1)).Work(context.Background(), volumeJob(1)))
	require.Zero(t, cloud2.created)
	require.Equal(t, diskscan.GapPermissionDenied, svc2.recorded[0].Gap)
}

func TestVolume_NoWriteCallWithoutAnOptIn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  diskscan.DiskScanMode
		role  string
		cloud *fakeCloud
		want  string
	}{
		{"mode off", diskscan.DiskScanModeOff, "disk-scan-role", &fakeCloud{}, diskscan.GapNotEnabled},
		{"existing_snapshots mode", diskscan.DiskScanModeExistingSnapshots, "disk-scan-role", &fakeCloud{}, diskscan.GapNoSnapshotAvailable},
		{"no disk-scan role", diskscan.DiskScanModeCreateSnapshots, "", &fakeCloud{}, diskscan.GapNotEnabled},
		{"role equals the collection role", diskscan.DiskScanModeCreateSnapshots, "collection-role", &fakeCloud{}, diskscan.GapNotEnabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newFakeDiskSvc(tc.mode)
			require.NoError(t, newVolumeWorker(svc, tc.cloud, tc.role, knownScan(1)).Work(context.Background(), volumeJob(1)))
			require.Zero(t, tc.cloud.created)
			require.Empty(t, tc.cloud.deleted)
			require.Equal(t, tc.want, svc.recorded[0].Gap)
			require.False(t, svc.recorded[0].InventoryKnown)
		})
	}
}

func TestVolume_CreateLimits(t *testing.T) {
	t.Run("a volume over the size cap is refused before a snapshot", func(t *testing.T) {
		svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
		cloud := &fakeCloud{}
		job := volumeJob(1)
		job.Args.SizeGiB = 2048
		require.NoError(t, createWorker(svc, cloud, knownScan(1)).Work(context.Background(), job))
		require.Zero(t, cloud.created)
		require.Equal(t, diskscan.GapOverCap, svc.recorded[0].Gap)
	})
	t.Run("the daily cap stops creation", func(t *testing.T) {
		svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
		svc.runs = []diskscan.DiskScanRun{{ID: "earlier", StartedAt: fakeNow.Add(-time.Hour)}}
		svc.recorded = []diskscan.VolumeResult{
			{RunID: "earlier", SnapshotSource: diskscan.SourceCreated, ObservedAt: fakeNow.Add(-time.Hour)},
			{RunID: "earlier", SnapshotSource: diskscan.SourceCreated, ObservedAt: fakeNow.Add(-2 * time.Hour)},
			{RunID: "earlier", SnapshotSource: diskscan.SourceCreated, ObservedAt: fakeNow.Add(-30 * time.Hour)},
		}
		cloud := &fakeCloud{}
		w := createWorker(svc, cloud, knownScan(1))
		w.limits.DailySnapshotCap = 2
		require.NoError(t, w.Work(context.Background(), volumeJob(1)))
		require.Zero(t, cloud.created)
		require.Equal(t, diskscan.GapOverCap, svc.recorded[len(svc.recorded)-1].Gap)
	})
}

func TestVolume_PendingSnapshotIsAGapAndStillDeleted(t *testing.T) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
	cloud := &fakeCloud{waitErr: context.DeadlineExceeded}
	w := createWorker(svc, cloud, knownScan(1))
	w.limits.SnapshotWait = time.Nanosecond
	require.NoError(t, w.Work(context.Background(), volumeJob(1)))
	require.Equal(t, diskscan.GapSnapshotPending, svc.recorded[0].Gap)
	require.Equal(t, []string{"snap-new-1"}, cloud.deleted)
}

func TestDiskScanLaneHonoursSnapshotLimit(t *testing.T) {
	require.LessOrEqual(t, queueWorkerCounts[queueDiskScan], DefaultDiskScanLimits().MaxConcurrentSnapshots,
		"the lane runs one job at a time and a job holds one snapshot")
	require.Less(t, DefaultDiskScanLimits().SnapshotWait+diskScanVolumeTimeout, 2*DefaultDiskScanLimits().SnapshotTTL)
	require.Greater(t, DefaultDiskScanLimits().SnapshotTTL, diskScanVolumeTimeout, "a snapshot outlives the job that made it")
}

// ---- sweep ----

func sweepFixture() (*fakeDiskSvc, *fakeCloud, *DiskScanSweepWorker) {
	svc := newFakeDiskSvc(diskscan.DiskScanModeCreateSnapshots)
	svc.enabled = []diskscan.ConnectorSettings{
		{ConnectorID: "c1", Type: "aws", Mode: diskscan.DiskScanModeCreateSnapshots},
		{ConnectorID: "c-existing", Type: "aws", Mode: diskscan.DiskScanModeExistingSnapshots},
	}
	cloud := &fakeCloud{}
	w := &DiskScanSweepWorker{svc: svc, clouds: &fakeClouds{cloud: cloud, role: "disk-scan-role", others: []string{"x"}}, limits: testLimits(), now: clock}
	return svc, cloud, w
}

func TestSweep_DeletesOnlyExpiredTaggedSnapshots(t *testing.T) {
	svc, cloud, w := sweepFixture()
	cloud.tagged = []engine.Snapshot{
		{ID: "snap-old", Provider: "aws", Ephemeral: true, CreatedAt: fakeNow.Add(-7 * time.Hour)},
		{ID: "snap-young", Provider: "aws", Ephemeral: true, CreatedAt: fakeNow.Add(-time.Hour)},
		{ID: "snap-untagged", Provider: "aws", Ephemeral: false, CreatedAt: fakeNow.Add(-30 * time.Hour)},
		{ID: "snap-no-time", Provider: "aws", Ephemeral: true},
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanSweepArgs]{}))
	require.Equal(t, []string{"snap-old"}, cloud.deleted)
	require.Equal(t, []string{"snap-old"}, svc.markedSnap)
}

func TestSweep_OrphansWithAndWithoutASnapshotID(t *testing.T) {
	svc, cloud, w := sweepFixture()
	cloud.tagged = []engine.Snapshot{{ID: "snap-lost", Provider: "aws", VolumeID: "vol-lost", Ephemeral: true, CreatedAt: fakeNow.Add(-8 * time.Hour)}}
	svc.orphans = []diskscan.SnapshotIntent{
		{ID: "i1", ConnectorID: "c1", Provider: "aws", VolumeRef: "vol-a", SnapshotID: "snap-a", CreatedAt: fakeNow.Add(-9 * time.Hour)},
		{ID: "i2", ConnectorID: "c1", Provider: "aws", VolumeRef: "vol-lost", CreatedAt: fakeNow.Add(-9 * time.Hour)},
		{ID: "i3", ConnectorID: "c1", Provider: "aws", VolumeRef: "vol-never", CreatedAt: fakeNow.Add(-9 * time.Hour)},
		{ID: "i4", ConnectorID: "c-existing", Provider: "aws", VolumeRef: "vol-b", SnapshotID: "snap-b", CreatedAt: fakeNow.Add(-9 * time.Hour)},
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[DiskScanSweepArgs]{}))
	require.ElementsMatch(t, []string{"snap-lost", "snap-a", "snap-lost"}, cloud.deleted)
	require.ElementsMatch(t, []string{"i1", "i2", "i3"}, svc.markedIntent, "the unmatched row closes once the listing shows nothing left")
	require.NotContains(t, cloud.deleted, "snap-b", "a connector not in create mode cannot be swept")
}

func TestSweep_AFailedDeleteLeavesTheIntentOpenAndErrors(t *testing.T) {
	svc, cloud, w := sweepFixture()
	cloud.deleteErr = errors.New("throttled")
	svc.orphans = []diskscan.SnapshotIntent{{ID: "i1", ConnectorID: "c1", Provider: "aws", VolumeRef: "vol-a", SnapshotID: "snap-a"}}
	require.Error(t, w.Work(context.Background(), &river.Job[DiskScanSweepArgs]{}))
	require.Empty(t, svc.markedIntent)
}

func TestSweep_ASharedRoleIsNeverSwept(t *testing.T) {
	_, cloud, w := sweepFixture()
	w.clouds = &fakeClouds{cloud: cloud, role: "collection-role", others: []string{"collection-role"}}
	cloud.tagged = []engine.Snapshot{{ID: "snap-old", Ephemeral: true, CreatedAt: fakeNow.Add(-24 * time.Hour)}}
	require.Error(t, w.Work(context.Background(), &river.Job[DiskScanSweepArgs]{}))
	require.Empty(t, cloud.deleted)
}

// ---- guards ----

// internal/jobs may call the disk scan service and the providers through
// interfaces, but never import a package that can mutate cloud state: the
// snapshotter chokepoint is built in cmd/graph only.
func TestJobsNeverImportCloudMutators(t *testing.T) {
	banned := []string{
		"github.com/aws/aws-sdk-go-v2/service/ec2",
		"github.com/aws/aws-sdk-go-v2/service/ebs",
		"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute",
		"google.golang.org/api/compute/v1",
		"/internal/scanner/diskscan/snapshotter",
		"/internal/scanner/diskscan/awsdisk",
		"/internal/scanner/diskscan/azuredisk",
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		require.NoError(t, perr)
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, b := range banned {
				require.Falsef(t, strings.Contains(p, b), "%s imports %s: jobs must not hold a cloud client; build it in cmd/graph", path, p)
			}
		}
		return nil
	})
	require.NoError(t, err)
	_, statErr := os.Stat("diskscan.go")
	require.NoError(t, statErr, "the walk ran in the jobs package")
}
