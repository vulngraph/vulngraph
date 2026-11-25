package diskscan

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

type fakeConns struct {
	byID map[string]ConnectorSettings
}

func (f *fakeConns) DiskScanSettings(_ context.Context, id string) (ConnectorSettings, error) {
	c, ok := f.byID[id]
	if !ok {
		return ConnectorSettings{}, ErrNotFound
	}
	return c, nil
}

func (f *fakeConns) DiskScanEnabled(_ context.Context) ([]ConnectorSettings, error) {
	var out []ConnectorSettings
	for _, c := range f.byID {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ConnectorID < out[j].ConnectorID })
	return out, nil
}

type fakeRepo struct {
	runs    map[string]DiskScanRun
	vols    map[string]volRow
	intents map[string]SnapshotIntent
	cache   map[string]CacheEntry
	seq     int
	upserts int
}

type volRow struct {
	boot bool
	res  VolumeResult
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{runs: map[string]DiskScanRun{}, vols: map[string]volRow{}, intents: map[string]SnapshotIntent{}, cache: map[string]CacheEntry{}}
}

func (f *fakeRepo) nextID() string { f.seq++; return "id-" + strconv.Itoa(f.seq) }

func (f *fakeRepo) InsertRun(_ context.Context, run DiskScanRun) (DiskScanRun, error) {
	run.ID = f.nextID()
	f.runs[run.ID] = run
	return run, nil
}

func (f *fakeRepo) GetRun(_ context.Context, id string) (DiskScanRun, error) {
	r, ok := f.runs[id]
	if !ok {
		return DiskScanRun{}, ErrNotFound
	}
	return r, nil
}

func (f *fakeRepo) ListRuns(_ context.Context, _ string, _ int) ([]DiskScanRun, error) {
	return nil, nil
}

func (f *fakeRepo) FinishRun(_ context.Context, run DiskScanRun) error {
	f.runs[run.ID] = run
	return nil
}

func (f *fakeRepo) CountVolumes(_ context.Context, runID string) (RunCounts, error) {
	var c RunCounts
	for _, v := range f.vols {
		if v.res.RunID != runID {
			continue
		}
		switch {
		case v.res.InventoryKnown:
			c.Scanned++
		case v.res.Gap == GapNotEnabled:
			c.NotEnabled++
		default:
			c.Gaps++
		}
	}
	return c, nil
}

func (f *fakeRepo) UpsertVolume(_ context.Context, boot bool, res VolumeResult) error {
	f.upserts++
	f.vols[res.RunID+"|"+res.AssetID+"|"+res.VolumeRef] = volRow{boot, res}
	return nil
}

func (f *fakeRepo) LatestVolumes(_ context.Context, ids []string) ([]VolumeResult, error) {
	best := map[string]volRow{}
	for _, v := range f.vols {
		for _, id := range ids {
			if v.res.AssetID != id {
				continue
			}
			cur, ok := best[id]
			if !ok || (v.boot && !cur.boot) || (v.boot == cur.boot && v.res.ObservedAt.After(cur.res.ObservedAt)) {
				best[id] = v
			}
		}
	}
	var out []VolumeResult
	for _, v := range best {
		out = append(out, v.res)
	}
	return out, nil
}

func (f *fakeRepo) ListVolumes(_ context.Context, runID string) ([]VolumeResult, error) {
	var out []VolumeResult
	for _, v := range f.vols {
		if v.res.RunID == runID {
			out = append(out, v.res)
		}
	}
	return out, nil
}

func (f *fakeRepo) InsertIntent(_ context.Context, in SnapshotIntent) error {
	for _, e := range f.intents {
		if e.RunID == in.RunID && e.VolumeRef == in.VolumeRef {
			return nil
		}
	}
	in.ID = f.nextID()
	f.intents[in.ID] = in
	return nil
}

func (f *fakeRepo) GetIntent(_ context.Context, runID, vol string) (SnapshotIntent, error) {
	for _, e := range f.intents {
		if e.RunID == runID && e.VolumeRef == vol {
			return e, nil
		}
	}
	return SnapshotIntent{}, ErrNotFound
}

func (f *fakeRepo) AttachSnapshot(_ context.Context, id, snap string) error {
	e, ok := f.intents[id]
	if !ok {
		return ErrNotFound
	}
	e.SnapshotID = snap
	f.intents[id] = e
	return nil
}

func (f *fakeRepo) MarkDeleted(_ context.Context, id string, at time.Time) error {
	if e, ok := f.intents[id]; ok && e.DeletedAt.IsZero() {
		e.DeletedAt = at
		f.intents[id] = e
	}
	return nil
}

func (f *fakeRepo) MarkDeletedBySnapshot(_ context.Context, provider, snap string, at time.Time) error {
	for id, e := range f.intents {
		if e.Provider == provider && e.SnapshotID == snap && e.DeletedAt.IsZero() {
			e.DeletedAt = at
			f.intents[id] = e
		}
	}
	return nil
}

func (f *fakeRepo) ListOrphans(_ context.Context, now time.Time, _ int) ([]SnapshotIntent, error) {
	var out []SnapshotIntent
	for _, e := range f.intents {
		if e.DeletedAt.IsZero() && e.DeleteAfter.Before(now) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeRepo) GetCache(_ context.Context, provider, snap string, now time.Time) (CacheEntry, bool, error) {
	e, ok := f.cache[provider+"|"+snap]
	if !ok || (!e.ExpiresAt.IsZero() && !e.ExpiresAt.After(now)) {
		return CacheEntry{}, false, nil
	}
	return e, true, nil
}

func (f *fakeRepo) PutCache(_ context.Context, e CacheEntry) error {
	f.cache[e.Provider+"|"+e.SnapshotID] = e
	return nil
}

var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func newSvc(modes ...DiskScanMode) (*Service, *fakeRepo, *fakeConns, *time.Time) {
	conns := &fakeConns{byID: map[string]ConnectorSettings{}}
	for i, m := range modes {
		id := "c" + strconv.Itoa(i)
		conns.byID[id] = ConnectorSettings{ConnectorID: id, Type: "aws", Mode: m, Role: "arn:disk", OtherRoles: []string{"arn:collect"}}
	}
	repo := newFakeRepo()
	now := t0
	return NewService(repo, conns).WithClock(func() time.Time { return now }), repo, conns, &now
}

func good() VolumeResult {
	return VolumeResult{InventoryKnown: true, CVEMatchableKnown: true, PackageCount: 120, SnapshotSource: SourceReused, SnapshotID: "snap-1"}
}

func TestValidateResult_NeverCleanForUnreadableDisk(t *testing.T) {
	tests := []struct {
		name string
		res  VolumeResult
		ok   bool
	}{
		{"known inventory", good(), true},
		{"known, zero packages is a real observation", VolumeResult{InventoryKnown: true}, true},
		{"zero value result", VolumeResult{}, false},
		{"unknown with no gap", VolumeResult{InventoryKnown: false}, false},
		{"unknown with unrecognised gap", VolumeResult{Gap: "weird"}, false},
		{"known with a gap", VolumeResult{InventoryKnown: true, Gap: GapReadError}, false},
		{"unknown but claims packages", VolumeResult{Gap: GapReadError, PackageCount: 3}, false},
		{"unknown but claims cve matchable", VolumeResult{Gap: GapUnsupportedFS, CVEMatchableKnown: true}, false},
		{"negative count", VolumeResult{InventoryKnown: true, PackageCount: -1}, false},
		{"bad source", VolumeResult{InventoryKnown: true, SnapshotSource: "teleport"}, false},
		{"encrypted without key", VolumeResult{Encrypted: true, Gap: GapEncryptedNoKey}, true},
		{"encrypted with no gap and unknown", VolumeResult{Encrypted: true}, false},
		{"unsupported fs", VolumeResult{Gap: GapUnsupportedFS}, true},
		{"unsupported partition", VolumeResult{Gap: GapUnsupportedPartition}, true},
		{"read error", VolumeResult{Gap: GapReadError}, true},
		{"not enabled", VolumeResult{Gap: GapNotEnabled}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResult(tc.res)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrInvalid)
		})
	}
}

func TestEveryGapConstantIsValidAndMatchesEngine(t *testing.T) {
	engineGaps := []string{
		engine.GapNotEnabled, engine.GapNoSnapshotAvailable, engine.GapSnapshotPending, engine.GapEncryptedNoKey,
		engine.GapUnsupportedFS, engine.GapUnsupportedPartition, engine.GapReadError, engine.GapOverCap,
		engine.GapPermissionDenied, engine.GapStale,
	}
	assert.ElementsMatch(t, engineGaps, validGaps)
}

func TestRecordResult_RefusesAmbiguousAndWritesNothing(t *testing.T) {
	svc, repo, _, _ := newSvc(DiskScanModeExistingSnapshots)
	run, err := svc.StartRun(context.Background(), "c0")
	require.NoError(t, err)

	tgt := DiskScanTarget{ConnectorID: "c0", AssetID: "i-1", VolumeRef: "vol-1", Boot: true}
	err = svc.RecordResult(context.Background(), run.ID, tgt, VolumeResult{})
	require.ErrorIs(t, err, ErrInvalid)
	require.Zero(t, repo.upserts)

	require.ErrorIs(t, svc.RecordResult(context.Background(), "", tgt, good()), ErrInvalid)
	require.ErrorIs(t, svc.RecordResult(context.Background(), run.ID, DiskScanTarget{}, good()), ErrInvalid)
	require.Zero(t, repo.upserts)
}

func TestRecordResult_StampsIdentityAndTime(t *testing.T) {
	svc, repo, _, _ := newSvc(DiskScanModeExistingSnapshots)
	run, err := svc.StartRun(context.Background(), "c0")
	require.NoError(t, err)

	res := good()
	res.AssetID, res.RunID = "other", "other" // overridden by the target and run
	require.NoError(t, svc.RecordResult(context.Background(), run.ID, DiskScanTarget{AssetID: "i-1", VolumeRef: "vol-1", Boot: true}, res))
	got := repo.vols[run.ID+"|i-1|vol-1"]
	assert.True(t, got.boot)
	assert.Equal(t, "i-1", got.res.AssetID)
	assert.Equal(t, run.ID, got.res.RunID)
	assert.Equal(t, t0, got.res.ObservedAt)
}

func TestStartRun(t *testing.T) {
	tests := []struct {
		name string
		mode DiskScanMode
		want RunStatus
	}{
		{"off is a not_enabled state, not an error", DiskScanModeOff, StatusNotEnabled},
		{"existing snapshots", DiskScanModeExistingSnapshots, StatusRunning},
		{"create snapshots", DiskScanModeCreateSnapshots, StatusRunning},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, _, _ := newSvc(tc.mode)
			run, err := svc.StartRun(context.Background(), "c0")
			require.NoError(t, err)
			assert.Equal(t, tc.want, run.Status)
			assert.Equal(t, tc.want, repo.runs[run.ID].Status)
			assert.Equal(t, tc.want == StatusNotEnabled, !run.FinishedAt.IsZero())
		})
	}
	svc, _, _, _ := newSvc()
	_, err := svc.StartRun(context.Background(), "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestFinishRun_StatusFromRecordedVolumes(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name    string
		planned int
		results []VolumeResult
		runErr  error
		want    RunStatus
		counts  RunCounts
	}{
		{"all scanned", 2, []VolumeResult{good(), good()}, nil, StatusSucceeded, RunCounts{Volumes: 2, Scanned: 2}},
		{"nothing planned", 0, nil, nil, StatusSucceeded, RunCounts{}},
		{"a gap makes it partial", 2, []VolumeResult{good(), {Gap: GapEncryptedNoKey, Encrypted: true}}, nil, StatusPartial, RunCounts{Volumes: 2, Scanned: 1, Gaps: 1}},
		{"missing results make it partial, never succeeded", 3, []VolumeResult{good()}, nil, StatusPartial, RunCounts{Volumes: 3, Scanned: 1}},
		{"all not enabled", 2, []VolumeResult{{Gap: GapNotEnabled}, {Gap: GapNotEnabled}}, nil, StatusNotEnabled, RunCounts{Volumes: 2, NotEnabled: 2}},
		{"error and nothing recorded", 2, nil, boom, StatusFailed, RunCounts{Volumes: 2}},
		{"error after some results", 2, []VolumeResult{good()}, boom, StatusPartial, RunCounts{Volumes: 2, Scanned: 1}},
		{"error after all scanned still partial", 1, []VolumeResult{good()}, boom, StatusPartial, RunCounts{Volumes: 1, Scanned: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, _ := newSvc(DiskScanModeExistingSnapshots)
			ctx := context.Background()
			run, err := svc.StartRun(ctx, "c0")
			require.NoError(t, err)
			for i, r := range tc.results {
				require.NoError(t, svc.RecordResult(ctx, run.ID, DiskScanTarget{AssetID: "i-" + strconv.Itoa(i), VolumeRef: "v"}, r))
			}
			got, err := svc.FinishRun(ctx, run.ID, tc.planned, tc.runErr)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got.Status)
			assert.Equal(t, tc.counts, got.Counts)
			assert.Equal(t, t0, got.FinishedAt)
			if tc.runErr != nil {
				assert.Equal(t, "boom", got.Err)
			}
		})
	}
}

func TestLatest(t *testing.T) {
	svc, repo, _, clock := newSvc(DiskScanModeExistingSnapshots)
	ctx := context.Background()
	run, err := svc.StartRun(ctx, "c0")
	require.NoError(t, err)

	old := good()
	old.ObservedAt = t0.Add(-48 * time.Hour)
	require.NoError(t, svc.RecordResult(ctx, run.ID, DiskScanTarget{AssetID: "i-1", VolumeRef: "boot", Boot: true}, old))
	*clock = t0
	require.NoError(t, svc.RecordResult(ctx, run.ID, DiskScanTarget{AssetID: "i-1", VolumeRef: "data"}, VolumeResult{Gap: GapReadError}))
	require.NoError(t, svc.RecordResult(ctx, run.ID, DiskScanTarget{AssetID: "i-2", VolumeRef: "boot", Boot: true}, VolumeResult{Gap: GapEncryptedNoKey, Encrypted: true}))

	got, err := svc.Latest(ctx, []string{"i-1", "i-2", "i-3"})
	require.NoError(t, err)
	require.Len(t, got, 2, "an asset never scanned is absent, not clean")
	assert.True(t, got["i-1"].InventoryKnown, "the boot volume decides over a newer data volume")
	assert.Equal(t, "boot", got["i-1"].VolumeRef)
	assert.False(t, got["i-2"].InventoryKnown)
	assert.Equal(t, GapEncryptedNoKey, got["i-2"].Gap)

	empty, err := svc.Latest(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, empty)

	// A row that somehow lacks both inventory and gap reads as a read error.
	repo.vols["x"] = volRow{true, VolumeResult{RunID: run.ID, AssetID: "i-9", VolumeRef: "v", PackageCount: 40, CVEMatchableKnown: true}}
	got, err = svc.Latest(ctx, []string{"i-9"})
	require.NoError(t, err)
	assert.False(t, got["i-9"].InventoryKnown)
	assert.Equal(t, GapReadError, got["i-9"].Gap)
	assert.Zero(t, got["i-9"].PackageCount)
	assert.False(t, got["i-9"].CVEMatchableKnown)
}

func TestEnabledConnectorsAndGrant(t *testing.T) {
	svc, _, _, _ := newSvc(DiskScanModeOff, DiskScanModeExistingSnapshots, DiskScanModeCreateSnapshots)
	ctx := context.Background()
	got, err := svc.EnabledConnectors(ctx)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "c1", got[0].ConnectorID)

	tests := []struct {
		id      string
		mode    DiskScanMode
		wantErr bool
	}{
		{"c0", DiskScanModeOff, true},
		{"c1", DiskScanModeExistingSnapshots, true},
		{"c2", DiskScanModeCreateSnapshots, false},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			grant, err := svc.Grant(ctx, tc.id)
			require.NoError(t, err)
			assert.Equal(t, "arn:disk", grant.DiskScanRole)
			assert.Equal(t, []string{"arn:collect"}, grant.OtherRoles)
			_, authErr := engine.Authorize(grant)
			if tc.wantErr {
				require.ErrorIs(t, authErr, engine.ErrNotAuthorized)
				return
			}
			require.NoError(t, authErr)
		})
	}
	_, err = svc.Grant(ctx, "missing")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestSnapshotRegistry(t *testing.T) {
	svc, _, _, clock := newSvc(DiskScanModeCreateSnapshots)
	svc.WithSnapshotTTL(time.Hour)
	ctx := context.Background()

	_, err := svc.RegisterSnapshotIntent(ctx, SnapshotIntent{RunID: "r1"})
	require.ErrorIs(t, err, ErrInvalid)

	in := SnapshotIntent{RunID: "r1", ConnectorID: "c0", Provider: "aws", Region: "eu-west-1", VolumeRef: "vol-1", SnapshotID: "ignored"}
	first, err := svc.RegisterSnapshotIntent(ctx, in)
	require.NoError(t, err)
	assert.Empty(t, first.SnapshotID, "the intent exists before any snapshot does")
	assert.Equal(t, t0.Add(time.Hour), first.DeleteAfter)

	require.NoError(t, svc.AttachSnapshot(ctx, first.ID, "snap-9"))
	retry, err := svc.RegisterSnapshotIntent(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, first.ID, retry.ID, "a retry gets its intent back, so it can never double-create")
	assert.Equal(t, "snap-9", retry.SnapshotID)

	require.ErrorIs(t, svc.AttachSnapshot(ctx, first.ID, ""), ErrInvalid)
	require.ErrorIs(t, svc.AttachSnapshot(ctx, "nope", "snap-1"), ErrNotFound)

	orphans, err := svc.ListOrphans(ctx)
	require.NoError(t, err)
	assert.Empty(t, orphans, "inside its TTL")

	*clock = t0.Add(2 * time.Hour)
	orphans, err = svc.ListOrphans(ctx)
	require.NoError(t, err)
	require.Len(t, orphans, 1)

	require.NoError(t, svc.MarkDeletedBySnapshot(ctx, "aws", "snap-9"))
	orphans, err = svc.ListOrphans(ctx)
	require.NoError(t, err)
	assert.Empty(t, orphans)
	require.NoError(t, svc.MarkDeletedBySnapshot(ctx, "aws", "unregistered"))

	other, err := svc.RegisterSnapshotIntent(ctx, SnapshotIntent{RunID: "r2", ConnectorID: "c0", Provider: "aws", VolumeRef: "vol-2"})
	require.NoError(t, err)
	*clock = t0.Add(4 * time.Hour)
	orphans, err = svc.ListOrphans(ctx)
	require.NoError(t, err)
	require.Len(t, orphans, 1, "an intent with no snapshot id still surfaces for the sweeper")
	require.NoError(t, svc.MarkDeleted(ctx, other.ID))
	orphans, err = svc.ListOrphans(ctx)
	require.NoError(t, err)
	assert.Empty(t, orphans)
}

func TestCache(t *testing.T) {
	svc, _, _, clock := newSvc()
	ctx := context.Background()

	_, ok, err := svc.CacheGet(ctx, "aws", "snap-1")
	require.NoError(t, err)
	assert.False(t, ok)

	require.ErrorIs(t, svc.CachePut(ctx, CacheEntry{Provider: "aws"}), ErrInvalid)
	require.ErrorIs(t, svc.CachePut(ctx, CacheEntry{Provider: "aws", SnapshotID: "snap-1"}), ErrInvalid,
		"a result with no inventory and no gap cannot be cached")

	e := CacheEntry{Provider: "aws", SnapshotID: "snap-1", Digest: "d", Extents: []engine.Extent{{Offset: 0, Length: 4096}}, Result: good()}
	require.NoError(t, svc.CachePut(ctx, e))
	got, ok, err := svc.CacheGet(ctx, "aws", "snap-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "d", got.Digest)
	assert.Equal(t, t0, got.CachedAt)

	denied := CacheEntry{Provider: "aws", SnapshotID: "denied:vol-1", Result: VolumeResult{Gap: GapPermissionDenied}, ExpiresAt: t0.Add(24 * time.Hour)}
	require.NoError(t, svc.CachePut(ctx, denied))
	_, ok, _ = svc.CacheGet(ctx, "aws", "denied:vol-1")
	assert.True(t, ok)
	*clock = t0.Add(25 * time.Hour)
	_, ok, _ = svc.CacheGet(ctx, "aws", "denied:vol-1")
	assert.False(t, ok, "the 24h negative entry expires")
}
