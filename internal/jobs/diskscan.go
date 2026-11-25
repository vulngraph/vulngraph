package jobs

// Agentless VM disk scanning: three kinds, one flow.
//
//	disk_scan_plan    (worker, maintain lane) picks the VMs whose package inventory is
//	                  unknown, opens a run and enqueues one volume job per VM, in the
//	                  run's own transaction.
//	disk_scan_volume  (scanner pod, own heavy lane) reads one boot volume from an
//	                  existing snapshot or, only when the connector opted in, from a
//	                  short-lived tagged one, then records the result and the packages.
//	disk_scan_sweep   (worker, maintain lane) deletes tagged snapshots past their TTL.
//
// This package never holds a cloud client that can mutate: the snapshotter is
// built in cmd/graph and reaches the workers only through DiskCloud, and
// TestJobsNeverImportCloudMutators pins that. Vulnerability matching stays in
// refresh_vm_vuln; these jobs write packages, results and their own tables.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/distro"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	// queueDiskScan is the third heavy lane: one volume read at a time on the
	// scanner pod. It is separate from queueScan so a nuclei run and a disk read
	// do not queue behind each other, and it is its own lane rather than a share
	// of queueScan because disk jobs carry a different memory and I/O profile.
	queueDiskScan = "disk_scan"

	diskScanWorkers = 1 // one volume at a time; see DiskScanLimits.MaxConcurrentSnapshots

	diskScanPlanInterval  = time.Hour
	diskScanSweepInterval = 30 * time.Minute
	diskScanVolumeTimeout = 90 * time.Minute
	diskScanPlanTimeout   = 10 * time.Minute
	diskScanSweepTimeout  = 15 * time.Minute
)

// DiskScanLimits bounds what disk scanning may spend and hold, per connector
// unless noted. DefaultDiskScanLimits is the maintainer-approved set.
type DiskScanLimits struct {
	// MaxConcurrentSnapshots bounds snapshots alive at once. The volume lane runs
	// one job at a time and a job holds at most one snapshot, so the lane is what
	// enforces it; TestDiskScanLaneHonoursSnapshotLimit pins the two together.
	MaxConcurrentSnapshots int
	// DailySnapshotCap bounds snapshots created in any 24 hours.
	DailySnapshotCap int
	// MaxVolumeBytes refuses a larger volume (gap over_cap) before it is read,
	// and before a snapshot of it is created.
	MaxVolumeBytes int64
	// MaxBytesRead is the byte budget for reading one volume.
	MaxBytesRead int64
	// SnapshotTTL is how long a snapshot we created may live before the sweep
	// deletes it. It must exceed the volume job's timeout.
	SnapshotTTL time.Duration
	// SnapshotWait is how long a created snapshot may take to complete.
	SnapshotWait time.Duration
	// RescanKnownAfter and RescanGapAfter decide when the plan reads a volume
	// again after a known result or a gap.
	RescanKnownAfter time.Duration
	RescanGapAfter   time.Duration
	// DenialCacheFor is how long a permission denial suppresses retries.
	DenialCacheFor time.Duration
	// CredentialLifetime is how long the cloud credentials sealed into a run's
	// jobs last (AWS sessions are minted for it; at least 15 minutes, which is
	// STS's floor, and at most an hour, which is its role-chaining ceiling). A
	// job that starts after they expire records the stale gap and the next plan
	// reads the volume again.
	CredentialLifetime time.Duration
	// MaxVolumesPerRun bounds one plan pass for one connector so a run finishes
	// inside CredentialLifetime on the one-at-a-time lane; the rest follow on
	// later passes. A connector with a run still in flight is not planned again.
	MaxVolumesPerRun int
	// RunStaleAfter closes a run whose volumes never all reported.
	RunStaleAfter time.Duration
	// ResultStaleAfter turns a capture older than this into the stale gap.
	ResultStaleAfter time.Duration
}

// DefaultDiskScanLimits returns the defaults.
func DefaultDiskScanLimits() DiskScanLimits {
	return DiskScanLimits{
		MaxConcurrentSnapshots: 2,
		DailySnapshotCap:       50,
		MaxVolumeBytes:         1 << 40,
		MaxBytesRead:           1 << 30,
		SnapshotTTL:            diskscan.DefaultSnapshotTTL,
		SnapshotWait:           30 * time.Minute,
		RescanKnownAfter:       24 * time.Hour,
		RescanGapAfter:         6 * time.Hour,
		DenialCacheFor:         24 * time.Hour,
		CredentialLifetime:     time.Hour,
		MaxVolumesPerRun:       30,
		RunStaleAfter:          3 * time.Hour,
		ResultStaleAfter:       7 * 24 * time.Hour,
	}
}

// ErrDiskPermissionDenied, ErrDiskEncryptedNoKey and ErrDiskEnvelope are the
// errors a DiskCloud and DiskScanClouds map their provider's errors to, so the
// jobs never import a provider package to classify one.
var (
	ErrDiskPermissionDenied = errors.New("disk scan: permission denied")
	ErrDiskEncryptedNoKey   = errors.New("disk scan: encrypted snapshot, no key access")
	// ErrDiskCredentialsExpired means the cloud credentials sealed into the job
	// ran out, before the job started or while it ran. Retrying cannot help.
	ErrDiskCredentialsExpired = errors.New("disk scan: credentials expired")
	// ErrDiskEnvelope means a volume job's sealed credentials cannot be used: they
	// are expired, malformed or bound to another run. Retrying cannot help.
	ErrDiskEnvelope = errors.New("disk scan: credential envelope unusable")
)

// DiskOptIns are the authorizations a connector's mode and principal yield. Read
// permits the read-access grant (Azure's SAS) and is valid in existing_snapshots
// and create_snapshots mode; Create permits creating and deleting tagged
// snapshots and is valid in create_snapshots mode only. Either may be the zero
// value, which authorizes nothing.
type DiskOptIns struct {
	Create engine.OptIn
	Read   engine.ReadOptIn
}

// DiskCloud is one connector's cloud access for disk scanning, built in
// cmd/graph. Snapshotter is the only way to a mutating client.
type DiskCloud interface {
	// Provider reads existing snapshots.
	Provider(ins DiskOptIns) engine.Provider
	Snapshotter(optIn engine.OptIn) (engine.Snapshotter, error)
	// WaitCompleted returns when a created snapshot can be read.
	WaitCompleted(ctx context.Context, snap engine.Snapshot) error
	// Release ends any read access taken on snap (an Azure SAS grant).
	Release(ctx context.Context, ins DiskOptIns, snap engine.Snapshot) error
}

// DiskScanAccess is what opening a connector's credentials yields. Role and
// OtherRoles are identifiers for engine.Authorize, never secrets.
type DiskScanAccess struct {
	Role       string
	OtherRoles []string
	Cloud      DiskCloud
}

// DiskScanClouds resolves connector credentials. Seal and Resolve run on the
// worker pod, which can decrypt connectors; Open runs on the scanner pod, which
// cannot, and sees only what Seal chose to hand over.
type DiskScanClouds interface {
	// Seal packs the disk-scan principals of a connector for one run.
	Seal(ctx context.Context, connectorID, runID string, expiresAt time.Time) ([]byte, error)
	Open(ctx context.Context, connectorID, runID string, sealed []byte) (DiskScanAccess, error)
	Resolve(ctx context.Context, connectorID string) (DiskScanAccess, error)
}

// DiskScanDeps wires disk scanning. Nil leaves it off.
type DiskScanDeps struct {
	Service  *diskscan.Service
	Clouds   DiskScanClouds
	Advisory distro.Sources
	// Limits: the zero value means DefaultDiskScanLimits.
	Limits DiskScanLimits
}

func (d *DiskScanDeps) limits() DiskScanLimits {
	if d.Limits == (DiskScanLimits{}) {
		return DefaultDiskScanLimits()
	}
	return d.Limits
}

// diskScanService is the slice of *diskscan.Service the workers use.
type diskScanService interface {
	EnabledConnectors(ctx context.Context) ([]diskscan.ConnectorSettings, error)
	PlanRun(ctx context.Context, connectorID string, enqueue diskscan.EnqueueFunc) (diskscan.DiskScanRun, error)
	FinishRun(ctx context.Context, runID string, planned int, runErr error) (diskscan.DiskScanRun, error)
	ListRuns(ctx context.Context, connectorID string, limit int) ([]diskscan.DiskScanRun, error)
	ListVolumes(ctx context.Context, runID string) ([]diskscan.VolumeResult, error)
	Latest(ctx context.Context, assetIDs []string) (map[string]diskscan.VolumeResult, error)
	RecordResult(ctx context.Context, runID string, t diskscan.DiskScanTarget, res diskscan.VolumeResult) error
	RecordPackages(ctx context.Context, set diskscan.PackageSet) error
	Packages(ctx context.Context, assetIDs []string) ([]diskscan.PackageSet, error)
	Grant(ctx context.Context, connectorID string) (engine.ConnectorGrant, error)
	RegisterSnapshotIntent(ctx context.Context, in diskscan.SnapshotIntent) (diskscan.SnapshotIntent, error)
	AttachSnapshot(ctx context.Context, intentID, snapshotID string) error
	MarkDeleted(ctx context.Context, intentID string) error
	MarkDeletedBySnapshot(ctx context.Context, provider, snapshotID string) error
	ListOrphans(ctx context.Context) ([]diskscan.SnapshotIntent, error)
	CacheGet(ctx context.Context, provider, snapshotID string) (diskscan.CacheEntry, bool, error)
	CachePut(ctx context.Context, e diskscan.CacheEntry) error
}

var _ diskScanService = (*diskscan.Service)(nil)

// DiskScanPlanArgs is the periodic tick that plans volume reads.
type DiskScanPlanArgs struct{}

func (DiskScanPlanArgs) Kind() string { return "disk_scan_plan" }

func (DiskScanPlanArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueMaintain, 2)
}

// DiskScanVolumeArgs reads one boot volume. (RunID, AssetID, VolumeRef) is the
// unique key; Sealed is the connector's disk-scan credentials for this run and
// is never logged.
type DiskScanVolumeArgs struct {
	RunID       string `json:"run_id" river:"unique"`
	AssetID     string `json:"asset_id" river:"unique"`
	VolumeRef   string `json:"volume_ref" river:"unique"`
	ConnectorID string `json:"connector_id"`
	Provider    string `json:"provider"`
	Region      string `json:"region"`
	ImageID     string `json:"image_id,omitempty"`
	SizeGiB     int    `json:"size_gib,omitempty"`
	// Planned is how many volumes the run enqueued; the job that records the
	// last result closes the run.
	Planned int    `json:"planned"`
	Sealed  []byte `json:"sealed"`
}

func (DiskScanVolumeArgs) Kind() string { return "disk_scan_volume" }

func (DiskScanVolumeArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       queueDiskScan,
		MaxAttempts: 3,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// DiskScanSweepArgs is the periodic tick that deletes expired tagged snapshots.
type DiskScanSweepArgs struct{}

func (DiskScanSweepArgs) Kind() string { return "disk_scan_sweep" }

func (DiskScanSweepArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueMaintain, 2)
}

// diskScanAssets is the slice of *asset.Service the plan uses.
type diskScanAssets interface {
	ListByType(ctx context.Context, assetType string, limit int) ([]asset.Asset, error)
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
}

// diskVolumeInserter inserts a run's volume jobs in the run's transaction.
type diskVolumeInserter interface {
	insertTx(ctx context.Context, tx pgx.Tx, params []river.InsertManyParams) error
}

type riverDiskInserter struct{}

func (riverDiskInserter) insertTx(ctx context.Context, tx pgx.Tx, params []river.InsertManyParams) error {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return fmt.Errorf("insertTx: %w", err)
	}
	if _, err := client.InsertManyTx(ctx, tx, params); err != nil {
		return fmt.Errorf("insertTx: %w", err)
	}
	return nil
}

// diskVMTypes maps a connector type to the asset type of its VMs and the
// metadata key holding the VM's boot volume.
var diskVMTypes = map[string]struct{ assetType, volumeKey string }{
	string(connector.TypeAWS):   {"ec2_instance", "root_volume_id"},
	string(connector.TypeAzure): {"azure_vm", "os_disk_id"},
}

const maxPlanAssets = 200000

// DiskScanPlanWorker opens a run per enabled connector and enqueues its volumes.
type DiskScanPlanWorker struct {
	river.WorkerDefaults[DiskScanPlanArgs]
	svc     diskScanService
	assets  diskScanAssets
	clouds  DiskScanClouds
	inserts diskVolumeInserter
	limits  DiskScanLimits
	now     func() time.Time
}

func (w *DiskScanPlanWorker) Timeout(*river.Job[DiskScanPlanArgs]) time.Duration {
	return diskScanPlanTimeout
}

func (w *DiskScanPlanWorker) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

func (w *DiskScanPlanWorker) Work(ctx context.Context, _ *river.Job[DiskScanPlanArgs]) error {
	conns, err := w.svc.EnabledConnectors(ctx)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	var errs []error
	for _, c := range conns {
		busy, err := w.closeStaleRuns(ctx, c.ConnectorID)
		if err != nil {
			errs = append(errs, fmt.Errorf("Work: close stale runs of %s: %w", c.ConnectorID, err))
		}
		if busy {
			continue
		}
		if err := w.planConnector(ctx, c); err != nil {
			errs = append(errs, fmt.Errorf("Work: plan %s: %w", c.ConnectorID, err))
		}
	}
	return errors.Join(errs...)
}

// closeStaleRuns closes runs whose volumes never all reported, so the run reads
// partial instead of running forever. It reports whether a run is still in
// flight: its jobs hold credentials that are about to run out, so the connector
// is not planned again until it finishes or goes stale.
func (w *DiskScanPlanWorker) closeStaleRuns(ctx context.Context, connectorID string) (busy bool, err error) {
	runs, err := w.svc.ListRuns(ctx, connectorID, 20)
	if err != nil {
		return false, fmt.Errorf("closeStaleRuns: %w", err)
	}
	cutoff := w.clock().Add(-w.limits.RunStaleAfter)
	for _, run := range runs {
		if run.Status != diskscan.StatusRunning {
			continue
		}
		if !run.Stale(cutoff) {
			busy = true
			continue
		}
		vols, err := w.svc.ListVolumes(ctx, run.ID)
		if err != nil {
			return busy, fmt.Errorf("closeStaleRuns: %w", err)
		}
		if _, err := w.svc.FinishRun(ctx, run.ID, len(vols), errors.New("run closed: some volumes never reported")); err != nil {
			return busy, fmt.Errorf("closeStaleRuns: %w", err)
		}
	}
	return busy, nil
}

// diskTarget is one VM's boot volume to read.
type diskTarget struct {
	assetID, volume, region, imageID string
	sizeGiB                          int
}

func (w *DiskScanPlanWorker) planConnector(ctx context.Context, c diskscan.ConnectorSettings) error {
	targets, err := w.targets(ctx, c)
	if err != nil {
		return fmt.Errorf("planConnector: %w", err)
	}
	if len(targets) == 0 {
		return nil
	}
	provider := string(c.Type)
	enqueue := func(ctx context.Context, tx diskscan.Tx, run diskscan.DiskScanRun) error {
		pgxTx, ok := tx.(pgx.Tx)
		if !ok {
			return fmt.Errorf("enqueue: transaction is %T, want pgx.Tx", tx)
		}
		sealed, err := w.clouds.Seal(ctx, c.ConnectorID, run.ID, w.clock().Add(w.limits.CredentialLifetime))
		if err != nil {
			return fmt.Errorf("enqueue: seal credentials: %w", err)
		}
		params := make([]river.InsertManyParams, len(targets))
		for i, t := range targets {
			params[i] = river.InsertManyParams{Args: DiskScanVolumeArgs{
				RunID: run.ID, AssetID: t.assetID, VolumeRef: t.volume, ConnectorID: c.ConnectorID,
				Provider: provider, Region: t.region, ImageID: t.imageID, SizeGiB: t.sizeGiB,
				Planned: len(targets), Sealed: sealed,
			}}
		}
		return w.inserts.insertTx(ctx, pgxTx, params)
	}
	run, err := w.svc.PlanRun(ctx, c.ConnectorID, enqueue)
	if err != nil {
		return fmt.Errorf("planConnector: %w", err)
	}
	log.FromContext(ctx).Info().Str("connector_id", c.ConnectorID).Str("run_id", run.ID).
		Str("status", string(run.Status)).Int("volumes", len(targets)).Msg("disk scan planned")
	return nil
}

// targets are the connector's VMs whose package inventory is not already known
// from another source and whose last disk result is not recent enough to keep.
func (w *DiskScanPlanWorker) targets(ctx context.Context, c diskscan.ConnectorSettings) ([]diskTarget, error) {
	kind, ok := diskVMTypes[string(c.Type)]
	if !ok {
		return nil, nil
	}
	vms, err := w.assets.ListByType(ctx, kind.assetType, maxPlanAssets)
	if err != nil {
		return nil, fmt.Errorf("targets: %w", err)
	}
	var cands []diskTarget
	for _, vm := range vms {
		vol := vm.Metadata[kind.volumeKey]
		if vm.Metadata["prov_connector_id"] != c.ConnectorID || vol == "" {
			continue
		}
		if asset.PackageInventoryKnown(vm.Metadata) && vm.Metadata[asset.MetaPackageInventory] != asset.PackageInventoryDisk {
			continue
		}
		cands = append(cands, diskTarget{assetID: vm.ID, volume: vol, region: vm.Region, imageID: vm.Metadata["image_id"]})
	}
	cands, err = w.dropRecent(ctx, cands)
	if err != nil {
		return nil, err
	}
	if len(cands) > w.limits.MaxVolumesPerRun {
		cands = cands[:w.limits.MaxVolumesPerRun]
	}
	if err := w.fillSizes(ctx, cands); err != nil {
		return nil, err
	}
	return cands, nil
}

// dropRecent skips volumes whose newest result is still fresh: a known one for
// RescanKnownAfter, a gap for RescanGapAfter.
func (w *DiskScanPlanWorker) dropRecent(ctx context.Context, cands []diskTarget) ([]diskTarget, error) {
	if len(cands) == 0 {
		return nil, nil
	}
	ids := make([]string, len(cands))
	for i, t := range cands {
		ids[i] = t.assetID
	}
	latest, err := w.svc.Latest(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("dropRecent: %w", err)
	}
	now := w.clock()
	out := cands[:0]
	for _, t := range cands {
		res, seen := latest[t.assetID]
		keepFor := w.limits.RescanGapAfter
		if res.InventoryKnown {
			keepFor = w.limits.RescanKnownAfter
		}
		// A stale gap means the credentials ran out, not that the disk was unreadable.
		if seen && res.VolumeRef == t.volume && res.Gap != diskscan.GapStale && now.Sub(res.ObservedAt) < keepFor {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// fillSizes reads each volume's size from its ebs_volume asset where the
// graph has one, so a create can be refused before it spends a snapshot.
func (w *DiskScanPlanWorker) fillSizes(ctx context.Context, cands []diskTarget) error {
	if len(cands) == 0 {
		return nil
	}
	ids := make([]string, len(cands))
	for i, t := range cands {
		ids[i] = t.volume
	}
	vols, err := w.assets.ByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("fillSizes: %w", err)
	}
	size := make(map[string]int, len(vols))
	for _, v := range vols {
		if n, err := strconv.Atoi(v.Metadata["size_gb"]); err == nil && n > 0 {
			size[v.ID] = n
		}
	}
	for i := range cands {
		cands[i].sizeGiB = size[cands[i].volume]
	}
	return nil
}
