package jobs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/distro"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	cleanupTimeout     = 2 * time.Minute
	maxTouchedExtents  = 4096
	touchMergeGap      = 1 << 20
	knownCacheFor      = 7 * 24 * time.Hour
	gapCacheFor        = 24 * time.Hour
	deniedCachePrefix  = "denied:"
	dailyWindow        = 24 * time.Hour
	dailyCountRunLimit = 60
)

// DiskScanVolumeWorker reads one boot volume.
//
// It never returns a clean-looking result for a disk it did not read: every
// path that cannot read records a gap (VolumeResult.Gap), and RecordResult
// refuses a known inventory without packages' worth of evidence. A missing
// permission or a mode that is off is a recorded state, never a retry loop.
type DiskScanVolumeWorker struct {
	river.WorkerDefaults[DiskScanVolumeArgs]
	svc      diskScanService
	clouds   DiskScanClouds
	advisory distro.Sources
	limits   DiskScanLimits
	now      func() time.Time
	// scanDisk reads a disk; nil means engine.ScanDisk. Tests inject a fake.
	scanDisk func(context.Context, engine.BlockSource, engine.Limits) (engine.DiskResult, error)
}

func (w *DiskScanVolumeWorker) Timeout(*river.Job[DiskScanVolumeArgs]) time.Duration {
	return diskScanVolumeTimeout
}

func (w *DiskScanVolumeWorker) clock() time.Time {
	if w.now != nil {
		return w.now().UTC()
	}
	return time.Now().UTC()
}

func (w *DiskScanVolumeWorker) Work(ctx context.Context, job *river.Job[DiskScanVolumeArgs]) error {
	v := &volumeRun{w: w, a: job.Args}
	v.target = diskscan.DiskScanTarget{
		ConnectorID: v.a.ConnectorID, AssetID: v.a.AssetID, VolumeRef: v.a.VolumeRef, Boot: true, ImageID: v.a.ImageID,
	}
	v.vol = engine.VolumeRef{Provider: v.a.Provider, Region: v.a.Region, VolumeID: v.a.VolumeRef, Boot: true, ImageID: v.a.ImageID}

	err := v.run(ctx)
	if errors.Is(err, ErrDiskCredentialsExpired) {
		// The sealed credentials ran out mid-job. Retrying cannot help; the next
		// plan seals fresh ones. Any snapshot left behind is the sweep's.
		err = v.gap(ctx, diskscan.GapStale)
	}
	if err != nil {
		if ctx.Err() != nil || job.Attempt < job.MaxAttempts {
			return fmt.Errorf("Work: %w", err)
		}
		// Out of attempts: the volume reads as unknown rather than stay unreported
		// and hold its run open.
		log.FromContext(ctx).Error().Err(err).Str("run_id", v.a.RunID).Str("volume", v.a.VolumeRef).
			Msg("disk scan: volume failed on its last attempt, recorded as read_error")
		if recErr := v.record(ctx, diskscan.VolumeResult{Gap: diskscan.GapReadError}); recErr != nil {
			return fmt.Errorf("Work: %w", errors.Join(err, recErr))
		}
	}
	return v.finishRunIfDone(ctx)
}

// volumeRun is one execution of the job.
type volumeRun struct {
	w      *DiskScanVolumeWorker
	a      DiskScanVolumeArgs
	target diskscan.DiskScanTarget
	vol    engine.VolumeRef
	access DiskScanAccess
	mode   diskscan.DiskScanMode
	optIn  engine.OptIn
	readIn engine.ReadOptIn
}

func (v *volumeRun) ins() DiskOptIns { return DiskOptIns{Create: v.optIn, Read: v.readIn} }

func (v *volumeRun) record(ctx context.Context, res diskscan.VolumeResult) error {
	if res.ObservedAt.IsZero() {
		res.ObservedAt = v.w.clock()
	}
	return v.w.svc.RecordResult(ctx, v.a.RunID, v.target, res)
}

func (v *volumeRun) gap(ctx context.Context, gap string) error {
	return v.record(ctx, diskscan.VolumeResult{Gap: gap})
}

// run returns an error only for a failure worth retrying; every outcome that
// retrying cannot change is recorded and returns nil.
func (v *volumeRun) run(ctx context.Context) error {
	access, err := v.w.clouds.Open(ctx, v.a.ConnectorID, v.a.RunID, v.a.Sealed)
	if errors.Is(err, ErrDiskCredentialsExpired) {
		return v.gap(ctx, diskscan.GapStale)
	}
	if errors.Is(err, ErrDiskEnvelope) {
		return v.gap(ctx, diskscan.GapReadError)
	}
	if err != nil {
		return fmt.Errorf("run: open credentials: %w", err)
	}
	v.access = access

	grant, err := v.w.svc.Grant(ctx, v.a.ConnectorID)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	v.mode = diskscan.DiskScanMode(grant.Mode)
	if !v.mode.Enabled() {
		return v.gap(ctx, diskscan.GapNotEnabled)
	}
	// Role identifiers come from the sealed envelope: this pod cannot read the
	// connector's config. The mode above is read live, so turning the feature
	// off stops reads at the next job.
	grant.DiskScanRole, grant.OtherRoles = access.Role, access.OtherRoles
	canCreate := false
	// The read opt-in holds in both modes, and only with a distinct principal. AWS
	// and GCP never use it; Azure cannot read a snapshot without it.
	readIn, rerr := engine.AuthorizeRead(grant)
	switch {
	case rerr == nil:
		v.readIn = readIn
	case !errors.Is(rerr, engine.ErrNotAuthorized):
		return fmt.Errorf("run: %w", rerr)
	}
	if v.mode == diskscan.DiskScanModeCreateSnapshots {
		optIn, aerr := engine.Authorize(grant)
		switch {
		case aerr == nil:
			v.optIn, canCreate = optIn, true
		case !errors.Is(aerr, engine.ErrNotAuthorized):
			return fmt.Errorf("run: %w", aerr)
		}
	}

	snaps, err := access.Cloud.Provider(v.ins()).ListReusable(ctx, v.vol)
	switch {
	case errors.Is(err, ErrDiskPermissionDenied):
		v.cacheDenial(ctx)
		return v.gap(ctx, diskscan.GapPermissionDenied)
	case err != nil:
		return fmt.Errorf("run: list snapshots of %s: %w", v.vol.VolumeID, err)
	}
	if len(snaps) > 0 {
		return v.scan(ctx, snaps[0], snaps[1:], diskscan.SourceReused)
	}
	switch {
	case !canCreate && v.mode == diskscan.DiskScanModeCreateSnapshots:
		return v.gap(ctx, diskscan.GapNotEnabled)
	case !canCreate:
		return v.gap(ctx, diskscan.GapNoSnapshotAvailable)
	}
	return v.createAndScan(ctx)
}

func (v *volumeRun) deniedKey() string { return deniedCachePrefix + v.a.ConnectorID }

func (v *volumeRun) cacheDenial(ctx context.Context) {
	now := v.w.clock()
	err := v.w.svc.CachePut(ctx, diskscan.CacheEntry{
		Provider: v.a.Provider, SnapshotID: v.deniedKey(), CachedAt: now, ExpiresAt: now.Add(v.w.limits.DenialCacheFor),
		Result: diskscan.VolumeResult{Gap: diskscan.GapPermissionDenied},
	})
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("connector_id", v.a.ConnectorID).Msg("disk scan: caching a permission denial failed")
	}
}

func (v *volumeRun) denied(ctx context.Context) bool {
	_, hit, err := v.w.svc.CacheGet(ctx, v.a.Provider, v.deniedKey())
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("disk scan: reading the denial cache failed")
	}
	return hit
}

// createdToday counts the connector's snapshots created in the last 24 hours.
func (v *volumeRun) createdToday(ctx context.Context) (int, error) {
	since := v.w.clock().Add(-dailyWindow)
	runs, err := v.w.svc.ListRuns(ctx, v.a.ConnectorID, dailyCountRunLimit)
	if err != nil {
		return 0, fmt.Errorf("createdToday: %w", err)
	}
	n := 0
	for _, run := range runs {
		if run.StartedAt.Before(since.Add(-dailyWindow)) {
			continue
		}
		vols, err := v.w.svc.ListVolumes(ctx, run.ID)
		if err != nil {
			return 0, fmt.Errorf("createdToday: %w", err)
		}
		for _, vol := range vols {
			if vol.SnapshotSource == diskscan.SourceCreated && !vol.ObservedAt.Before(since) {
				n++
			}
		}
	}
	return n, nil
}

// createAndScan snapshots the volume with the opted-in role, reads the
// snapshot and deletes it. The intent row is written before the create call, a
// retry finds the run's snapshot instead of creating a second one, and the
// deferred cleanup deletes the snapshot on every path once it exists.
func (v *volumeRun) createAndScan(ctx context.Context) error {
	lim := v.w.limits
	if v.a.SizeGiB > 0 && int64(v.a.SizeGiB)<<30 > lim.MaxVolumeBytes {
		return v.gap(ctx, diskscan.GapOverCap)
	}
	if v.denied(ctx) {
		return v.gap(ctx, diskscan.GapPermissionDenied)
	}
	made, err := v.createdToday(ctx)
	if err != nil {
		return fmt.Errorf("createAndScan: %w", err)
	}
	if made >= lim.DailySnapshotCap {
		return v.gap(ctx, diskscan.GapOverCap)
	}
	sn, err := v.access.Cloud.Snapshotter(v.optIn)
	if errors.Is(err, engine.ErrNotAuthorized) {
		return v.gap(ctx, diskscan.GapNotEnabled)
	}
	if err != nil {
		return fmt.Errorf("createAndScan: %w", err)
	}

	intent, err := v.w.svc.RegisterSnapshotIntent(ctx, diskscan.SnapshotIntent{
		RunID: v.a.RunID, ConnectorID: v.a.ConnectorID, Provider: v.a.Provider, Region: v.a.Region, VolumeRef: v.a.VolumeRef,
	})
	if err != nil {
		return fmt.Errorf("createAndScan: %w", err)
	}
	if !intent.DeletedAt.IsZero() {
		// A previous attempt of this run created, cleaned up and then failed. The
		// next plan reads the volume again; this run does not snapshot it twice.
		return v.gap(ctx, diskscan.GapReadError)
	}

	snap, err := sn.CreateTagged(ctx, v.optIn, v.vol, v.a.RunID)
	if errors.Is(err, ErrDiskPermissionDenied) {
		v.cacheDenial(ctx)
		if merr := v.w.svc.MarkDeleted(ctx, intent.ID); merr != nil {
			log.FromContext(ctx).Warn().Err(merr).Msg("disk scan: marking a denied intent deleted failed")
		}
		return v.gap(ctx, diskscan.GapPermissionDenied)
	}
	if err != nil {
		// The create may or may not have happened. The intent stays: a retry finds
		// the run's tagged snapshot, and the sweep deletes it if no retry does.
		return fmt.Errorf("createAndScan: create snapshot of %s: %w", v.vol.VolumeID, err)
	}
	defer func() { v.cleanup(ctx, sn, snap, intent.ID) }()

	if err := v.w.svc.AttachSnapshot(ctx, intent.ID, snap.ID); err != nil {
		return fmt.Errorf("createAndScan: %w", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, lim.SnapshotWait)
	defer cancel()
	switch werr := v.access.Cloud.WaitCompleted(waitCtx, snap); {
	case errors.Is(werr, ErrDiskPermissionDenied):
		v.cacheDenial(ctx)
		return v.gap(ctx, diskscan.GapPermissionDenied)
	case (waitCtx.Err() != nil || errors.Is(werr, context.DeadlineExceeded)) && ctx.Err() == nil:
		return v.gap(ctx, diskscan.GapSnapshotPending)
	case werr != nil:
		return fmt.Errorf("createAndScan: wait for %s: %w", snap.ID, werr)
	}
	return v.scan(ctx, snap, nil, diskscan.SourceCreated)
}

// cleanup deletes a snapshot this job created, on a fresh context so a
// cancelled job still cleans up. A snapshot it cannot delete keeps its intent
// row, which the sweep acts on.
func (v *volumeRun) cleanup(ctx context.Context, sn engine.Snapshotter, snap engine.Snapshot, intentID string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	logger := log.FromContext(ctx)
	if err := v.access.Cloud.Release(cctx, v.ins(), snap); err != nil {
		logger.Warn().Err(err).Str("snapshot", snap.ID).Msg("disk scan: releasing read access failed")
	}
	if err := sn.DeleteTagged(cctx, v.optIn, snap); err != nil {
		logger.Error().Err(err).Str("snapshot", snap.ID).Msg("disk scan: deleting a created snapshot failed; the sweep retries")
		return
	}
	if err := v.w.svc.MarkDeleted(cctx, intentID); err != nil {
		logger.Error().Err(err).Str("snapshot", snap.ID).Msg("disk scan: marking a deleted snapshot failed; the sweep re-checks it")
	}
}

// finishRunIfDone closes the run once every planned volume has a result.
func (v *volumeRun) finishRunIfDone(ctx context.Context) error {
	vols, err := v.w.svc.ListVolumes(ctx, v.a.RunID)
	if err != nil {
		return fmt.Errorf("finishRunIfDone: %w", err)
	}
	if len(vols) < v.a.Planned {
		return nil
	}
	if _, err := v.w.svc.FinishRun(ctx, v.a.RunID, v.a.Planned, nil); err != nil {
		return fmt.Errorf("finishRunIfDone: %w", err)
	}
	return nil
}

// touchRecorder wraps a BlockSource and remembers which byte ranges were read,
// so a later snapshot with no changed block in them can reuse the result.
type touchRecorder struct {
	engine.BlockSource
	mu    sync.Mutex
	spans []engine.Extent
}

func (t *touchRecorder) ReadAt(p []byte, off int64) (int, error) {
	t.mu.Lock()
	t.spans = append(t.spans, engine.Extent{Offset: off, Length: int64(len(p))})
	t.mu.Unlock()
	return t.BlockSource.ReadAt(p, off)
}

// Extents returns the read ranges sorted and merged. Past maxTouchedExtents the
// whole read span is returned as one extent: a larger claim only makes reuse
// rarer, never wrong.
func (t *touchRecorder) Extents() []engine.Extent {
	t.mu.Lock()
	defer t.mu.Unlock()
	spans := slices.Clone(t.spans)
	slices.SortFunc(spans, func(a, b engine.Extent) int { return int(a.Offset - b.Offset) })
	var out []engine.Extent
	for _, s := range spans {
		if n := len(out); n > 0 && s.Offset <= out[n-1].Offset+out[n-1].Length+touchMergeGap {
			if end := s.Offset + s.Length; end > out[n-1].Offset+out[n-1].Length {
				out[n-1].Length = end - out[n-1].Offset
			}
			continue
		}
		out = append(out, s)
	}
	if len(out) > maxTouchedExtents {
		last := out[len(out)-1]
		return []engine.Extent{{Offset: out[0].Offset, Length: last.Offset + last.Length - out[0].Offset}}
	}
	return out
}

func intersects(a, b []engine.Extent) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Offset < y.Offset+y.Length && y.Offset < x.Offset+x.Length {
				return true
			}
		}
	}
	return false
}

// capturedAt is when the snapshot's data was captured: the stamp and the
// staleness rule read the disk's age, not when this job looked at it.
func (v *volumeRun) capturedAt(snap engine.Snapshot) time.Time {
	if snap.CreatedAt.IsZero() {
		return v.w.clock()
	}
	return snap.CreatedAt.UTC()
}

// scan reads snap, or reuses an earlier read of it, and records the outcome.
// others are the volume's other existing snapshots, candidates for a
// changed-block diff against the previous result's snapshot.
func (v *volumeRun) scan(ctx context.Context, snap engine.Snapshot, others []engine.Snapshot, source diskscan.SnapshotSource) error {
	provider := v.access.Cloud.Provider(v.ins())
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		if err := v.access.Cloud.Release(cctx, v.ins(), snap); err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("snapshot", snap.ID).Msg("disk scan: releasing read access failed")
		}
	}()

	if source != diskscan.SourceCreated {
		if reused, err := v.reuse(ctx, provider, snap, others, source); err != nil {
			return err
		} else if reused {
			return nil
		}
	}
	src, err := provider.Open(ctx, snap)
	switch {
	case errors.Is(err, ErrDiskEncryptedNoKey):
		return v.recordGap(ctx, snap, source, diskscan.GapEncryptedNoKey, true)
	case errors.Is(err, ErrDiskPermissionDenied):
		v.cacheDenial(ctx)
		return v.recordGap(ctx, snap, source, diskscan.GapPermissionDenied, false)
	case err != nil:
		return fmt.Errorf("scan: open %s: %w", snap.ID, err)
	}
	defer func() { _ = src.Close() }()

	rec := &touchRecorder{BlockSource: src}
	scan := v.w.scanDisk
	if scan == nil {
		scan = engine.ScanDisk
	}
	dr, err := scan(ctx, rec, engine.Limits{MaxVolumeBytes: v.w.limits.MaxVolumeBytes, MaxBytesRead: v.w.limits.MaxBytesRead})
	if err != nil {
		return fmt.Errorf("scan: read %s: %w", snap.ID, err)
	}
	if !dr.InventoryKnown || len(dr.Packages) == 0 || dr.Ecosystem == "" {
		gap := dr.Gap
		if gap == diskscan.GapNone {
			gap = diskscan.GapReadError
		}
		return v.recordGap(ctx, snap, source, gap, false)
	}
	return v.recordKnown(ctx, snap, source, dr.Ecosystem, dr.Packages, rec.Extents())
}

// recordKnown stores the packages first, then the result that vouches for them.
func (v *volumeRun) recordKnown(ctx context.Context, snap engine.Snapshot, source diskscan.SnapshotSource,
	ecosystem string, pkgs []pkginventory.InstalledPackage, touched []engine.Extent) error {
	observed := v.capturedAt(snap)
	err := v.w.svc.RecordPackages(ctx, diskscan.PackageSet{
		AssetID: v.a.AssetID, VolumeRef: v.a.VolumeRef, RunID: v.a.RunID, SnapshotID: snap.ID,
		Ecosystem: ecosystem, Packages: pkgs, ObservedAt: observed,
	})
	if err != nil {
		return fmt.Errorf("recordKnown: %w", err)
	}
	cveGap := pkginventory.CVEGap(ecosystem, pkginventory.HasSourceNames(pkgs), v.w.advisory, v.w.clock())
	res := diskscan.VolumeResult{
		SnapshotID: snap.ID, SnapshotSource: source, Encrypted: snap.Encrypted, InventoryKnown: true,
		CVEMatchableKnown: cveGap == "", PackageCount: len(pkgs), ObservedAt: observed,
	}
	if err := v.record(ctx, res); err != nil {
		return fmt.Errorf("recordKnown: %w", err)
	}
	v.cacheResult(ctx, snap, source, res, touched, knownCacheFor)
	return nil
}

// recordGap stores an unknown inventory. Gaps a later read can change are not
// cached beyond a day.
func (v *volumeRun) recordGap(ctx context.Context, snap engine.Snapshot, source diskscan.SnapshotSource, gap string, encrypted bool) error {
	res := diskscan.VolumeResult{
		SnapshotID: snap.ID, SnapshotSource: source, Encrypted: snap.Encrypted || encrypted, Gap: gap, ObservedAt: v.capturedAt(snap),
	}
	if err := v.record(ctx, res); err != nil {
		return fmt.Errorf("recordGap: %w", err)
	}
	if gap == diskscan.GapUnsupportedFS || gap == diskscan.GapUnsupportedPartition || gap == diskscan.GapEncryptedNoKey || gap == diskscan.GapOverCap {
		v.cacheResult(ctx, snap, source, res, nil, gapCacheFor)
	}
	return nil
}

// cacheResult remembers a result under (provider, snapshot). A snapshot we
// created is deleted within hours, so nothing could hit its entry.
func (v *volumeRun) cacheResult(ctx context.Context, snap engine.Snapshot, source diskscan.SnapshotSource, res diskscan.VolumeResult, touched []engine.Extent, ttl time.Duration) {
	if source == diskscan.SourceCreated {
		return
	}
	now := v.w.clock()
	err := v.w.svc.CachePut(ctx, diskscan.CacheEntry{
		Provider: v.a.Provider, SnapshotID: snap.ID, Extents: touched, Result: res, CachedAt: now, ExpiresAt: now.Add(ttl),
	})
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("snapshot", snap.ID).Msg("disk scan: caching a result failed; the next run reads again")
	}
}

// reuse answers from the cache, or from a changed-block diff against the
// previous result's snapshot, without reading the disk. It reports false when
// the volume must be read.
func (v *volumeRun) reuse(ctx context.Context, provider engine.Provider, snap engine.Snapshot, others []engine.Snapshot, source diskscan.SnapshotSource) (bool, error) {
	entry, hit, err := v.w.svc.CacheGet(ctx, v.a.Provider, snap.ID)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("disk scan: reading the result cache failed; reading the disk")
		return false, nil
	}
	if hit {
		return v.replay(ctx, snap, source, entry)
	}
	return v.reuseByDiff(ctx, provider, snap, others, source)
}

// replay records a cached result. A known inventory needs its package list,
// which the table holds only for the volume's latest snapshot.
func (v *volumeRun) replay(ctx context.Context, snap engine.Snapshot, source diskscan.SnapshotSource, entry diskscan.CacheEntry) (bool, error) {
	res := entry.Result
	res.SnapshotID, res.SnapshotSource, res.Encrypted, res.ObservedAt = snap.ID, source, snap.Encrypted || res.Encrypted, v.capturedAt(snap)
	if res.InventoryKnown {
		if _, ok, err := v.packagesOf(ctx, snap.ID); err != nil {
			return false, err
		} else if !ok {
			return false, nil
		}
	}
	if err := v.record(ctx, res); err != nil {
		return false, fmt.Errorf("replay: %w", err)
	}
	return true, nil
}

func (v *volumeRun) packagesOf(ctx context.Context, snapshotID string) (diskscan.PackageSet, bool, error) {
	sets, err := v.w.svc.Packages(ctx, []string{v.a.AssetID})
	if err != nil {
		return diskscan.PackageSet{}, false, fmt.Errorf("packagesOf: %w", err)
	}
	for _, s := range sets {
		if s.VolumeRef == v.a.VolumeRef && s.SnapshotID == snapshotID {
			return s, true, nil
		}
	}
	return diskscan.PackageSet{}, false, nil
}

func (v *volumeRun) reuseByDiff(ctx context.Context, provider engine.Provider, snap engine.Snapshot, others []engine.Snapshot, source diskscan.SnapshotSource) (bool, error) {
	prev, err := v.w.svc.Latest(ctx, []string{v.a.AssetID})
	if err != nil {
		return false, fmt.Errorf("reuseByDiff: %w", err)
	}
	last, ok := prev[v.a.AssetID]
	if !ok || !last.InventoryKnown || last.VolumeRef != v.a.VolumeRef || last.SnapshotID == "" || last.SnapshotID == snap.ID {
		return false, nil
	}
	entry, hit, err := v.w.svc.CacheGet(ctx, v.a.Provider, last.SnapshotID)
	if err != nil || !hit || len(entry.Extents) == 0 {
		return false, nil
	}
	baseIdx := slices.IndexFunc(others, func(s engine.Snapshot) bool { return s.ID == last.SnapshotID })
	if baseIdx < 0 {
		return false, nil
	}
	changed, err := provider.Changed(ctx, others[baseIdx], snap)
	if err != nil || intersects(changed, entry.Extents) {
		return false, nil
	}
	set, ok, err := v.packagesOf(ctx, last.SnapshotID)
	if err != nil || !ok {
		return false, err
	}
	set.RunID, set.SnapshotID, set.ObservedAt = v.a.RunID, snap.ID, v.capturedAt(snap)
	if err := v.w.svc.RecordPackages(ctx, set); err != nil {
		return false, fmt.Errorf("reuseByDiff: %w", err)
	}
	res := entry.Result
	res.SnapshotID, res.SnapshotSource, res.Encrypted, res.ObservedAt = snap.ID, source, snap.Encrypted, set.ObservedAt
	if err := v.record(ctx, res); err != nil {
		return false, fmt.Errorf("reuseByDiff: %w", err)
	}
	v.cacheResult(ctx, snap, source, res, entry.Extents, knownCacheFor)
	return true, nil
}
