package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
)

type fakeImageScanner struct {
	mu       sync.Mutex
	byDigest map[string]imagevuln.Result
	got      []string
}

func (f *fakeImageScanner) ScanImage(_ context.Context, digest, _ string) (imagevuln.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, digest)
	return f.byDigest[digest], nil
}

type fakeImageStore struct{ imgs []asset.Asset }

func (f *fakeImageStore) ListByType(_ context.Context, _ string, _ int) ([]asset.Asset, error) {
	return f.imgs, nil
}

type fakeIngester struct {
	mu     sync.Mutex
	assets []asset.Asset
	edges  []asset.Edge
}

func (f *fakeIngester) Ingest(_ context.Context, a []asset.Asset, e []asset.Edge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.assets = append(f.assets, a...)
	f.edges = append(f.edges, e...)
	return nil
}

func TestImageVulnWorker_ScansRecordsAndIngests(t *testing.T) {
	images := &fakeImageStore{imgs: []asset.Asset{
		{ID: "image/sha256:aaa", Type: "container_image", Metadata: map[string]string{"image_id": "sha256:aaa", "image_ref": "gcr.io/p/a:1"}},
		{ID: "image/sha256:bbb", Type: "container_image", Metadata: map[string]string{"image_id": "sha256:bbb", "image_ref": "gcr.io/p/b:2"}},
		{ID: "image/nodigest", Type: "container_image", Metadata: map[string]string{}}, // skipped: no digest
	}}
	scanner := &fakeImageScanner{byDigest: map[string]imagevuln.Result{
		"sha256:aaa": {
			Findings: []finding.Finding{{ID: "f1", Source: "supply_chain", ResourceType: "package", ResourceID: "pkg:deb/debian/openssl@1", CheckID: "CVE-1"}},
			Assets:   []asset.Asset{{ID: "pkg:deb/debian/openssl@1", Type: "package"}},
			Edges:    []asset.Edge{{SrcID: "image/sha256:aaa", DstID: "pkg:deb/debian/openssl@1", EdgeType: "runs_package"}},
		},
		"sha256:bbb": {}, // clean image
	}}
	findings := &fakeFindingStore{}
	ing := &fakeIngester{}

	w := &ImageVulnWorker{scanner: scanner, images: images, assets: ing, findings: findings}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))

	// Only the two images WITH a digest are scanned; the digest-less one is skipped.
	require.ElementsMatch(t, []string{"sha256:aaa", "sha256:bbb"}, scanner.got)

	// The one finding is recorded and its package asset + runs_package edge ingested.
	require.Len(t, findings.recorded, 1)
	require.Equal(t, "f1", findings.recorded[0].ID)
	require.Len(t, ing.assets, 1)
	require.Len(t, ing.edges, 1)
	require.Equal(t, "runs_package", ing.edges[0].EdgeType)
}

type fakeBaseRecorder struct {
	mu    sync.Mutex
	bases []asset.ImageBase
}

func (f *fakeBaseRecorder) RecordImageBases(_ context.Context, b []asset.ImageBase) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bases = append(f.bases, b...)
	return nil
}

// Every cleanly scanned image records its base identity — unknown included, so
// "scanned, unidentified" and "not scanned yet" stay different facts.
func TestImageVulnWorker_RecordsBaseIdentity(t *testing.T) {
	images := &fakeImageStore{imgs: []asset.Asset{
		{ID: "image/sha256:aaa", Type: "container_image", Metadata: map[string]string{"image_id": "sha256:aaa", "image_ref": "gcr.io/p/a:1"}},
		{ID: "image/sha256:bbb", Type: "container_image", Metadata: map[string]string{"image_id": "sha256:bbb", "image_ref": "gcr.io/p/b:1"}},
	}}
	scanner := &fakeImageScanner{byDigest: map[string]imagevuln.Result{
		"sha256:aaa": {Base: imagevuln.BaseIdentity{Image: "debian:bookworm-slim", Source: imagevuln.BaseSourceAnnotation, OS: "Debian:12"}},
		"sha256:bbb": {Base: imagevuln.BaseIdentity{Source: imagevuln.BaseSourceUnknown}},
	}}
	bases := &fakeBaseRecorder{}
	w := &ImageVulnWorker{scanner: scanner, images: images, assets: &fakeIngester{}, findings: &fakeFindingStore{}, bases: bases}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))

	byID := map[string]asset.ImageBase{}
	for _, b := range bases.bases {
		byID[b.ImageID] = b
	}
	require.Len(t, byID, 2)
	require.Equal(t, "debian:bookworm-slim", byID["image/sha256:aaa"].BaseImage)
	require.Equal(t, imagevuln.BaseSourceAnnotation, byID["image/sha256:aaa"].BaseImageSource)
	require.Equal(t, "Debian:12", byID["image/sha256:aaa"].BaseOS)
	require.Equal(t, imagevuln.BaseSourceUnknown, byID["image/sha256:bbb"].BaseImageSource)
	require.Empty(t, byID["image/sha256:bbb"].BaseOS)
}

// A digest is immutable, but its coverage finding is not permanent: once a
// rescan matches the image's OS packages in full — the scanner now reads its
// rpm database — the finding an older scan opened is resolved as fixed. An image
// still carrying a gap keeps it open, and a resolved one is not re-resolved.
func TestImageVulnWorker_ResolvesCoverageOnceMatchable(t *testing.T) {
	images := &fakeImageStore{imgs: []asset.Asset{
		{ID: "image/sha256:ubi", Type: "container_image", Metadata: map[string]string{"image_id": "sha256:ubi", "image_ref": "ubi9"}},
		{ID: "image/sha256:old", Type: "container_image", Metadata: map[string]string{"image_id": "sha256:old", "image_ref": "debian:10"}},
		{ID: "image/sha256:done", Type: "container_image", Metadata: map[string]string{"image_id": "sha256:done", "image_ref": "alpine"}},
	}}
	gap := finding.Finding{ID: imagevuln.OSCoverageFindingID("sha256:old"), CheckID: "imagevuln-os-packages-unmatchable"}
	scanner := &fakeImageScanner{byDigest: map[string]imagevuln.Result{
		"sha256:ubi":  {},
		"sha256:old":  {OSCVEGap: asset.CVEGapEOLDistro, Findings: []finding.Finding{gap}},
		"sha256:done": {},
	}}
	findings := &fakeFindingStore{list: []finding.Finding{
		{ID: imagevuln.OSCoverageFindingID("sha256:ubi"), CheckID: "imagevuln-os-packages-unmatchable"},
		{ID: imagevuln.OSCoverageFindingID("sha256:old"), CheckID: "imagevuln-os-packages-unmatchable"},
		{ID: imagevuln.OSCoverageFindingID("sha256:done"), ResolvedAt: time.Now().Add(-time.Hour), ResolutionReason: finding.ReasonFixed},
	}}
	w := &ImageVulnWorker{scanner: scanner, images: images, assets: &fakeIngester{}, findings: findings}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))

	require.Len(t, findings.resolved, 1)
	require.Equal(t, imagevuln.OSCoverageFindingID("sha256:ubi"), findings.resolved[0].ID)
	require.Equal(t, finding.ReasonFixed, findings.reasons[findings.resolved[0].ID])
}

func TestImageVulnWorker_NoImages(t *testing.T) {
	w := &ImageVulnWorker{
		scanner:  &fakeImageScanner{},
		images:   &fakeImageStore{},
		assets:   &fakeIngester{},
		findings: &fakeFindingStore{},
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
}

// fakeCursor is an in-memory ImageScanCursor.
type fakeCursor struct {
	mu     sync.Mutex
	states map[string]imageScanState
	marked []string
	failed []imageFailure

	// prune records the args of the last PruneOrphaned call and lets tests
	// inject its return value.
	pruneCalls   int
	prunedLive   []string
	prunedCutoff time.Time
	pruneResult  int64
	pruneErr     error
}

func (f *fakeCursor) States(context.Context) (map[string]imageScanState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]imageScanState{}
	for k, v := range f.states {
		out[k] = v
	}
	return out, nil
}

func (f *fakeCursor) MarkScanned(_ context.Context, digests []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.marked = append(f.marked, digests...)
	return nil
}

func (f *fakeCursor) MarkFailed(_ context.Context, failures []imageFailure) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed = append(f.failed, failures...)
	return nil
}

func (f *fakeCursor) PruneOrphaned(_ context.Context, liveDigests []string, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneCalls++
	f.prunedLive = append([]string(nil), liveDigests...)
	f.prunedCutoff = cutoff
	return f.pruneResult, f.pruneErr
}

// scannedState is a digest whose last action was a clean scan at t.
func scannedState(t time.Time) imageScanState {
	return imageScanState{scannedAt: t, attemptedAt: t}
}

// imageAssets builds one container_image asset per digest, in the order given,
// each with a fresh LastSeen — i.e. genuinely live, per liveImageDigests' own
// liveness filter. Use imageAssetsSeenAt directly for a fixture that needs to
// look stale/orphaned.
func imageAssets(digests ...string) []asset.Asset {
	return imageAssetsSeenAt(time.Now(), digests...)
}

func imageAssetsSeenAt(lastSeen time.Time, digests ...string) []asset.Asset {
	out := make([]asset.Asset, 0, len(digests))
	for _, d := range digests {
		out = append(out, asset.Asset{
			ID: "image/" + d, Type: "container_image", LastSeen: lastSeen,
			Metadata: map[string]string{"image_id": d, "image_ref": "gcr.io/p/" + d},
		})
	}
	return out
}

// Guards GraphImageScanCoverageStale against firing on a digest that scanned
// cleanly once and then dropped out of inventory: selectTargets only ever
// touches digests present in the current `images` listing, so an orphaned
// row's scanned_at is frozen forever and permanently drags down
// min(scanned_at) no matter how healthy the rest of the estate is. Mirrors
// OSV's DeleteOrphanedScannedPackages fix for the identical shape
// (GraphOSVScanCoverageStale).
func TestImageVulnWorker_PruneOrphanedUsesLiveDigestsAndRescanCutoff(t *testing.T) {
	// A duplicate digest (two assets can share an image_id after a retag) must
	// be deduplicated, exactly as selectTargets' own `seen` map does.
	images := append(imageAssets("sha256:a", "sha256:b"), imageAssets("sha256:a")...)
	cursor := &fakeCursor{}
	w := &ImageVulnWorker{cursor: cursor}

	before := time.Now()
	w.pruneOrphaned(context.Background(), images)
	after := time.Now()

	require.Equal(t, 1, cursor.pruneCalls)
	require.ElementsMatch(t, []string{"sha256:a", "sha256:b"}, cursor.prunedLive)
	require.False(t, cursor.prunedCutoff.Before(before.Add(-imageRescanAfter)),
		"cutoff must be imageRescanAfter ago, not something shorter")
	require.False(t, cursor.prunedCutoff.After(after.Add(-imageRescanAfter)),
		"cutoff must be imageRescanAfter ago, not something longer")
}

// TestImageVulnWorker_PruneOrphanedExcludesStaleLastSeen guards the liveness
// half of the prune: ContainerImageStore.ListByType is backed by
// assetIDsByType, which applies NO liveness gate (its one exemption in
// TestAssetReadersApplyLiveness was scoped to packages, a different, genuinely
// non-ephemeral caller) — so a decommissioned image's asset row is returned by
// ListByType forever, same as any other asset row never being deleted. Without
// filtering on LastSeen here, such a row would count as "live" and never be
// pruned, and graph_image_scan_oldest_scanned_timestamp_seconds would hold its
// stale value across a completed, successful refresh_image_vuln run.
func TestImageVulnWorker_PruneOrphanedExcludesStaleLastSeen(t *testing.T) {
	live := imageAssetsSeenAt(time.Now(), "sha256:live")
	stale := imageAssetsSeenAt(time.Now().Add(-14*24*time.Hour), "sha256:orphaned")
	cursor := &fakeCursor{}
	w := &ImageVulnWorker{cursor: cursor}

	w.pruneOrphaned(context.Background(), append(live, stale...))

	require.Equal(t, 1, cursor.pruneCalls)
	require.ElementsMatch(t, []string{"sha256:live"}, cursor.prunedLive,
		"an asset row ListByType still returns for a digest ClickHouse has not actually seen "+
			"in 14 days must NOT count as live — that is exactly how a decommissioned image stays "+
			"un-pruned forever despite this sweep running cleanly")
}

// A listing at the hard cap cannot be trusted as a complete inventory
// snapshot — see listImageLimit's own doc — and this operation DELETES rows,
// so an incomplete "live" set must never be treated as authoritative: that
// would prune digests that are actually still live but fell outside the cap.
func TestImageVulnWorker_PruneOrphanedSkippedWhenListingLooksTruncated(t *testing.T) {
	images := make([]asset.Asset, listImageLimit)
	for i := range images {
		d := fmt.Sprintf("sha256:%d", i)
		images[i] = asset.Asset{ID: "image/" + d, Type: "container_image", Metadata: map[string]string{"image_id": d}}
	}
	cursor := &fakeCursor{}
	w := &ImageVulnWorker{cursor: cursor}

	w.pruneOrphaned(context.Background(), images)
	require.Zero(t, cursor.pruneCalls)
}

// If every asset in a non-empty listing resolves to a blank digest, the
// "live" set is empty — and an empty live set sent to the prune query would
// delete every row in the table (NOT (digest = ANY('{}')) is true for
// everything). That must never happen from a listing that merely failed to
// resolve digests.
func TestImageVulnWorker_PruneOrphanedSkippedWhenNoDigestsResolve(t *testing.T) {
	images := []asset.Asset{
		{ID: "image/nodigest1", Type: "container_image", Metadata: map[string]string{}},
		{ID: "image/nodigest2", Type: "container_image", Metadata: map[string]string{"image_id": ""}},
	}
	cursor := &fakeCursor{}
	w := &ImageVulnWorker{cursor: cursor}

	w.pruneOrphaned(context.Background(), images)
	require.Zero(t, cursor.pruneCalls)
}

// A nil cursor (no Postgres wired) must degrade to a no-op, the same posture
// as scanStates/recordAttempts.
func TestImageVulnWorker_PruneOrphanedNilCursorIsNoOp(t *testing.T) {
	w := &ImageVulnWorker{}
	require.NotPanics(t, func() {
		w.pruneOrphaned(context.Background(), imageAssets("sha256:a"))
	})
}

// A prune failure must not fail the sweep: worst case a stale row lingers one
// more cycle, the same posture as recordAttempts' cursor-write failures.
func TestImageVulnWorker_PruneOrphanedFailureDoesNotFailSweep(t *testing.T) {
	images := &fakeImageStore{imgs: imageAssets("sha256:a")}
	cursor := &fakeCursor{pruneErr: errors.New("boom")}
	w := &ImageVulnWorker{
		scanner: &fakeImageScanner{byDigest: map[string]imagevuln.Result{}}, images: images,
		assets: &fakeIngester{}, findings: &fakeFindingStore{}, cursor: cursor,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Equal(t, 1, cursor.pruneCalls)
}

// Work() wiring: the prune runs against the same listing the sweep scans,
// every run — not just when the estate happens to have orphans.
func TestImageVulnWorker_WorkCallsPruneOrphaned(t *testing.T) {
	images := &fakeImageStore{imgs: imageAssets("sha256:a", "sha256:b")}
	cursor := &fakeCursor{}
	w := &ImageVulnWorker{
		scanner: &fakeImageScanner{byDigest: map[string]imagevuln.Result{}}, images: images,
		assets: &fakeIngester{}, findings: &fakeFindingStore{}, cursor: cursor,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Equal(t, 1, cursor.pruneCalls)
	require.ElementsMatch(t, []string{"sha256:a", "sha256:b"}, cursor.prunedLive)
}

// The cursor is the whole point: without it the sweep re-lists images by
// last_seen DESC and rescans the same prefix every run, so most images
// never produce a runs_package edge.
func TestImageVulnWorker_ScansLeastRecentlyScannedFirst(t *testing.T) {
	now := time.Now()
	images := &fakeImageStore{imgs: imageAssets("sha256:fresh", "sha256:stale", "sha256:never")}
	cursor := &fakeCursor{states: map[string]imageScanState{
		// "fresh" is only relatively fresh: both are past imageRescanAfter, so this
		// test is about ORDER and nothing else.
		"sha256:fresh": scannedState(now.Add(-(imageRescanAfter + time.Hour))),
		"sha256:stale": scannedState(now.Add(-90 * 24 * time.Hour)),
	}}
	scanner := &fakeImageScanner{byDigest: map[string]imagevuln.Result{}}

	w := &ImageVulnWorker{
		scanner: scanner, images: images, assets: &fakeIngester{},
		findings: &fakeFindingStore{}, cursor: cursor,
	}
	plan, err := w.selectTargets(context.Background(), images.imgs)
	targets, total := plan.targets, plan.total
	require.NoError(t, err)
	require.Equal(t, 3, total)
	require.Equal(t,
		[]string{"sha256:never", "sha256:stale", "sha256:fresh"},
		[]string{targets[0].digest, targets[1].digest, targets[2].digest},
		"never-scanned first, then least recently scanned")

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.ElementsMatch(t, []string{"sha256:never", "sha256:stale", "sha256:fresh"}, cursor.marked)
}

// A digest that failed to scan must NOT be recorded as scanned — that would hide
// the failure behind a full rotation of the estate — but the ATTEMPT must be
// recorded, or it sorts ahead of every healthy image forever.
func TestImageVulnWorker_FailedScanRecordsAttemptNotAScan(t *testing.T) {
	images := &fakeImageStore{imgs: imageAssets("sha256:ok", "sha256:bad")}
	cursor := &fakeCursor{}
	scanner := &failingImageScanner{fail: "sha256:bad"}

	w := &ImageVulnWorker{
		scanner: scanner, images: images, assets: &fakeIngester{},
		findings: &fakeFindingStore{}, cursor: cursor,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Equal(t, []string{"sha256:ok"}, cursor.marked)
	require.Len(t, cursor.failed, 1)
	require.Equal(t, "sha256:bad", cursor.failed[0].digest)
	require.Contains(t, cursor.failed[0].reason, "pull failed",
		"the reason is recorded so an operator can tell WHY an image is uncovered")
}

// The livelock the attempted_at/failures cursor columns exist to break.
//
// If only a clean scan wrote scanned_at and selection put never-scanned digests
// first, a permanently unscannable digest would sort ahead of every successful
// one for ever: the same imagesPerSweep failures would fill every run and a
// healthy image behind them would never be reached again. On a large estate the
// failing set can exceed the per-sweep image budget outright.
func TestImageVulnWorker_FailingDigestsDoNotStarveHealthyOnes(t *testing.T) {
	now := time.Now()
	images := &fakeImageStore{imgs: imageAssets("sha256:broken", "sha256:healthy")}
	cursor := &fakeCursor{states: map[string]imageScanState{
		// Tried a minute ago and failed; never once scanned.
		"sha256:broken": {attemptedAt: now.Add(-time.Minute), failures: 1},
		// Scanned cleanly, but a long time ago.
		"sha256:healthy": scannedState(now.Add(-30 * 24 * time.Hour)),
	}}

	w := &ImageVulnWorker{
		scanner: &failingImageScanner{fail: "sha256:broken"}, images: images,
		assets: &fakeIngester{}, findings: &fakeFindingStore{}, cursor: cursor,
	}
	plan, err := w.selectTargets(context.Background(), images.imgs)
	targets, total := plan.targets, plan.total
	require.NoError(t, err)
	require.Equal(t, 2, total, "a backed-off digest is still part of the estate")

	require.Len(t, targets, 1, "the freshly-failed digest is inside its backoff window")
	require.Equal(t, "sha256:healthy", targets[0].digest,
		"a digest that has only ever failed must not outrank a stale but healthy one")
}

// The ORDERING half of the livelock, which the test above does not reach.
//
// That test's failing digest is inside its 2h backoff, so it is filtered out at
// selectTargets before the sort is ever consulted — it asserts the backoff, not the
// ordering key. Without this test, replacing lastTouched's body with
// `return s.scannedAt` would leave the whole package green.
//
// The residual risk the backoff does NOT cover: for 1-4 consecutive failures the
// backoff is 2/4/8/16h, all shorter than imageVulnInterval (24h), so every failing
// digest is eligible on every daily sweep. Ordering by scanned_at then puts all of
// them — which have no scanned_at at all — ahead of every healthy image, so they
// would compete for the image budget on every run, forever. Ordering by last
// ATTEMPT is what makes progress monotonic.
func TestImageVulnWorker_FailingDigestOutsideBackoffSortsAfterStaleHealthy(t *testing.T) {
	now := time.Now()
	images := &fakeImageStore{imgs: imageAssets("sha256:broken", "sha256:healthy")}
	cursor := &fakeCursor{states: map[string]imageScanState{
		// Failed once, three hours ago: PAST its 2h backoff, so it is eligible —
		// and it has never been scanned, so scanned_at is the zero time.
		"sha256:broken": {attemptedAt: now.Add(-3 * time.Hour), failures: 1},
		// Scanned cleanly a day ago: stale, but the sweep did nothing with it since.
		"sha256:healthy": scannedState(now.Add(-24 * time.Hour)),
	}}

	w := &ImageVulnWorker{
		scanner: &failingImageScanner{fail: "sha256:broken"}, images: images,
		assets: &fakeIngester{}, findings: &fakeFindingStore{}, cursor: cursor,
	}
	plan, err := w.selectTargets(context.Background(), images.imgs)
	targets, total := plan.targets, plan.total
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, targets, 2, "past its backoff, the failing digest is eligible again")

	require.Equal(t, "sha256:healthy", targets[0].digest,
		"ordering is by last ATTEMPT: the healthy image was last touched 24h ago, the "+
			"broken one 3h ago. Ordering by scanned_at instead puts the never-scanned "+
			"broken digest first and starves the healthy one out of every sweep.")
	require.Equal(t, "sha256:broken", targets[1].digest)
}

// Backoff must be bounded and must never delay a healthy image.
func TestImageRetryBackoffGrowsAndCaps(t *testing.T) {
	require.Zero(t, imageRetryBackoff(0), "a digest with no failures is never delayed")
	require.Equal(t, 2*time.Hour, imageRetryBackoff(1))
	require.Equal(t, 4*time.Hour, imageRetryBackoff(2))
	require.Equal(t, imageRetryBackoffCap, imageRetryBackoff(100),
		"backoff must cap so a fixed registry is still picked up")
	require.Greater(t, imageRetryBackoff(6), imageVulnInterval,
		"a repeatedly failing digest must eventually sit out whole sweeps")
}

// Once a digest recovers it must stop backing off immediately — a clean scan
// resets the failure count, which is why MarkScanned writes failures = 0.
func TestImageVulnWorker_RecoveredDigestIsEligibleAgain(t *testing.T) {
	now := time.Now()
	images := &fakeImageStore{imgs: imageAssets("sha256:recovered")}
	cursor := &fakeCursor{states: map[string]imageScanState{
		"sha256:recovered": scannedState(now.Add(-2 * 24 * time.Hour)),
	}}
	w := &ImageVulnWorker{
		scanner: &fakeImageScanner{byDigest: map[string]imagevuln.Result{}}, images: images,
		assets: &fakeIngester{}, findings: &fakeFindingStore{}, cursor: cursor,
	}
	plan, err := w.selectTargets(context.Background(), images.imgs)
	targets := plan.targets
	require.NoError(t, err)
	require.Len(t, targets, 1)
}

type failingImageScanner struct{ fail string }

func (f *failingImageScanner) ScanImage(_ context.Context, digest, _ string) (imagevuln.Result, error) {
	if digest == f.fail {
		return imagevuln.Result{}, errors.New("pull failed")
	}
	return imagevuln.Result{}, nil
}

// A digest scanned inside imageRescanAfter is skipped, and that is what makes a
// complete pass reachable at all.
//
// Without it every digest is eligible on every run, so a 400-image slice of a
// larger eligible set is truncated by the time budget on EVERY sweep: the job
// could never report a complete pass and a continuation chain would never terminate.
func TestImageVulnWorker_RecentlyScannedDigestsAreSkipped(t *testing.T) {
	now := time.Now()
	images := &fakeImageStore{imgs: imageAssets("sha256:justdone", "sha256:due")}
	cursor := &fakeCursor{states: map[string]imageScanState{
		"sha256:justdone": scannedState(now.Add(-(imageRescanAfter - time.Hour))),
		"sha256:due":      scannedState(now.Add(-(imageRescanAfter + time.Hour))),
	}}
	w := &ImageVulnWorker{
		scanner: &fakeImageScanner{byDigest: map[string]imagevuln.Result{}}, images: images,
		assets: &fakeIngester{}, findings: &fakeFindingStore{}, cursor: cursor,
	}
	plan, err := w.selectTargets(context.Background(), images.imgs)
	targets, total := plan.targets, plan.total
	require.NoError(t, err)
	require.Equal(t, 2, total, "a digest inside the rescan window is still part of the estate")
	require.Len(t, targets, 1)
	require.Equal(t, "sha256:due", targets[0].digest)
}

// The rescan window must stay shorter than the sweep's own interval, or a digest
// scanned early in one day's chain is still "fresh" when the next tick fires and
// waits an extra full day — drifting runs_package toward the 48h edge
// freshness cliff.
func TestImageRescanWindowIsShorterThanTheSweepInterval(t *testing.T) {
	require.Less(t, imageRescanAfter, imageVulnInterval)
	require.Less(t, imageRescanAfter+imageVulnInterval, 48*time.Hour,
		"a digest must be re-scanned before its runs_package edges leave the 48h window")
}

// What a truncated sweep MEANS.
//
// Progress is already durable (recordAttempts commits on a detached context), so a
// sweep that scanned 225 of 400 images did 225 images of real work. Reporting that
// as an error would make a working sweep look identical to a broken one and lean
// on River's retry to finish the inventory — which River discards after the last
// attempt, leaving refresh_image_vuln with a zero success rate while still
// covering most digests a day.
func TestTruncatedOutcome(t *testing.T) {
	for _, tc := range []struct {
		name      string
		outOfTime bool
		scanned   int
		queued    int
		hop       int
		wantChain bool
		wantErr   bool
	}{
		{name: "complete pass", outOfTime: false, scanned: 12, queued: 12},
		{name: "complete pass with nothing to do", outOfTime: false},
		{
			name:      "truncated after real progress chains, does not error",
			outOfTime: true, scanned: 225, queued: 400, wantChain: true,
		},
		{
			name:      "zero progress with work queued is a real failure",
			outOfTime: true, scanned: 0, queued: 400, wantErr: true,
		},
		{
			// Every eligible image failing FAST (a registry/credential error, not a
			// timeout) finishes well inside the budget, so outOfTime is false. An
			// `if !outOfTime { return false, nil }` guard would return success here
			// with zero images scanned and no chained continuation, indistinguishable
			// from "nothing was eligible." The zero-progress-with-work-queued check
			// must fire regardless of outOfTime.
			name:      "zero progress with work queued is a real failure even when not out of time",
			outOfTime: false, scanned: 0, queued: 400, wantErr: true,
		},
		{
			name:      "last hop stops chaining but is not a failure",
			outOfTime: true, scanned: 100, queued: 400, hop: maxSweepHops - 1,
		},
		{
			name:      "chain runs up to but not past the cap",
			outOfTime: true, scanned: 100, queued: 400, hop: maxSweepHops - 2, wantChain: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain, err := truncatedOutcome(tc.outOfTime, tc.scanned, tc.queued, tc.hop)
			require.Equal(t, tc.wantChain, chain)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// A sweep truncated after doing real work must report SUCCESS. This is the
// end-to-end half of TestTruncatedOutcome: an errored sweep is retried and then
// discarded by River, so the estate's coverage would be delivered entirely by
// jobs the queue recorded as failures.
func TestImageVulnWorker_TruncatedSweepWithProgressSucceeds(t *testing.T) {
	// More digests than imageScanConcurrency, so the dispatch loop blocks on the
	// semaphore and re-checks the budget: the first batch is scanned and the rest
	// are left for the next hop.
	images := &fakeImageStore{imgs: imageAssets(
		"sha256:a", "sha256:b", "sha256:c", "sha256:d", "sha256:e", "sha256:f")}
	cursor := &fakeCursor{}
	w := &ImageVulnWorker{
		scanner: &slowImageScanner{delay: 40 * time.Millisecond},
		images:  images, assets: &fakeIngester{},
		findings: &fakeFindingStore{}, cursor: cursor,
	}

	ctx, cancel := context.WithDeadline(context.Background(),
		time.Now().Add(sweepDeadlineMargin+30*time.Millisecond))
	defer cancel()
	require.NoError(t, w.Work(ctx, &river.Job[RefreshImageVulnArgs]{}),
		"a truncated pass that scanned images is not a failure")
	require.NotEmpty(t, cursor.marked, "and the images it did scan are durably recorded")
	require.Less(t, len(cursor.marked), 6, "while the pass really was truncated")
}

// A sweep that runs out of time having scanned NOTHING must still error: the budget
// bought no progress at all, so the retry is worth having.
func TestImageVulnWorker_DeadlineHitErrors(t *testing.T) {
	images := &fakeImageStore{imgs: imageAssets("sha256:a", "sha256:b", "sha256:c")}
	cursor := &fakeCursor{}
	w := &ImageVulnWorker{
		scanner: &fakeImageScanner{byDigest: map[string]imagevuln.Result{}},
		images:  images, assets: &fakeIngester{},
		findings: &fakeFindingStore{}, cursor: cursor,
	}

	// A deadline already inside the margin means no image is even started.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	err := w.Work(ctx, &river.Job[RefreshImageVulnArgs]{})
	require.ErrorContains(t, err, "scanned none of")
	require.Empty(t, cursor.marked)
}

// slowImageScanner takes a measurable amount of time per image, so a sweep can be
// truncated mid-pass with some images already scanned.
type slowImageScanner struct{ delay time.Duration }

func (s *slowImageScanner) ScanImage(ctx context.Context, _, _ string) (imagevuln.Result, error) {
	select {
	case <-time.After(s.delay):
		return imagevuln.Result{}, nil
	case <-ctx.Done():
		return imagevuln.Result{}, ctx.Err()
	}
}

// Progress must not be lost when a sweep is cut short: the cursor write uses a
// context detached from the (possibly cancelled) job context.
func TestImageVulnWorker_CursorWriteSurvivesCancelledContext(t *testing.T) {
	cursor := &fakeCursor{}
	w := &ImageVulnWorker{cursor: cursor}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, w.recordAttempts(ctx, []string{"sha256:a"}, []imageFailure{{digest: "sha256:b", reason: "boom"}}))
	require.Equal(t, []string{"sha256:a"}, cursor.marked)
	require.Len(t, cursor.failed, 1)
}
