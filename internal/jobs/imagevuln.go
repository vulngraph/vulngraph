package jobs

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// imageScanConcurrency bounds how many images are pulled + scanned at once.
// Each scan pulls and unpacks an image (I/O + disk heavy), so this stays low —
// the sweep is a daily background job, not latency-sensitive.
const imageScanConcurrency = 4

// listImageLimit caps how many container_image assets are LISTED per sweep. It
// is a safety valve on the ClickHouse read, not the scan budget — a large estate
// has far fewer distinct digests than this.
const listImageLimit = 20000

// imagesPerSweep caps how many images one sweep actually scans. A full sweep of
// the estate can exceed the job's own time budget, so the cursor makes a capped
// sweep correct: each run takes the oldest slice, and a truncated slice chains a
// continuation hop instead of erroring, so the estate is covered over a few runs
// rather than the same prefix being rescanned forever. 400 is a slice size, not
// a promise of completion within one run.
const imagesPerSweep = 400

// sweepDeadlineMargin is held back from the job's deadline so the last in-flight
// scans can finish ingesting instead of being cancelled mid-write.
const sweepDeadlineMargin = 3 * time.Minute

// imageRescanAfter is how long a cleanly-scanned digest is left alone before it
// is eligible again — the same shape as osvRescanAfter. It is what makes "this
// sweep has nothing left to do" reachable: without it every digest is eligible on
// every run and a truncated pass never converges.
//
// 20h, not 24h: it must be SHORTER than imageVulnInterval or a digest scanned
// early in yesterday's chain is still "fresh" when today's periodic fires and
// gets skipped for a whole extra day, drifting toward the 48h graph-edge
// freshness window that runs_package must stay inside.
const imageRescanAfter = 20 * time.Hour

// maxSweepHops bounds the continuation chain one periodic tick may start.
//
// The chain terminates on its own once every digest is inside imageRescanAfter,
// which typical throughput reaches in a few hops. The cap is the backstop for the
// case where it does not — a registry slow enough that a hop covers almost
// nothing must not turn the content-scan lane (one worker) into a permanent
// image-pull loop.
const maxSweepHops = 8

// sweepChainDelay paces the continuation, so the chain does not pull from the
// registries back to back, and is short enough that the whole estate is still
// covered within a few hours of the daily tick.
const sweepChainDelay = 5 * time.Minute

// sweepSoftBudget bounds a sweep when the job carries no deadline (tests, manual
// invocation).
const sweepSoftBudget = 45 * time.Minute

// imageProgressEvery is how often the sweep logs progress. Without it a sweep
// that runs for an hour and is killed leaves no record of how far it got.
const imageProgressEvery = 25

// ImageVulnScanner resolves one container image to supply-chain findings plus
// the package assets + runs_package edges linking the image to its dependencies.
// *imagevuln.Scanner satisfies it; tests fake it.
type ImageVulnScanner interface {
	ScanImage(ctx context.Context, digest, ref string) (imagevuln.Result, error)
}

// ContainerImageStore lists the container_image assets to scan.
type ContainerImageStore interface {
	ListByType(ctx context.Context, assetType string, limit int) ([]asset.Asset, error)
}

// AssetIngester persists the package assets + runs_package edges a scan produces.
type AssetIngester interface {
	Ingest(ctx context.Context, assets []asset.Asset, edges []asset.Edge) error
}

// RefreshImageVulnArgs sweeps container_image digests through the image-vuln
// scanner, oldest-scanned first, recording supply-chain findings per
// image CVE and ingesting the runs_package edges that let those findings reach
// must_fix.
//
// Hop is the position in a continuation chain: a sweep truncated by its time
// budget schedules the next hop (bounded by maxSweepHops) so the estate is
// covered by successive jobs rather than by hoping one job is big enough. Zero
// for the periodic's own tick, which is what an existing `{}` args row decodes
// to.
type RefreshImageVulnArgs struct {
	Hop int `json:"hop,omitempty"`
}

func (RefreshImageVulnArgs) Kind() string { return "refresh_image_vuln" }

// InsertOpts puts the sweep on the content-scan lane. It does I/O-heavy per-image
// work (pull + unpack + package inventory) that must not tie up the enrich/respond
// lanes, and its real worker exists only where an ImageSource is wired — the
// worker pod. River fetches by queue and never by kind, so a shared queue with a
// different pod's worker risks that worker locking and instantly erroring jobs it
// cannot actually run; this queue is dedicated to avoid that race.
//
// The lane has one worker: the split is by pod-affinity, not by kind, so a
// future worker-pod-only heavy scan joins this lane rather than giving the
// memory-bound worker a second concurrent heavy job.
//
// MaxAttempts is 2 so a genuine failure — a sweep that scanned NOTHING — gets one
// retry. A sweep merely truncated by its time budget is not a failure: it
// schedules its own continuation (see Work) rather than relying on River's retry,
// since River discards a job after its last attempt and that made a healthy,
// multi-hop sweep indistinguishable from a permanently broken one.
//
// Unique by args, not just kind: a hop chains its continuation while it is still
// running, and kind-only uniqueness would drop that insert as a duplicate of
// itself. Hop 0 (the periodic tick) is still a singleton.
func (RefreshImageVulnArgs) InsertOpts() river.InsertOpts {
	opts := periodicSingletonOpts(queueContentScan, 2)
	opts.UniqueOpts.ByArgs = true
	return opts
}

// imageScanState is what the cursor remembers about one digest.
type imageScanState struct {
	scannedAt   time.Time // zero = never scanned cleanly
	attemptedAt time.Time // zero = never attempted
	failures    int       // consecutive failed attempts; reset by a clean scan
	// lastError is the reason the most recent attempt failed (markImagesFailed's
	// own text), empty if failures == 0. Not read by selectTargets/backoff — it
	// exists purely so a persistently-failing digest can be diagnosed (see
	// logStalestDigest) without a database query: the answer is already sitting
	// in this row from whichever attempt last set it.
	lastError string
}

// lastTouched is the ordering key: the most recent time the sweep did anything
// with this digest. Using it rather than scannedAt is what stops a permanently
// unscannable image from sorting ahead of every healthy one forever.
func (s imageScanState) lastTouched() time.Time {
	if s.attemptedAt.After(s.scannedAt) {
		return s.attemptedAt
	}
	return s.scannedAt
}

// imageFailure is one digest that failed to scan, with the reason recorded for
// operators — "the sweep skipped it" is not diagnosable on its own.
type imageFailure struct {
	digest string
	ref    string
	reason string
	// interrupted means the sweep's own deadline cancelled the scan: the
	// attempt is recorded, but it says nothing about the image.
	interrupted bool
	// noManifests means the image was read in full and holds nothing the
	// scanner can inventory (imagevuln.ErrNoManifests).
	noManifests bool
}

// imageRetryBackoffCap bounds the exponential retry backoff. A digest that has
// failed seven times in a row is retried weekly: often enough that a fixed
// registry or a re-pushed tag is picked up, rarely enough that it stops
// competing with healthy images for the per-sweep budget.
const imageRetryBackoffCap = 7 * 24 * time.Hour

// imageRetryBackoff is 2^failures hours, capped. Zero for a digest with no
// recorded failures, so healthy images are never delayed.
func imageRetryBackoff(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	backoff := time.Hour << min(failures, 10)
	return min(backoff, imageRetryBackoffCap)
}

// ImageScanCursor persists what the sweep has tried and what succeeded, so a
// sweep resumes where the last one stopped instead of restarting at the same
// last_seen-ordered prefix — and so a digest that cannot be scanned at all backs
// off instead of consuming the whole budget on every run.
type ImageScanCursor interface {
	States(ctx context.Context) (map[string]imageScanState, error)
	MarkScanned(ctx context.Context, digests []string) error
	MarkFailed(ctx context.Context, failures []imageFailure) error
	// PruneOrphaned deletes cursor rows past cutoff whose digest is not in
	// liveDigests, and returns how many rows were removed.
	PruneOrphaned(ctx context.Context, liveDigests []string, cutoff time.Time) (int64, error)
}

// pgImageScanCursor is the Postgres-backed cursor (image_scan_state), mirroring
// osv_scanned_packages.
type pgImageScanCursor struct{ pool *pgxpool.Pool }

func newImageScanCursor(pool *pgxpool.Pool) ImageScanCursor {
	if pool == nil {
		return nil
	}
	return pgImageScanCursor{pool: pool}
}

// selectImageScanState reads the whole cursor — one row per digest ever tried,
// which is bounded by the container_image inventory (typically hundreds).
const selectImageScanState = `
SELECT digest, scanned_at, attempted_at, failures, last_error
FROM image_scan_state`

// markImagesScanned records a clean scan and clears the failure state, so a
// digest that recovers stops backing off immediately.
const markImagesScanned = `
INSERT INTO image_scan_state (digest, scanned_at, attempted_at, failures, last_error)
SELECT unnest($1::text[]), now(), now(), 0, ''
ON CONFLICT (digest) DO UPDATE
    SET scanned_at = now(), attempted_at = now(), failures = 0, last_error = ''`

// markImagesFailed records the attempt WITHOUT touching scanned_at: the digest
// stops sorting ahead of healthy images, but it is still not counted as scanned.
const markImagesFailed = `
INSERT INTO image_scan_state (digest, attempted_at, failures, last_error)
SELECT d, now(), 1, e FROM unnest($1::text[], $2::text[]) AS t(d, e)
ON CONFLICT (digest) DO UPDATE
    SET attempted_at = now(),
        failures     = image_scan_state.failures + 1,
        last_error   = excluded.last_error`

// pruneOrphanedImageScans deletes image_scan_state rows whose digest is no
// longer present in the current container_image inventory (a rebuild that
// retagged the image to a new digest, or the asset decommissioned outright),
// scoped to rows already past the rescan cutoff. Mirrors OSV's
// DeleteOrphanedScannedPackages: without this, such a row is never re-attempted
// and never ages out, permanently depressing the oldest-scanned coverage gauge
// even though live coverage is healthy. `scanned_at IS NOT NULL` leaves a digest
// that has NEVER scanned cleanly untouched — that is
// graph_image_scan_never_scanned's own accepted floor, not this metric's problem.
const pruneOrphanedImageScans = `
DELETE FROM image_scan_state
WHERE scanned_at IS NOT NULL
  AND scanned_at < $1
  AND NOT (digest = ANY($2::text[]))`

// ImageScanCoverage is the image-vuln sweep's actual coverage of the estate, read
// from its own cursor. graph_job_runs_total{worker="refresh_image_vuln"} only
// answers "did the job run", which is a different question in both directions —
// a truncated-but-productive sweep can look failed, and a sweep that scans
// nothing can look fine. Only the cursor knows how much is actually covered.
type ImageScanCoverage struct {
	TrackedDigests int64     // digests the sweep has ever attempted
	NeverScanned   int64     // attempted but never once scanned cleanly (pull denied, no manifests)
	CoveredRecent  int64     // scanned inside the freshness window — 0 means the sweep is dark
	OldestScanned  time.Time // worst-covered digest; zero when nothing has ever been scanned
}

// selectImageScanCoverage aggregates the cursor table (one row per digest). $1 is the
// freshness cutoff, passed in from Go so the window cannot drift from
// imageRescanAfter.
const selectImageScanCoverage = `
SELECT count(*)                                        AS tracked,
       count(*) FILTER (WHERE scanned_at IS NULL)      AS never_scanned,
       count(*) FILTER (WHERE scanned_at >= $1)        AS covered_recent,
       min(scanned_at)                                 AS oldest_scanned
FROM image_scan_state`

// ReadImageScanCoverage reads the image-vuln coverage gauges' Postgres source.
//
// Mirrors OSVScanStaleness' posture: log and return the error rather than
// panicking a scrape, letting the caller (cmd/graph/worker_metrics.go) emit
// nothing this scrape. The freshness cutoff is imageRescanAfter plus one sweep
// interval of grace, so a digest is only "not covered recently" once the sweep
// has actually had a tick in which to get to it.
func ReadImageScanCoverage(ctx context.Context, pool *pgxpool.Pool) (ImageScanCoverage, error) {
	queryCtx, cancel := context.WithTimeout(ctx, cursorTimeout)
	defer cancel()

	cutoff := time.Now().Add(-(imageRescanAfter + imageVulnInterval))
	var (
		out    ImageScanCoverage
		oldest *time.Time
	)
	err := pool.QueryRow(queryCtx, selectImageScanCoverage, cutoff).
		Scan(&out.TrackedDigests, &out.NeverScanned, &out.CoveredRecent, &oldest)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).
			Msg("ImageScanCoverage: query failed — image-scan coverage metrics skipped this scrape")
		return ImageScanCoverage{}, fmt.Errorf("ImageScanCoverage: %w", err)
	}
	if oldest != nil {
		out.OldestScanned = *oldest
	}
	return out, nil
}

// cursorTimeout bounds each cursor statement. The sweep may be at its own
// deadline when it writes, and a hung cursor write must not become the reason
// the whole pass is lost.
const cursorTimeout = 30 * time.Second

func (c pgImageScanCursor) States(ctx context.Context) (map[string]imageScanState, error) {
	queryCtx, cancel := context.WithTimeout(ctx, cursorTimeout)
	defer cancel()

	rows, err := c.pool.Query(queryCtx, selectImageScanState)
	if err != nil {
		return nil, fmt.Errorf("States: %w", err)
	}
	defer rows.Close()

	out := map[string]imageScanState{}
	for rows.Next() {
		var (
			digest      string
			scannedAt   *time.Time
			attemptedAt *time.Time
			failures    int32
			lastError   string
		)
		if err := rows.Scan(&digest, &scannedAt, &attemptedAt, &failures, &lastError); err != nil {
			return nil, fmt.Errorf("States: scan: %w", err)
		}
		state := imageScanState{failures: int(failures), lastError: lastError}
		if scannedAt != nil {
			state.scannedAt = *scannedAt
		}
		if attemptedAt != nil {
			state.attemptedAt = *attemptedAt
		}
		out[digest] = state
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("States: rows: %w", err)
	}
	return out, nil
}

func (c pgImageScanCursor) MarkScanned(ctx context.Context, digests []string) error {
	execCtx, cancel := context.WithTimeout(ctx, cursorTimeout)
	defer cancel()
	if _, err := c.pool.Exec(execCtx, markImagesScanned, digests); err != nil {
		return fmt.Errorf("MarkScanned: %w", err)
	}
	return nil
}

func (c pgImageScanCursor) MarkFailed(ctx context.Context, failures []imageFailure) error {
	digests := make([]string, 0, len(failures))
	reasons := make([]string, 0, len(failures))
	for _, f := range failures {
		digests = append(digests, f.digest)
		reasons = append(reasons, f.reason)
	}
	execCtx, cancel := context.WithTimeout(ctx, cursorTimeout)
	defer cancel()
	if _, err := c.pool.Exec(execCtx, markImagesFailed, digests, reasons); err != nil {
		return fmt.Errorf("MarkFailed: %w", err)
	}
	return nil
}

func (c pgImageScanCursor) PruneOrphaned(ctx context.Context, liveDigests []string, cutoff time.Time) (int64, error) {
	execCtx, cancel := context.WithTimeout(ctx, cursorTimeout)
	defer cancel()
	tag, err := c.pool.Exec(execCtx, pruneOrphanedImageScans, cutoff, liveDigests)
	if err != nil {
		return 0, fmt.Errorf("PruneOrphaned: %w", err)
	}
	return tag.RowsAffected(), nil
}

// coverageFindingStore is the finding store plus the by-id read that finds a
// scanned resource's open coverage finding.
type coverageFindingStore interface {
	FindingStore
	ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

// ImageVulnWorker scans container_image assets and records their findings.
type ImageVulnWorker struct {
	river.WorkerDefaults[RefreshImageVulnArgs]
	scanner  ImageVulnScanner
	images   ContainerImageStore
	assets   AssetIngester
	findings coverageFindingStore
	// cursor orders the sweep oldest-scanned-first. Nil degrades to an
	// uncursored sweep of the first imagesPerSweep images.
	cursor ImageScanCursor
	// edges keeps an unscanned running image's last-known package edges fresh
	// (coverUnscanned). Nil leaves them to age out.
	edges imageEdgeStore
	// bases stores each scanned image's base identity for the base-image job
	// (baseimage.go). Nil records nothing, so every image reads as unscanned
	// there.
	bases ImageBaseRecorder
}

// ImageBaseRecorder persists scanned images' base identities.
type ImageBaseRecorder interface {
	RecordImageBases(ctx context.Context, bases []asset.ImageBase) error
}

// Timeout overrides River's 1-minute default: pulling and scanning hundreds of
// images takes far longer. The sweep stops itself at sweepDeadlineMargin before
// this, so the deadline is a backstop rather than the normal exit.
func (ImageVulnWorker) Timeout(_ *river.Job[RefreshImageVulnArgs]) time.Duration {
	return 60 * time.Minute
}

// scanTarget is one image the sweep may scan, with the cursor state that ordered it.
type scanTarget struct {
	digest string
	ref    string
	state  imageScanState
}

// sweepPlan is what one hop will scan and what it will not.
type sweepPlan struct {
	targets   []scanTarget // to scan, oldest-touched first, at most imagesPerSweep
	total     int          // digests considered
	backedOff []scanTarget // eligible but inside their failure backoff
	overCap   []scanTarget // eligible but past this hop's imagesPerSweep
}

func (w *ImageVulnWorker) Work(ctx context.Context, job *river.Job[RefreshImageVulnArgs]) error {
	logger := log.FromContext(ctx)
	images, err := w.images.ListByType(ctx, "container_image", listImageLimit)
	if err != nil {
		return fmt.Errorf("Work: list container_image assets: %w", err)
	}
	if len(images) == 0 {
		logger.Info().Msg("imagevuln sweep: no container_image assets")
		return nil
	}

	w.pruneOrphaned(ctx, images)
	w.logStalestDigest(ctx, images)

	plan, err := w.selectTargets(ctx, images)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	targets, total := plan.targets, plan.total
	if len(targets) == 0 {
		// Backed-off digests still run; their last-known packages stay live.
		w.coverUnscanned(ctx, nil, plan.backedOff)
		logger.Info().Int("images", total).Msg("imagevuln sweep: no scannable digests")
		return nil
	}

	deadline := time.Now().Add(sweepSoftBudget)
	if d, ok := ctx.Deadline(); ok {
		deadline = d.Add(-sweepDeadlineMargin)
	}

	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, imageScanConcurrency)
		mu        sync.Mutex
		totalFind int
		scanned   []string
		failed    []imageFailure
		partial   []scanTarget // scanned, but the walk was incomplete
		attempted int
		outOfTime bool
		// dispatched counts targets handed to a scan; the rest were never
		// reached and are unscanned, not failed.
		dispatched int
	)
	for _, target := range targets {
		if time.Now().After(deadline) || ctx.Err() != nil {
			outOfTime = true
			break
		}
		dispatched++
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Any("panic", rec).Str("digest", target.digest).
						Msg("imagevuln scan panicked; image skipped")
					mu.Lock()
					defer mu.Unlock()
					failed = append(failed, imageFailure{
						digest: target.digest, ref: target.ref, reason: fmt.Sprintf("scan panicked: %v", rec),
					})
				}
			}()

			findings, partialWalk, err := w.scanImage(ctx, target)
			mu.Lock()
			defer mu.Unlock()
			attempted++
			if attempted%imageProgressEvery == 0 {
				logger.Info().
					Int("attempted", attempted).Int("queued", len(targets)).
					Int("findings", totalFind).
					Msg("imagevuln sweep progress")
			}
			if err != nil {
				logger.Warn().Err(err).Str("digest", target.digest).
					Int("prior_failures", target.state.failures).
					Msg("imagevuln scan failed; image skipped")
				// Record the ATTEMPT, not a scan. scanned_at stays untouched so the
				// image is never counted as covered, but attempted_at moves — which
				// is what stops a permanently-broken digest from sorting ahead of
				// every healthy image on every run and eating the whole budget.
				failed = append(failed, imageFailure{
					digest: target.digest, ref: target.ref, reason: err.Error(), interrupted: ctx.Err() != nil,
					noManifests: errors.Is(err, imagevuln.ErrNoManifests),
				})
				return
			}
			scanned = append(scanned, target.digest)
			totalFind += findings
			if partialWalk {
				partial = append(partial, target)
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		// The deadline landed on the in-flight scans rather than on the dispatch
		// loop. Those images did not complete, so the pass is truncated either way.
		outOfTime = true
	}

	if err := w.recordAttempts(ctx, scanned, failed); err != nil {
		logger.Warn().Err(err).Msg("imagevuln: could not persist scan cursor")
	}
	if len(scanned) > 0 {
		// New identities and package edges: regroup the base-image findings.
		enqueueBaseImages(ctx)
	}

	// Kick a KEV refresh so image CVEs get known_exploited set before the daily
	// periodic — the same immediacy the OSV feed gives its supply-chain findings.
	if totalFind > 0 {
		if client, cerr := river.ClientFromContextSafely[pgx.Tx](ctx); cerr == nil {
			if _, err := client.Insert(ctx, RefreshKEVArgs{}, nil); err != nil {
				logger.Warn().Err(err).Msg("imagevuln: could not enqueue kev refresh")
			}
		}
	}

	logger.Info().
		Int("images", total).
		Int("queued", len(targets)).
		Int("scanned", len(scanned)).
		Int("failed", len(failed)).
		Int("findings", totalFind).
		Int("hop", job.Args.Hop).
		Bool("out_of_time", outOfTime).
		Msg("imagevuln sweep complete")

	chain, err := truncatedOutcome(outOfTime, len(scanned), len(targets), job.Args.Hop)
	chained := chain && w.chainNextHop(ctx, job.Args.Hop+1)

	// Failed and backed-off images are covered on every hop. Those merely not
	// reached are covered only where the chain ends: a continuation hop will
	// reach most of them, and re-stamping the whole remaining estate on every
	// hop would rewrite most of its package edges up to maxSweepHops times.
	unscanned := append(partial, plan.backedOff...)
	if !chained {
		unscanned = append(append(unscanned, plan.overCap...), targets[dispatched:]...)
	}
	w.coverUnscanned(ctx, failed, unscanned)
	return err
}

// truncatedOutcome decides what a finished sweep MEANS: whether to chain a
// continuation, and whether the job failed.
//
// A truncated pass is not a failure: recordAttempts has already committed every
// digest this sweep scanned (on a context detached from the job's), so partial
// progress is real progress and the remainder is simply the next hop's.
//
// Zero progress with work queued is the case that IS genuinely wrong, and it is
// the only one that errors — the budget bought nothing. This check is
// deliberately ungated by outOfTime: every eligible image failing fast (a
// registry/credential error, not a timeout) must not look identical to "nothing
// was eligible". queued==0 still returns success — "nothing to do" is a real
// success case, only "had work, did none of it" errors.
//
// Pure and separate from Work so both branches are table-testable without a
// River client.
func truncatedOutcome(outOfTime bool, scanned, queued, hop int) (chain bool, err error) {
	if scanned == 0 && queued > 0 {
		return false, fmt.Errorf("Work: sweep scanned none of %d queued images", queued)
	}
	if !outOfTime {
		return false, nil
	}
	if hop+1 >= maxSweepHops {
		// Not an error: the work landed. The chain stops here and the next periodic
		// tick starts a fresh one; the coverage gauges say whether that is enough.
		return false, nil
	}
	return true, nil
}

// chainNextHop queues the continuation. Best-effort by design: the periodic tick
// is the backstop, and a failed insert must not discard a sweep that did land its
// work. The context is detached because this runs at the sweep's own deadline —
// the same reason recordAttempts detaches.
// It reports whether the continuation was queued.
func (w *ImageVulnWorker) chainNextHop(ctx context.Context, hop int) bool {
	logger := log.FromContext(ctx)
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return false // no client (unit test) — nothing to chain
	}
	insertCtx := context.WithoutCancel(ctx)
	if _, err := client.Insert(insertCtx, RefreshImageVulnArgs{Hop: hop},
		&river.InsertOpts{ScheduledAt: time.Now().Add(sweepChainDelay)}); err != nil {
		logger.Warn().Err(err).Int("hop", hop).
			Msg("imagevuln: could not chain the next sweep hop; the periodic tick is the backstop")
		return false
	}
	logger.Info().Int("hop", hop).Msg("imagevuln: sweep truncated, next hop scheduled")
	return true
}

// scanImage scans one image and persists everything it produced, returning the
// finding count and whether the walk was incomplete.
func (w *ImageVulnWorker) scanImage(ctx context.Context, target scanTarget) (int, bool, error) {
	res, err := w.scanner.ScanImage(ctx, target.digest, target.ref)
	if err != nil {
		return 0, false, fmt.Errorf("scanImage: %w", err)
	}
	// Ingest the package nodes + runs_package edges first so the graph linkage
	// exists before the findings that depend on it for must-fix.
	if len(res.Assets) > 0 || len(res.Edges) > 0 {
		if err := w.assets.Ingest(ctx, res.Assets, res.Edges); err != nil {
			return 0, false, fmt.Errorf("scanImage: ingest: %w", err)
		}
	}
	if len(res.Findings) > 0 {
		if err := w.findings.RecordObserved(ctx, res.Findings); err != nil {
			return 0, false, fmt.Errorf("scanImage: record: %w", err)
		}
		enqueueEnrich(ctx, res.Findings)
	}
	// Recorded last and as part of the scan: a digest the cursor marks scanned
	// always has an identity row, so a missing row means "not scanned yet",
	// never "scanned and lost".
	if w.bases != nil {
		if err := w.bases.RecordImageBases(ctx, []asset.ImageBase{imageBaseOf(target.digest, res.Base)}); err != nil {
			return 0, false, fmt.Errorf("scanImage: record base: %w", err)
		}
	}
	if err := w.resolveCoverage(ctx, target.digest, res); err != nil {
		return 0, false, fmt.Errorf("scanImage: %w", err)
	}
	return len(res.Findings), res.OSCVEGap == asset.CVEGapScanIncomplete, nil
}

// imageBaseOf is the stored form of a scan's base identity.
func imageBaseOf(digest string, b imagevuln.BaseIdentity) asset.ImageBase {
	return asset.ImageBase{
		ImageID:         collect.ImageAssetID(digest),
		BaseImage:       b.Image,
		BaseImageDigest: b.Digest,
		BaseImageSource: b.Source,
		BaseOS:          b.OS,
		ScannedAt:       time.Now(),
	}
}

// selectTargets orders the scannable digests least-recently-touched first, drops
// the ones already scanned within imageRescanAfter and the ones still inside
// their failure backoff, and returns at most imagesPerSweep of them, how many
// images were considered, and the eligible-but-unscanned rest (sweepPlan).
//
// Ordering by last ATTEMPT rather than last successful scan is what makes
// progress monotonic: a digest that can never be scanned still gets its
// attempted_at bumped, so it does not sort ahead of every healthy image forever.
// The backoff then stops the known-bad ones from competing for the budget.
func (w *ImageVulnWorker) selectTargets(ctx context.Context, images []asset.Asset) (sweepPlan, error) {
	states, err := w.scanStates(ctx)
	if err != nil {
		return sweepPlan{}, err
	}

	now := time.Now()
	seen := make(map[string]bool, len(images))
	targets := make([]scanTarget, 0, len(images))
	var backedOff []scanTarget
	fresh := 0
	for _, img := range images {
		digest := img.Metadata["image_id"]
		if digest == "" || seen[digest] {
			continue // no resolved digest — nothing stable to scan or key on
		}
		seen[digest] = true
		state := states[digest]
		// Already covered inside the rescan window. This is what lets a sweep
		// finish: without it every digest is eligible on every run, so the budget
		// always truncates and no pass is ever complete.
		if !state.scannedAt.IsZero() && now.Sub(state.scannedAt) < imageRescanAfter {
			fresh++
			continue
		}
		if backoff := imageRetryBackoff(state.failures); backoff > 0 &&
			now.Sub(state.attemptedAt) < backoff {
			backedOff = append(backedOff, scanTarget{digest: digest, ref: img.Metadata["image_ref"], state: state})
			continue
		}
		targets = append(targets, scanTarget{
			digest: digest, ref: img.Metadata["image_ref"], state: state,
		})
	}

	// Never touched first (zero time sorts first), then least-recently touched.
	// Digest breaks ties so the order is stable across runs.
	sort.Slice(targets, func(i, j int) bool {
		a, b := targets[i].state.lastTouched(), targets[j].state.lastTouched()
		if !a.Equal(b) {
			return a.Before(b)
		}
		return targets[i].digest < targets[j].digest
	})

	plan := sweepPlan{targets: targets, total: len(targets) + len(backedOff) + fresh, backedOff: backedOff}
	if len(targets) > imagesPerSweep {
		plan.targets, plan.overCap = targets[:imagesPerSweep], targets[imagesPerSweep:]
	}
	if len(backedOff) > 0 || fresh > 0 {
		log.FromContext(ctx).Info().
			Int("backed_off", len(backedOff)).Int("fresh", fresh).Int("eligible", len(plan.targets)).
			Msg("imagevuln: digests skipped this sweep (inside the rescan window or backing off)")
	}
	return plan, nil
}

// scanStates loads the per-image cursor. No cursor wired means no ordering.
func (w *ImageVulnWorker) scanStates(ctx context.Context) (map[string]imageScanState, error) {
	if w.cursor == nil {
		return map[string]imageScanState{}, nil
	}
	states, err := w.cursor.States(ctx)
	if err != nil {
		return nil, fmt.Errorf("scanStates: %w", err)
	}
	return states, nil
}

// recordAttempts advances the cursor for everything this sweep touched: clean
// scans reset the failure state, failures record the attempt so the digest stops
// starving the next sweep.
func (w *ImageVulnWorker) recordAttempts(ctx context.Context, scanned []string, failed []imageFailure) error {
	if w.cursor == nil {
		return nil
	}
	// The sweep may have exhausted its own deadline; the cursor write must still
	// land, or the next run repeats the same images.
	writeCtx := context.WithoutCancel(ctx)
	if len(scanned) > 0 {
		if err := w.cursor.MarkScanned(writeCtx, scanned); err != nil {
			return fmt.Errorf("recordAttempts: %w", err)
		}
	}
	if len(failed) > 0 {
		if err := w.cursor.MarkFailed(writeCtx, failed); err != nil {
			return fmt.Errorf("recordAttempts: %w", err)
		}
	}
	return nil
}
