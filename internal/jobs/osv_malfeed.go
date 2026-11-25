package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
	"github.com/vulngraph/vulngraph/internal/intel/osv"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// malFeedInterval: how often the mal-feed job asks GitHub what changed in
// ossf/malicious-packages since the last run and diffs any new advisories
// against the current package inventory. Independent of osvRescanAfter (7d) —
// this job never consults osv_scanned_packages, so a package the daily
// per-package sweep marked "clean" hours ago is still caught immediately if a
// MAL-* record ships for it. Hourly, not sub-hourly: the GitHub compare call is
// cheap and flat-cost, but the inventory diff pays the same ScanLivePackages
// cost refresh_osv already pays daily, so tightening the cadence multiplies
// that ClickHouse read proportionally.
const malFeedInterval = 1 * time.Hour

// MalFeedQuerier walks ossf/malicious-packages incrementally.
// *osv.MalFeedClient implements it; tests fake it.
type MalFeedQuerier interface {
	FetchSince(ctx context.Context, lastSHA string) (records []osv.MalRecord, headSHA string, err error)
}

// RefreshMalFeedArgs re-diffs the package inventory against newly-published
// malicious-package advisories, independent of and much faster than the
// daily per-package refresh_osv sweep — see malFeedInterval's doc for why
// both exist.
type RefreshMalFeedArgs struct{}

func (RefreshMalFeedArgs) Kind() string { return "refresh_osv_malfeed" }

// InsertOpts: singleton with 3 attempts (periodicSingletonOpts) — the hourly
// tick is the retry, and the watermark makes every run incremental.
func (RefreshMalFeedArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueEnrich, 3)
}

// Timeout: one GitHub compare call, a handful of small per-record fetches
// (bounded by malFeedMaxFilesPerRun in the osv package), plus one estate pass
// over the in-memory package inventory (paged via ScanLivePackages, the
// same cost refresh_osv already pays daily). No per-package network calls,
// so this stays well under a minute even cold. 5 minutes of headroom.
func (*MalFeedWorker) Timeout(_ *river.Job[RefreshMalFeedArgs]) time.Duration {
	return 5 * time.Minute
}

// MalFeedWorker walks ossf/malicious-packages incrementally (via
// MalFeedQuerier) and cross-references any new advisories against the current
// package inventory, independent of the daily per-package refresh_osv sweep.
// It only ever ADDS findings — resolution stays owned entirely by refresh_osv's
// own reconcile pass (osv.go), so the two jobs' responsibilities never
// collide. A finding this job creates on a package still inside
// osvRescanAfter's skip window can dangle for a while before reconcile
// reconsiders it; that reach is a pre-existing property of reconcileSupplyChain,
// not something specific to this job.
type MalFeedWorker struct {
	river.WorkerDefaults[RefreshMalFeedArgs]
	querier  MalFeedQuerier
	assets   PackageStore
	findings FindingStore
	pool     *pgxpool.Pool // nil only in unit tests; the watermark read/write is skipped
}

func (w *MalFeedWorker) Work(ctx context.Context, _ *river.Job[RefreshMalFeedArgs]) error {
	logger := log.FromContext(ctx)
	// Nil querier: the feed is switched off (INTEL_MALFEED_DISABLED /
	// OFFLINE_MODE) and the periodic is not scheduled; a stray job is a no-op.
	if w.querier == nil {
		logger.Debug().Msg("osv malfeed: feed disabled — skipping refresh")
		return nil
	}

	var q *sqlcgen.Queries
	lastSHA := ""
	if w.pool != nil {
		q = sqlcgen.New(w.pool)
		sha, err := q.GetOSVMalFeedWatermark(ctx)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("Work: load watermark: %w", err)
		}
		lastSHA = sha
	}

	records, headSHA, err := w.querier.FetchSince(ctx, lastSHA)
	if err != nil {
		return fmt.Errorf("Work: fetch malfeed: %w", err)
	}

	// The watermark is persisted at the END of Work, only after every step
	// that consumes `records` has actually succeeded — deliberately NOT here,
	// right after a successful fetch. Advancing it immediately would mean a
	// later failure (ScanLivePackages, findings.Record) still returns an
	// error and gets retried by River, but the retry's own FetchSince call
	// would start from the ALREADY-ADVANCED watermark and never see these
	// records again — a silent loss indistinguishable from "nothing new".
	// Persisting last, after the write that makes the records durable,
	// closes that window: a failure anywhere before then leaves the
	// watermark untouched, so a retry safely (if a little redundantly)
	// re-fetches and re-attempts the exact same range.
	persistWatermark := func() {
		if q == nil || headSHA == "" || headSHA == lastSHA {
			return
		}
		if err := q.SetOSVMalFeedWatermark(ctx, headSHA); err != nil {
			// Non-fatal: worst case the next run re-asks GitHub for a slightly
			// wider (still correct, just redundant) range next time.
			logger.Warn().Err(err).Msg("osv malfeed: failed to persist watermark")
		}
	}

	if len(records) == 0 {
		persistWatermark()
		logger.Info().Str("last_sha", lastSHA).Str("head_sha", headSHA).Msg("osv malfeed: nothing new since last run")
		return nil
	}

	// Index the new records by (ecosystem,name,version) -> the advisories
	// naming it. Same key shape osv.go's own package-inventory walk already
	// uses, so the lookup below is a plain map hit, not a second network call
	// per package.
	byPkg := map[osv.Package][]osv.Vuln{}
	for _, r := range records {
		for _, p := range r.Affected {
			byPkg[p] = append(byPkg[p], r.Vuln)
		}
	}

	now := time.Now()
	var found []finding.Finding
	_, err = w.assets.ScanLivePackages(ctx, func(coords []asset.PackageCoord) error {
		for _, a := range coords {
			p := osv.Package{
				Ecosystem: a.Metadata["ecosystem"],
				Name:      a.Metadata["package"],
				Version:   a.Metadata["version"],
			}
			for _, h := range osv.Hits(byPkg[p]) {
				// Same helpers osv.go uses, so a record this job and the daily
				// sweep both see produces the SAME deterministic finding ID —
				// an idempotent upsert, never a duplicate row.
				found = append(found, supplyChainFinding(p, a.ID, p.Name, h, now))
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("Work: list packages: %w", err) // watermark NOT advanced — safe to retry
	}

	if len(found) == 0 {
		persistWatermark()
		logger.Info().Int("new_records", len(records)).Msg("osv malfeed: new advisories found, none match current inventory")
		return nil
	}

	if err := w.findings.RecordObserved(ctx, found); err != nil {
		return fmt.Errorf("Work: record findings: %w", err) // watermark NOT advanced — safe to retry
	}
	persistWatermark()
	enqueueEnrich(ctx, found)

	logger.Warn().
		Int("new_records", len(records)).
		Int("matched", len(found)).
		Msg("osv malfeed: malicious package(s) found in current inventory")
	return nil
}
