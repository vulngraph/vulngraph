package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/kevwatch"
	"github.com/vulngraph/vulngraph/internal/intel/kev"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// KEVFetcher retrieves the CISA KEV catalog. *kev.Fetcher implements it; tests
// fake it.
type KEVFetcher interface {
	Fetch(ctx context.Context) (*kev.Catalog, error)
}

// FindingStore is the slice of the finding service the OSV/feed producers need.
type FindingStore interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
	// Record re-writes the full findings row without the RecordObserved
	// lifecycle stamps. No production caller remains: a full-row write built
	// from an earlier read can reopen a finding resolved since, or re-resolve
	// one reopened since (TestOnlyScoreWritersCallRecordDirectly).
	Record(ctx context.Context, findings []finding.Finding) error
	// RecordEnrichment writes enrichment outputs to finding_enrichment.
	RecordEnrichment(ctx context.Context, enrichments []finding.Enrichment) error
	// RecordObserved is for OBSERVATION PRODUCERS (a check/feed/scanner just
	// re-detected something) — see finding.Service.RecordObserved's doc.
	RecordObserved(ctx context.Context, findings []finding.Finding) error
	// Resolve stamps findings resolved — used by the OSV reconcile pass
	// to close advisories that a re-scanned package no longer matches.
	Resolve(ctx context.Context, findings []finding.Finding, reason finding.ResolutionReason) error
}

// kevFindingStore is the slice of the finding service the KEV refresh needs.
// It has no findings-row writer on purpose: the KEV flag is an enrichment
// output, and a findings-row write built from the List read would carry that
// read's lifecycle columns (resolved_at, last_observed_at) over whatever a sync
// wrote in between.
type kevFindingStore interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
	ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
	// RecordEnrichment writes the KnownExploited flag to finding_enrichment —
	// the only store of it. Every finding reader LEFT JOINs that table.
	RecordEnrichment(ctx context.Context, enrichments []finding.Enrichment) error
}

// KEVAdditionRecorder diffs each fetched catalog against the last one seen and
// records a `kev.added` event per newly listed CVE. *kevwatch.Service
// implements it.
type KEVAdditionRecorder interface {
	Reconcile(ctx context.Context, entries []kevwatch.Entry, openFindings map[string]int) ([]kevwatch.Addition, error)
}

// RefreshKEVArgs refreshes the KEV catalog and re-escalates any known-exploited
// findings. Runs on queueFeeds, not respond's decide traffic — this
// is a periodic intel refresh, not a per-finding decision.
type RefreshKEVArgs struct{}

func (RefreshKEVArgs) Kind() string { return "refresh_kev" }

// MaxAttempts 2, not River's library default of 25 — same reasoning as
// CorrelateArgs.InsertOpts (correlate.go) and EnrichSweepArgs.InsertOpts
// (enrich.go): RunOnStart (periodic.go) already re-arms this job on every
// worker restart, far more often than kevInterval's 24h, so one retry
// absorbing a transient blip is enough. Grinding through River's default
// backoff for up to 25 attempts while re-walking the same pagination from
// scratch every time is strictly worse than failing fast and paging via
// GraphIntelFeedNeverRefreshed/GraphJobErrorRateHigh.
//
// Unique by state: a periodic tick (or an OSV/image-vuln enqueue) landing while
// a refresh is already queued or running is dropped, not stacked.
func (RefreshKEVArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueFeeds, 2)
}

// KEVWorker fetches the catalog and escalates matching findings.
type KEVWorker struct {
	river.WorkerDefaults[RefreshKEVArgs]
	fetcher  KEVFetcher
	findings kevFindingStore
	// additions records newly listed CVEs; nil skips the diff (no Postgres).
	additions KEVAdditionRecorder
	now       func() time.Time // nil => time.Now
}

// kevListPageLimit paginates the CVE finding scan at List()'s max page
// size. An unpaginated List call silently caps at finding.DefaultLimit, so without pagination the worker would only
// ever see the first page, no matter how many times it reran.
const kevListPageLimit = finding.DefaultLimit

// Timeout overrides River's 1-minute default: listAll paginates through every
// matching open CVE finding, which can be a large population,
// not just the first page. Same rationale as
// EnrichSweepWorker.Timeout/DanglingSweepWorker.Timeout.
func (KEVWorker) Timeout(_ *river.Job[RefreshKEVArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *KEVWorker) Work(ctx context.Context, _ *river.Job[RefreshKEVArgs]) error {
	// Nil fetcher: the feed is switched off (INTEL_KEV_DISABLED / OFFLINE_MODE).
	// The worker stays registered so a refresh the OSV and image-vuln workers
	// still enqueue completes quietly instead of erroring on an unworkable kind.
	if w.fetcher == nil {
		log.FromContext(ctx).Debug().Msg("kev: feed disabled — skipping refresh")
		return nil
	}
	cat, err := w.fetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("Work: fetch kev: %w", err)
	}

	// CVE check ids appear on scanner, supply-chain and VM-inventory findings
	// (and any future CVE producer), so the scan is by CVE across every source
	// rather than a source allowlist that silently misses a new producer. A
	// MAL-* advisory keeps its own ID as CheckID and carries the CVE alias in
	// Metadata["cve"]; Filter.CVEIn matches either, pre-aggregation.
	found, err := w.listAll(ctx, cat.CVEIDs())
	if err != nil {
		return fmt.Errorf("Work: list CVE findings: %w", err)
	}

	escalated, err := w.flag(ctx, cat, found)
	// Re-enrich whatever was flagged (even when a later chunk failed) so the
	// score picks up the KEV page floor.
	enqueueEnrich(ctx, escalated)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	added, err := w.recordAdditions(ctx, cat, found)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	// Feed-side staleness: a successful fetch that returns an old catalog (CISA
	// stopped publishing, or a stale mirror) is invisible to the job-success
	// gauge — warn when dateReleased itself is stale.
	if rel := cat.Released(); !rel.IsZero() {
		if age := time.Since(rel); age > feedStaleAfter {
			log.FromContext(ctx).Warn().Time("date_released", rel).Dur("age", age).
				Msg("kev catalog dateReleased is stale (>48h) — feed may have stopped updating")
		}
	}
	log.FromContext(ctx).Info().
		Int("kev_catalog", cat.Len()).Int("escalated", len(escalated)).Int("kev_added", len(added)).
		Int("scanned", len(found)).Time("date_released", cat.Released()).
		Msg("kev catalog refreshed")
	return nil
}

// kevWriteBatch bounds one ByIDs re-read (an unbatched IN list) and the
// enrichment write that follows it, so the re-read stays immediately ahead of
// its write even when a first run flags thousands of findings.
const kevWriteBatch = 500

// flag writes KnownExploited for every found finding the catalog lists and
// returns the ones it wrote. The flag goes to finding_enrichment only, built
// from a ByIDs re-read taken immediately before the write — never from the
// List read, which may be minutes old by now — so the other nine enrichment
// outputs are carried forward as they stand. EnrichedAt is stamped now: that
// column is the argMax version, so reusing the stored value would tie with the
// row being superseded (and a never-enriched zero would sit past the table TTL).
func (w *KEVWorker) flag(ctx context.Context, cat *kev.Catalog, found []finding.Finding) ([]finding.Finding, error) {
	candidates := kev.Enrich(cat, found)
	var escalated []finding.Finding
	for start := 0; start < len(candidates); start += kevWriteBatch {
		chunk := candidates[start:min(start+kevWriteBatch, len(candidates))]
		ids := make([]string, len(chunk))
		for i, f := range chunk {
			ids[i] = f.ID
		}
		fresh, err := w.findings.ByIDs(ctx, ids)
		if err != nil {
			return escalated, fmt.Errorf("flag: re-read: %w", err)
		}
		flagged := kev.Enrich(cat, fresh)
		if len(flagged) == 0 {
			continue
		}
		now := w.clock()
		enrichments := make([]finding.Enrichment, len(flagged))
		for i, f := range flagged {
			f.EnrichedAt = now
			enrichments[i] = finding.EnrichmentOf(f)
		}
		if err := w.findings.RecordEnrichment(ctx, enrichments); err != nil {
			return escalated, fmt.Errorf("flag: record: %w", err)
		}
		escalated = append(escalated, flagged...)
	}
	return escalated, nil
}

// recordAdditions diffs the catalog for newly listed CVEs. It runs after the
// flag write, so a failure here fails the job (River retries it) without
// undoing any flag; the diff and its events commit together, so the retry
// sees the same diff and an event is never recorded twice.
func (w *KEVWorker) recordAdditions(ctx context.Context, cat *kev.Catalog, found []finding.Finding) ([]kevwatch.Addition, error) {
	if w.additions == nil {
		return nil, nil
	}
	src := cat.Entries()
	entries := make([]kevwatch.Entry, len(src))
	for i, e := range src {
		entries[i] = kevwatch.Entry{CVEID: e.CVEID, DateAdded: e.DateAdded, Name: e.Name}
	}
	added, err := w.additions.Reconcile(ctx, entries, kev.OpenFindingsByCVE(cat, found))
	if err != nil {
		return nil, fmt.Errorf("recordAdditions: %w", err)
	}
	for _, a := range added {
		log.FromContext(ctx).Info().Str("event", kevwatch.EventKind).Str("cve", a.CVEID).
			Time("date_added", a.DateAdded).Int("open_findings", a.OpenFindings).Msg("kev: CVE newly listed")
	}
	return added, nil
}

func (w *KEVWorker) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

// listAll paginates through every open finding that matches one of
// cveIDs (see Filter.CVEIn — pushed into ClickHouse pre-aggregation, not
// scanned in Go), keyset-walking past List()'s per-call DefaultLimit cap
// instead of silently truncating at the first page. This usually returns well
// under one page: the whole reason CVEIn exists is so this does not mean
// "every open finding."
func (w *KEVWorker) listAll(ctx context.Context, cveIDs []string) ([]finding.Finding, error) {
	var (
		out    []finding.Finding
		cursor string
	)
	for {
		batch, err := w.findings.List(ctx, finding.Filter{CVEIn: cveIDs, Limit: kevListPageLimit, Cursor: cursor})
		if err != nil {
			return nil, fmt.Errorf("listAll: %w", err)
		}
		out = append(out, batch...)
		if len(batch) < kevListPageLimit {
			break
		}
		cursor = finding.EncodeCursor(batch[len(batch)-1], false)
	}
	return out, nil
}
