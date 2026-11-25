package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// enrichSweepLimit is the page size for each ClickHouse query in the sweep.
const enrichSweepLimit = finding.DefaultLimit

// enrichSweepMax caps the total findings enqueued per sweep tick, sized to drain
// the never-enriched backfill (Phase 1) over about a day and then no-op back to
// drift correction (Phase 2). The enrichQueueMax backpressure guard skips the
// tick when the queue is already deep, so the burst self-throttles.
const enrichSweepMax = 2500

// defaultEnrichMaxAge is the freshness backstop: even an unchanged finding is
// re-enriched once its last enrichment is older than this, so graph-context
// drift the input fingerprint can't see (a new blast-radius asset, a new peer
// finding) is still picked up — just not every cycle. Overridable via
// ENRICH_MAX_AGE. Long enough that the fingerprint gate does most of the work —
// genuinely changed findings are still enriched immediately at ingest time; the
// backstop only catches graph-context drift.
const defaultEnrichMaxAge = 24 * time.Hour

// EnrichArgs scores one finding through the enrichment pipeline. Carries only
// FindingID (not the full Finding struct) so:
//  1. River job rows are ~50 bytes instead of ~1500 bytes (10k jobs ≈ 15MB → 500KB)
//  2. ByArgs uniqueness hashes a stable ID not volatile Score/ScoreBand/EnrichedAt,
//     so re-enqueueing the same finding deduplicates correctly.
//
// The worker re-fetches the full finding from ClickHouse at the start of Work.
type EnrichArgs struct {
	FindingID string `json:"finding_id"`
}

func (EnrichArgs) Kind() string { return "enrich" }

// InsertOpts keeps enrich jobs on their own queue (so they never starve the
// LLM-bound respond queue) and unique per finding while queued/running.
func (EnrichArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:      queueEnrich,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// enricher is the slice of the enrich service the worker needs (a narrow
// consumer interface so Work is unit-testable; *enrich.Service satisfies it).
type enricher interface {
	Enrich(ctx context.Context, f finding.Finding) (enrich.Score, error)
}

// FindingFetcher re-fetches a finding by ID at the start of each enrich job.
// finding.Service satisfies it.
type FindingFetcher interface {
	Get(ctx context.Context, id string) (finding.Finding, error)
}

// SuppressionChecker reports whether a finding has been silenced. suppress.Service
// implements it; nil disables the check (e.g. in tests).
type SuppressionChecker interface {
	IsSuppressed(ctx context.Context, findingID string) (bool, error)
}

// EnrichCache gates re-enrichment (the last input fingerprint + enrich time per
// finding) and dedupes alerts (the urgency each finding last alerted at).
// enrichcache.Service implements it. Optional — a nil cache disables the gate
// (every job enriches) and the dedupe (every alertable enrich alerts).
type EnrichCache interface {
	Get(ctx context.Context, findingID string) (enrichcache.Entry, error)
	Put(ctx context.Context, e enrichcache.Entry) error
	InvalidateFingerprints(ctx context.Context, findingIDs []string) error
	AlertState(ctx context.Context, findingID string) (enrichcache.AlertState, error)
	RecordAlert(ctx context.Context, a enrichcache.AlertState) error
}

// GraphContextProvider supplies the two graph-derived inputs that drive the
// enrichment fingerprint. Point queries only — must be cheap enough to
// run on every enrich call, including cache-hit paths.
// *asset.Service + *finding.Service implement the two halves; a concrete
// graphCtxSvc in cmd/graph combines them.
type GraphContextProvider interface {
	// IsExposedEdge reports whether resourceID has an exposed_to_internet edge.
	IsExposedEdge(ctx context.Context, resourceID string) (bool, error)
	// PrivescBucket returns the bucketed count of ciem_privesc findings on
	// resourceID ("0","1","2-3","4+").
	PrivescBucket(ctx context.Context, resourceID string) (string, error)
}

// EnrichWorker scores a finding and, if the enriched score reaches the pipeline
// threshold and the finding isn't suppressed, enqueues the decision. This is the
// trigger flip: the decision pipeline is gated on the contextual score, never
// raw severity.
type EnrichWorker struct {
	river.WorkerDefaults[EnrichArgs]
	enrich   enricher
	findings FindingFetcher // re-fetches the finding at job start (args carry ID only)
	suppress SuppressionChecker
	cache    EnrichCache          // nil => no change-gate (always enrich)
	graph    GraphContextProvider // nil => graph context omitted from fingerprint
	maxAge   time.Duration        // freshness backstop; <=0 => defaultEnrichMaxAge
	now      func() time.Time
	notify   NoticeDeliverer // nil => no outbound alerting
	carriers AlertCarrier    // nil => every alertable finding alerts for itself
}

// clock returns the worker's time source, defaulting to time.Now so a
// zero-value worker (tests that don't set now) still works.
func (w *EnrichWorker) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

// unmeasuredRetryAfter is how soon a finding enriched with an unmeasured
// source (enrich.Score.Unmeasured — e.g. EPSS before its catalog first loads,
// a failed corroboration query) is re-enriched, instead of riding the
// freshness backstop: its inputs fingerprint is unchanged, so without this the
// missing contribution would persist for a whole backstop period.
const unmeasuredRetryAfter = 30 * time.Minute

// cacheStamp is the EnrichedAt recorded in the change-gate cache. A score with
// an unmeasured source is stamped as if enriched (backstop - retry) ago, so the
// gate lets the next visit through after unmeasuredRetryAfter rather than after
// the full backstop.
func (w *EnrichWorker) cacheStamp(score enrich.Score) time.Time {
	now := w.clock()
	if len(score.Unmeasured) == 0 || w.backstop() <= unmeasuredRetryAfter {
		return now
	}
	return now.Add(unmeasuredRetryAfter - w.backstop())
}

func (w *EnrichWorker) backstop() time.Duration {
	if w.maxAge > 0 {
		return w.maxAge
	}
	return defaultEnrichMaxAge
}

// Timeout overrides River's 1-minute default. Enrich runs several graph/CH
// reads (safety, exposure, blast radius) per finding; under a deep enrich
// backlog a CH pool wait can exceed a minute, so the default killed
// enrichments that would otherwise complete.
func (EnrichWorker) Timeout(_ *river.Job[EnrichArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *EnrichWorker) Work(ctx context.Context, job *river.Job[EnrichArgs]) error {
	start := time.Now()
	// Re-fetch the full finding from CH. Args carry only FindingID (smaller payload,
	// stable uniqueness hash). ErrNotFound means the finding was deleted — skip.
	f, err := w.findings.Get(ctx, job.Args.FindingID)
	if err != nil {
		if errors.Is(err, finding.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("Work: get finding %s: %w", job.Args.FindingID, err)
	}
	// A resolved finding is history: readers hide it, nothing decides on it, and
	// enriching it is what re-sent "New critical finding" for already-fixed CVEs
	// every time a correlate sweep re-enqueued its resource.
	if f.Resolved() {
		log.FromContext(ctx).Debug().Str("finding_id", f.ID).Msg("enrich skipped — finding resolved")
		return nil
	}

	// The cache entry is read before the fingerprint: a graph read that fails
	// below carries the entry's last measured value forward (CarryForward).
	// Fail-open: a cache read error leaves nothing to carry and no gate.
	var (
		cached   enrichcache.Entry
		cacheHit bool
	)
	if w.cache != nil {
		if e, err := w.cache.Get(ctx, f.ID); err == nil {
			cached, cacheHit = e, true
		}
	}
	in, graphCtx := w.fingerprintFor(ctx, f, cached.Graph)
	fp := enrichcache.Fingerprint(in)
	ctxFP := enrichcache.ContextFingerprint(in)

	// Change-gate: skip the whole enrich — and so the downstream decide,
	// which is enqueued only at the end of this method — when the finding's inputs
	// are unchanged and it was enriched within the freshness backstop. This is the
	// dominant ClickHouse saving: enrichment walks the blast radius per finding.
	//
	// Exception: ALWAYS enrich if the finding has score=0. Score=0 is the sentinel
	// for "never enriched" — a ClickHouse ReplacingMergeTree re-ingest can produce
	// a fresh score=0 row even though the cache says "fingerprint unchanged, done
	// recently". Without this guard, a large share of findings silently stay at
	// score=0 (invisible in triage) because the change-gate skips them.
	if f.Score > 0 && cacheHit && cached.InputFP == fp && w.clock().Sub(cached.EnrichedAt) < w.backstop() {
		log.FromContext(ctx).Debug().Str("finding_id", f.ID).
			Msg("enrich skipped — unchanged and fresh")
		return nil
	}

	score, err := w.enrich.Enrich(ctx, f)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	log.FromContext(ctx).Info().
		Str("finding_id", f.ID).
		Uint8("score", score.Value).Str("band", string(score.Band)).
		Dur("elapsed", time.Since(start)).
		Msg("finding enriched")

	// A resolve can land while this enrich runs. For an alertable score, re-read
	// before writing anything: a just-resolved finding must neither alert as
	// "New" nor get a cache entry and alert state back after the resolve
	// observer cleared them (which would also delay its regression alert).
	// Only alertable scores pay for the read — elsewhere the stale entry costs
	// at most one deferred re-enrich.
	if alertable(score) {
		if fresh, err := w.findings.Get(ctx, f.ID); err == nil && fresh.Resolved() {
			log.FromContext(ctx).Info().Str("finding_id", f.ID).
				Msg("enrich: finding resolved during enrichment — nothing recorded, no alert")
			return nil
		}
	}

	// A cache miss whose CONTEXT fingerprint matches the stored one is
	// attributable entirely to a LogicVersion bump, not to any real change in the
	// finding — the corpus-wide re-enrich a bump forces exists to let the new
	// scoring logic take effect, not to re-litigate every already-correct
	// decision. If the recomputed ScoreBand also matches what was stored, nothing
	// about this finding's disposition actually moved, so the decide/alert step
	// below is skipped. A genuine input change (context fingerprint differs) or a
	// brand-new finding (no cache entry) always falls through and decides/alerts
	// as before.
	//
	// Three deliberate edges:
	//   - The freshness backstop still wins: an entry older than the backstop was
	//     due a re-decide regardless of the bump, so a stale entry decides.
	//   - Band-granularity is the contract: a bump that moves the score WITHIN a
	//     band does not re-decide. Bands are what the decide pipeline consumes;
	//     within-band movement changes no disposition.
	contextUnchanged := cached.ContextFP == ctxFP
	//   - An explicitly invalidated entry (InputFP "", see
	//     invalidateExposedFindings) is never version-only: it was invalidated
	//     because graph context the fingerprint cannot see moved.
	versionOnlyNoOp := cacheHit && cached.InputFP != "" && cached.InputFP != fp && contextUnchanged &&
		cached.ScoreBand == string(score.Band) &&
		w.clock().Sub(cached.EnrichedAt) < w.backstop()
	inputsChanged := !cacheHit || cached.InputFP != fp

	// Record the fingerprint so the next sweep over this unchanged finding is a
	// no-op. Best-effort — a cache write failure must not fail the enrichment.
	if w.cache != nil {
		entry := enrichcache.Entry{
			FindingID:  f.ID,
			InputFP:    fp,
			ContextFP:  ctxFP,
			ScoreBand:  string(score.Band),
			EnrichedAt: w.cacheStamp(score),
			Graph:      graphCtx,
		}
		if err := w.cache.Put(ctx, entry); err != nil {
			log.FromContext(ctx).Error().Err(err).Str("finding_id", f.ID).
				Msg("enrich cache put failed")
		}
	}

	if versionOnlyNoOp {
		log.FromContext(ctx).Debug().Str("finding_id", f.ID).Str("band", string(score.Band)).
			Msg("enrich: version-bump-only re-score, band unchanged — decide/alert skipped")
		return nil
	}
	if inputsChanged {
		w.refreshFleetPackage(ctx, f)
	}

	// A suppressed finding is acknowledged-and-silenced: it must neither
	// re-alert nor enter the decision pipeline — checked BEFORE the alert
	// dispatch below, or an acknowledged critical re-pages on every cache-miss
	// re-enrich and on the freshness backstop. Fail soft on a suppression-store
	// hiccup (log + proceed) so a transient PG error doesn't silently drop
	// legitimate alerts/decisions.
	suppressed := false
	if w.suppress != nil {
		var supErr error
		suppressed, supErr = w.suppress.IsSuppressed(ctx, job.Args.FindingID)
		if supErr != nil {
			log.FromContext(ctx).Error().Err(supErr).Str("finding_id", job.Args.FindingID).
				Msg("suppression check failed; proceeding")
			suppressed = false
		}
	}

	// Alert only on an urgency TRANSITION (alertTransition): entering the page
	// band or must_fix, or rising a band. Re-enriching the same state — a
	// correlate invalidation, the freshness backstop, a flapping graph read —
	// sends nothing. Best-effort — alerting never fails the enrichment.
	if !suppressed && w.notify != nil {
		w.maybeAlert(ctx, f, score)
	}

	if score.Value < enrich.ThresholdPipeline {
		return nil // monitored, not reasoned
	}

	if suppressed {
		log.FromContext(ctx).Info().Str("finding_id", job.Args.FindingID).
			Msg("finding suppressed; alert and decision skipped")
		return nil
	}

	// Carry the enriched score into the decision so it is recorded with it.
	f.Score = score.Value
	f.ScoreBand = string(score.Band)
	enqueueDecide(ctx, f)
	return nil
}

// EnrichSweepArgs is the periodic tick that re-enriches findings, picking up
// context that has drifted since they were last scored (new blast radius, KEV
// escalation, team history). The ingest-time enqueue layers on top for freshness.
type EnrichSweepArgs struct{}

func (EnrichSweepArgs) Kind() string { return "enrich_sweep" }

// enrichSweepMaxAttempts is 2, not River's library default of 25, for the same
// reason correlate carries 2 (internal/jobs/correlate.go).
//
// A sweep tick holds its pagination cursor in a stack local (see drain), so a
// retry does not resume — it restarts phase 1 from page 1 and re-walks the
// identical pages against the identical data. A failure that is a property of
// the query rather than of the moment reproduces on every attempt, and River's
// default backoff policy would schedule the next one a day and a half out; worse,
// wedged retryable rows suppress the fresh periodic ticks that would have
// succeeded, and they still count toward queue-depth backpressure as if they
// were real work in flight.
//
// 2 is right because a periodic tick is its own retry: this job re-derives its
// whole work set from ClickHouse every ENRICH_INTERVAL, so the next tick is
// strictly better than a backed-off attempt at the same tick. One extra attempt
// covers a genuinely transient blip; anything past that is a bug to fix, not to
// retry.
const enrichSweepMaxAttempts = 2

// Unique by state: a periodic tick landing while a sweep is already queued or
// running is dropped, not stacked behind it.
func (EnrichSweepArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueEnrich, enrichSweepMaxAttempts)
}

// EnrichSweepWorker lists current findings and enqueues a per-finding enrich job
// for each — the same EnrichArgs path ingest uses, so scoring logic lives in one
// place.
type EnrichSweepWorker struct {
	river.WorkerDefaults[EnrichSweepArgs]
	findings FindingLister
	alerts   AlertStatePruner // nil => alert state is never pruned
}

// AlertStatePruner drops alert state for findings gone without a resolve.
// enrichcache.Service implements it.
type AlertStatePruner interface {
	PruneAlertStates(ctx context.Context, olderThan time.Time) (int64, error)
}

// alertStateRetention: every open finding is re-enriched at least once per
// freshness backstop (24h), so alert state for a finding not enriched in this
// long belongs to one that is gone (aged out by TTL without a resolve). Pruning
// too eagerly costs one duplicate alert, never a missed one.
const alertStateRetention = 30 * 24 * time.Hour

// backfillSeverities orders the never-enriched backfill most-severe-first so real
// criticals stop hiding at score 0 within hours, not after the whole backlog drains.
var backfillSeverities = []finding.Severity{
	finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow,
}

// Timeout overrides River's 1-minute default. drain() paginates up to
// enrichSweepMax findings per phase in enrichSweepLimit-sized pages — several
// dozen List() calls per job execution — and under load the cumulative time
// across enough pages can exceed a minute even though no single page is slow.
// Same failure class EnrichWorker.Timeout already documents, one level up
// (per-tick sweep vs per-finding enrich).
func (EnrichSweepWorker) Timeout(_ *river.Job[EnrichSweepArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *EnrichSweepWorker) Work(ctx context.Context, _ *river.Job[EnrichSweepArgs]) error {
	var total int
	if w.alerts != nil {
		if n, err := w.alerts.PruneAlertStates(ctx, time.Now().Add(-alertStateRetention)); err != nil {
			log.FromContext(ctx).Warn().Err(err).Msg("enrich sweep: alert-state prune failed")
		} else if n > 0 {
			log.FromContext(ctx).Info().Int64("rows", n).Msg("enrich sweep: pruned alert state of findings no longer enriched")
		}
	}
	// Phase 1 — backfill never-enriched findings, most-severe first. These sit at
	// score 0 in the monitor band, so a score-sorted worklist hides them entirely.
	// This phase drains the whole backlog over successive ticks, then no-ops.
	//
	// Phase 1 is gated on its OWN ceiling (backfillQueueCeiling), well above the
	// routine-drift one: gating it on the tighter enrichQueueMax would let the
	// pass that creates that depth (the full-corpus reenrich) block the repair,
	// and removing the gate entirely lets the accumulated queue grow without
	// limit across ticks and OOM the worker. So repair gets priority over drift,
	// but not immunity from backpressure.
	if !sweepHasCapacity(ctx, backfillQueueCeiling) {
		return nil
	}
	for _, sev := range backfillSeverities {
		if total >= enrichSweepMax {
			break
		}
		n, err := w.drain(ctx, finding.Filter{Unenriched: true, Severity: sev},
			enrichSweepMax-total, river.PriorityDefault)
		if err != nil {
			return fmt.Errorf("Work: backfill %s: %w", sev, err)
		}
		total += n
	}

	// Phase 2 — drift re-enrichment: re-score findings whose graph context (blast
	// radius, KEV escalation, team history, must-fix classification) may have moved
	// since they were last enriched. Sorted oldest-enriched-first (StaleFirst), NOT
	// most-recently-detected: a plain finding.Filter{} sorts by detected_at desc and
	// restarts from the newest finding every tick, so on a corpus bigger than one
	// tick's budget the older tail is never reached at all. StaleFirst self-balances
	// instead of needing a persisted cursor: re-enriching a finding bumps its
	// enriched_at, pushing it to the back of this same sort, so every tick makes
	// forward progress and the whole corpus is eventually covered. Only the budget
	// Phase 1 left unused, so a large never-enriched backlog still drains first.
	//
	// Phase 2 IS gated on queue depth (unlike Phase 1 above): re-scoring a finding
	// that already has a score is routine convergence work and must not pile onto a
	// deep queue. It also stays at enrichSweepPriority so it can never outrank a new
	// detection or a KEV escalation.
	if total < enrichSweepMax && sweepHasCapacity(ctx, enrichQueueMax) {
		n, err := w.drain(ctx, finding.Filter{StaleFirst: true},
			enrichSweepMax-total, enrichSweepPriority)
		if err != nil {
			return fmt.Errorf("Work: drift pass: %w", err)
		}
		total += n
	}

	log.FromContext(ctx).Info().Int("findings", total).Msg("enrich sweep enqueued")
	return nil
}

// drain paginates findings matching f and enqueues a per-finding enrich job for
// each — the same EnrichArgs path ingest uses — up to budget. It spreads CH load
// across DefaultLimit-sized pages instead of one giant query. Returns the count
// enqueued.
func (w *EnrichSweepWorker) drain(ctx context.Context, f finding.Filter, budget, priority int) (int, error) {
	f.Limit = enrichSweepLimit
	var (
		cursor string
		total  int
	)
	for total < budget {
		f.Cursor = cursor
		batch, err := w.findings.List(ctx, f)
		if err != nil {
			return total, fmt.Errorf("drain: list findings (cursor=%q): %w", cursor, err)
		}
		if len(batch) == 0 {
			break
		}
		if total+len(batch) > budget {
			batch = batch[:budget-total] // honor the remaining budget exactly
		}
		// Demoted priority: this periodic re-enrich sweep must never queue-block
		// ingest-time enrichment of a new detection or a KEV-escalation re-enrich
		// (see enrichSweepPriority's doc comment).
		enqueueEnrichPriority(ctx, batch, priority)
		total += len(batch)
		if len(batch) < enrichSweepLimit {
			break // last page for this filter
		}
		last := batch[len(batch)-1]
		if f.StaleFirst {
			cursor = finding.EncodeStaleCursor(last)
		} else {
			cursor = finding.EncodeCursor(last, false)
		}
	}
	return total, nil
}

// FindingLister is the slice of the finding service the enrich sweep needs.
type FindingLister interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
}

// enrichQueueMax caps pending enrich jobs queued from ingest-time paths (sync,
// scan). When the enrich queue is already this deep, skip ingest-time enqueue
// and let the periodic sweep backstop pick things up instead — this prevents a
// large connector sync wave from piling jobs onto an already-deep queue.
const enrichQueueMax = 1000

// backfillQueueCeiling bounds enrich-sweep Phase 1, the never-enriched backfill.
//
// It is deliberately far above enrichQueueMax: a finding at score 0 with
// enriched_at unset is invisible in triage, so repair must not be blocked by a
// queue that routine drift and the full-corpus reenrich pass keep deep. It is
// deliberately NOT absent either — enrichSweepMax caps a single tick, not the
// accumulated queue, so an ungated Phase 1 can still grow without limit across
// ticks.
//
// Pinned to reenrichQueueCeiling plus a margin, not a bare literal: the two
// ceilings must stay correctly ordered, or a full-corpus reenrich pass can hold
// the queue in a band where Phase 1's own lower ceiling trips first and the
// backfill goes dark while reenrich is already self-throttling.
// TestQueueCeilingsAreMeasurable pins the invariant: this must exceed
// reenrichQueueCeiling and stay at or below jobListMaxFirst so the depth probe
// can still measure it. It is a CEILING, not a target — steady state should sit
// far below it once the backfill drains.
const backfillQueueCeiling = reenrichQueueCeiling + 1_000

// jobLister is the one river.Client method the depth checks need, so they are
// unit-testable with a fake.
type jobLister interface {
	JobList(ctx context.Context, params *river.JobListParams) (*river.JobListResult, error)
}

// jobListMaxFirst is River's hard limit on JobListParams.First — it PANICS above
// 10,000 (river@v0.39.0 job_list_params.go). Any queue ceiling compared against a
// JobList-derived depth must therefore be at or below this, which is the constraint
// TestQueueCeilingsAreMeasurable enforces.
const jobListMaxFirst = 10_000

// enrichQueueDepth returns the enrich queue depth, probing only as deep as the
// caller's ceiling needs (deeper than the probe all reads the same). It counts
// every not-yet-finished state — including retryable and pending: without them
// a backlog of timeout-retrying jobs would be invisible to backpressure.
//
// The probe depth MUST be derived from the ceiling — a probe capped below a
// caller's ceiling makes `depth >= ceiling` arithmetically unreachable, silently
// disabling that gate with no symptom beyond a log line that never appears.
func enrichQueueDepth(ctx context.Context, client jobLister, ceiling int) (int, error) {
	probe := ceiling + 1
	if probe > jobListMaxFirst {
		probe = jobListMaxFirst
	}
	list, err := client.JobList(ctx, river.NewJobListParams().Queues(queueEnrich).
		States(uniqueStates...).First(probe))
	if err != nil {
		return 0, fmt.Errorf("enrichQueueDepth: %w", err)
	}
	return len(list.Jobs), nil
}

// sweepHasCapacity reports whether the enrich sweep may enqueue this tick.
// Fail-closed: a failed depth check counts as no capacity. Warn-level so a
// persistently full queue is alertable from logs. No client in context (unit
// tests driving the worker directly) proceeds, matching enqueueEnrich.
func sweepHasCapacity(ctx context.Context, ceiling int) bool {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return true
	}
	depth, err := enrichQueueDepth(ctx, client, ceiling)
	if err != nil || depth >= ceiling {
		log.FromContext(ctx).Warn().Int("queue_depth", depth).Int("ceiling", ceiling).Err(err).
			Msg("enrich sweep skipped — queue at capacity")
		return false
	}
	return true
}

// enqueueEnrichIfCapacity is the backpressure variant of enqueueEnrich.
// Called from SyncWorker so that a full sync wave doesn't overwhelm the queue.
func enqueueEnrichIfCapacity(ctx context.Context, found []finding.Finding) {
	if len(found) == 0 {
		return
	}
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		// No client in context (unit tests) — fall back to regular enqueue.
		enqueueEnrich(ctx, found)
		return
	}
	depth, depthErr := enrichQueueDepth(ctx, client, enrichQueueMax)
	if depthErr != nil || depth >= enrichQueueMax {
		// Queue full or check failed — skip ingest-time enqueue.
		// The periodic EnrichSweep will pick these up.
		log.FromContext(ctx).Debug().Int("queue_depth", depth).
			Msg("enrich queue at capacity — skipping ingest-time enqueue")
		return
	}
	enqueueEnrich(ctx, found)
}

// enqueueEnrich fans out an enrich job per finding on ingest (sync, scan, KEV).
// Every finding is enriched — there is no severity pre-filter; the pipeline gate
// is the enriched score, applied after scoring in EnrichWorker.
//
// Not in the domain-write transaction (the domain write is ClickHouse, which
// can't share River's Postgres tx); a failed enqueue is logged, not fatal — the
// periodic sweep re-enqueues.
func enqueueEnrich(ctx context.Context, found []finding.Finding) {
	enqueueEnrichPriority(ctx, found, river.PriorityDefault)
}

// enrichSweepPriority demotes the periodic full-corpus re-enrich sweep
// (EnrichSweepWorker.drain) below river.PriorityDefault, so it can never
// compete for a worker slot against ingest-time enrichment of a brand-new
// detection or a KEV-escalation re-enrich (both stay at PriorityDefault via
// plain enqueueEnrich). River's priority is a hard ordering, not a tie-break: as
// long as ANY PriorityDefault job is available, zero jobs at this priority run —
// which is what stops the routine, un-urgent half of the backlog from starving
// the urgent half when the queue is deep.
const enrichSweepPriority = river.PriorityDefault + 1

// enqueueEnrichPriority is enqueueEnrich with an explicit River priority
// (1=highest/default, 4=lowest — see river.InsertOpts.Priority). Queue and
// UniqueOpts still come from EnrichArgs.InsertOpts() regardless of priority;
// river.Client.Insert merges per-call opts with the args-level opts
// field-by-field (cmp.Or), it does not replace them wholesale.
func enqueueEnrichPriority(ctx context.Context, found []finding.Finding, priority int) {
	if len(found) == 0 {
		return
	}
	// Safely: enqueue is best-effort and called from several workers; in
	// production the client is always present, but tolerate its absence (e.g. a
	// unit test driving a producer worker directly) rather than panicking.
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("enqueue enrich: no river client in context")
		return
	}
	opts := &river.InsertOpts{Priority: priority}
	for _, f := range found {
		if _, err := client.Insert(ctx, EnrichArgs{FindingID: f.ID}, opts); err != nil {
			log.FromContext(ctx).Error().Err(err).Str("finding_id", f.ID).Msg("enqueue enrich failed")
		}
	}
}

// respondQueueMax caps the number of pending decide jobs. When the respond
// queue exceeds this depth, new decide inserts are silently dropped — the
// agent will re-evaluate on the next enrichment sweep once it drains.
// Without this, a single enrichment sweep can queue tens of thousands of LLM jobs, saturating
// the Ladybug connection pool and blocking everything else for hours.
const respondQueueMax = 500

// respondQueueDepth measures the respond (decide) backlog, capped at
// respondQueueMax+1 (deeper than the cap all reads the same). It counts every
// not-yet-finished state via uniqueStates — including retryable and pending:
// without them a backlog of timeout-retrying decide jobs would be invisible to
// this guard (enrichQueueDepth and correlateQueueDepth count them for the same
// reason).
func respondQueueDepth(ctx context.Context, client jobLister) (int, error) {
	list, err := client.JobList(ctx, river.NewJobListParams().Queues("respond").
		States(uniqueStates...).First(respondQueueMax+1))
	if err != nil {
		return 0, fmt.Errorf("respondQueueDepth: %w", err)
	}
	return len(list.Jobs), nil
}

// respondQueueGuard applies the respondQueueMax backpressure decision given an
// already-measured depth/error, logging a Warn on drop so a saturated respond
// queue is alertable from logs rather than a silent drop.
// Returns true if the caller must drop the decide job.
func respondQueueGuard(ctx context.Context, f finding.Finding, depth int, depthErr error) bool {
	if depthErr != nil || depth >= respondQueueMax {
		log.FromContext(ctx).Warn().Int("queue_depth", depth).Int("ceiling", respondQueueMax).
			Err(depthErr).Str("finding_id", f.ID).
			Msg("decide skipped — respond queue at capacity")
		return true
	}
	return false
}

// enqueueDecide enqueues the decision for one (already enriched, above-threshold)
// finding, subject to the respondQueueMax depth guard.
// Client-safe like enqueueEnrich so the enrich worker is unit-testable.
func enqueueDecide(ctx context.Context, f finding.Finding) {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("enqueue decide: no river client in context")
		return
	}
	// Depth guard: fail-closed. If the list fails (DB busy), treat as full
	// and skip — better to miss one decide job than flood the queue under load.
	// The next enrich sweep will re-queue once the agent drains.
	depth, depthErr := respondQueueDepth(ctx, client)
	if respondQueueGuard(ctx, f, depth, depthErr) {
		return
	}
	if _, err := client.Insert(ctx, DecideArgs{Finding: f}, nil); err != nil {
		log.FromContext(ctx).Error().Err(err).Str("finding_id", f.ID).Msg("enqueue decide failed")
	}
}
