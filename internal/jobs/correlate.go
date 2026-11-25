package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// maxExposedAssets caps assets processed per correlate sweep in
// invalidateExposedFindings, so this fast/targeted path never loads the whole
// findings corpus into memory at once. Package-level so it's the single
// source of truth for the cap AND the value passed to ListExternalIDs.
//
// 1000, not a larger round number: asset.CHRepo's ListExternal has its own
// outer ceiling, defaultExternalLimit=1000 (a shared safety clamp other
// callers also fall under), and silently clamps anything larger — matching
// that ceiling here keeps the real cap visible in the one constant that
// governs it (see asset.clampExternalLimit's doc comment).
const maxExposedAssets = 1000

// LadybugSyncFn is a convenience adapter so worker.go can pass a closure as a LadybugSyncer.
type LadybugSyncFn func(context.Context) error

func (f LadybugSyncFn) Sync(ctx context.Context) error { return f(ctx) }

// Correlator runs the cross-asset correlation rules and writes derived edges.
// *correlate.Service implements it.
type Correlator interface {
	Correlate(ctx context.Context) (int, error)
	PartialCorrelate(ctx context.Context, changedIDs []string) (int, error)
}

// AssetExposer returns IDs of the limit most-recently-seen internet-facing assets
// (public IP or domain set). *asset.Service implements it.
type AssetExposer interface {
	ListExternalIDs(ctx context.Context, limit int) ([]string, error)
}

// FindingsByResource returns findings for the given resource IDs (batch).
// *finding.Service implements it.
type FindingsByResource interface {
	ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

// EnrichCacheInvalidator clears the input fingerprint of the given findings,
// forcing their next enrich past the change-gate so scores are recomputed with
// current graph context. The rest of each cache entry survives.
// *enrichcache.Service implements it.
type EnrichCacheInvalidator interface {
	InvalidateFingerprints(ctx context.Context, findingIDs []string) error
}

// CorrelateArgs runs a correlation sweep. When ChangedIDs is non-empty it runs
// a partial sweep (only rules relevant to the changed asset types, only the
// needed asset types loaded). When empty it runs the full whole-graph sweep.
type CorrelateArgs struct {
	ChangedIDs []string `json:"changed_ids,omitempty"`
}

func (CorrelateArgs) Kind() string { return "correlate" }

// InsertOpts puts correlation on its own queue so a large whole-graph join
// never starves the sync or respond queues.
//
// MaxAttempts 2, not River's library default of 25: a full sweep is
// idempotent and self-superseding, so the periodic tick already IS the retry
// — retrying up to 25 times just re-reads the whole view over and over while
// fresh ticks pile in behind it. One retry absorbs a genuine transient blip;
// past that the failure is structural and must SURFACE rather than grind.
// Same reasoning as RefreshImageVulnArgs.InsertOpts.
func (CorrelateArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: queueCorrelate, MaxAttempts: 2}
}

// correlateBootDelay holds the boot sweep back until the deploy's sync wave has
// written its first rows, so correlate does not join syncs, enrich and the
// Ladybug rebuild in saturating ClickHouse CPU. The serve pod's ClickHouse BFS
// fallback covers the gap.
const correlateBootDelay = 5 * time.Minute

// fullCorrelateOpts makes the whole-graph sweep a singleton. ByArgs, so a
// pending partial sweep (non-empty ChangedIDs, same kind) never suppresses a
// full one. Queue and MaxAttempts fall through to CorrelateArgs.InsertOpts.
func fullCorrelateOpts() *river.InsertOpts {
	return &river.InsertOpts{UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: uniqueStates}}
}

// EnqueueBootCorrelate schedules the worker's one boot-time full sweep,
// correlateBootDelay out. It is an explicit insert rather than RunOnStart
// because only the River leader runs periodics, and the leader may be the
// scanner pod. A full sweep already queued or running — a sibling replica's
// boot sweep, or the periodic tick — makes this a no-op.
func EnqueueBootCorrelate(ctx context.Context, client jobInserter) error {
	opts := fullCorrelateOpts()
	opts.ScheduledAt = time.Now().Add(correlateBootDelay)
	res, err := client.Insert(ctx, CorrelateArgs{}, opts)
	if err != nil {
		return fmt.Errorf("EnqueueBootCorrelate: %w", err)
	}
	if res.UniqueSkippedAsDuplicate {
		log.FromContext(ctx).Info().Int64("job_id", res.Job.ID).
			Msg("boot correlate skipped — a full sweep is already queued or running")
	}
	return nil
}

// LadybugSyncer rebuilds the Ladybug graph from ClickHouse. The concrete sync logic
// (which sources to read) is captured in the closure built in worker.go.
// Nil disables Ladybug sync.
type LadybugSyncer interface {
	Sync(ctx context.Context) error
}

// TopologyBumper increments the topology version counter in ClickHouse
// sync_state after every completed full correlate sweep, whether or not
// topology changed. The Ladybug sync closure compares this counter with the
// version it last loaded: equal means a signal-only refresh, anything else
// hands off to SyncFromSources and its load-digest gate. Nil disables bumping,
// so the counter never moves and every sync after the first one that loads a
// non-zero version is signal-only.
type TopologyBumper interface {
	BumpTopologyVersion(ctx context.Context) error
}

// AssetsByIDsAndIngest reads assets by IDs and re-ingests with updated scores.
// *asset.Service satisfies it.
type AssetsByIDsAndIngest interface {
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
	Ingest(ctx context.Context, assets []asset.Asset, edges []asset.Edge) error
}

// PendingCIVerifier exposes the AWS role targets the CIAccess correlate rule
// found no live iam_role node for in the sweep just completed — live
// candidates for the out-of-band verify_ci_role job. The registered
// *correlate.CIAccess rule instance satisfies it. Nil disables the enqueue
// (e.g. a deployment that hasn't wired the CIAccess rule).
type PendingCIVerifier interface {
	PendingLiveVerify() []correlate.PendingVerify
}

// CorrelateWorker runs one correlation sweep, then:
//  1. Bumps asset scores from high/critical finding severity (when wired)
//  2. Invalidates the enrich cache for exposed assets (score freshness)
//  3. Bumps the topology version so Ladybug knows a full rebuild is needed
//  4. Rebuilds the Ladybug graph (when wired) for real Cypher traversal
type CorrelateWorker struct {
	river.WorkerDefaults[CorrelateArgs]
	correlate    Correlator
	assets       AssetExposer
	findings     FindingsByResource
	enrichCache  EnrichCacheInvalidator
	ladybug      LadybugSyncer        // nil = Ladybug not configured
	topoBumper   TopologyBumper       // nil = topology version bumping disabled
	findingsList FindingLister        // nil = finding scoring disabled
	assetsByIDs  AssetsByIDsAndIngest // nil = finding scoring disabled
	ciAccess     PendingCIVerifier    // nil = verify_ci_role enqueue disabled
	metrics      *obs.Metrics         // nil = correlate sweep metrics disabled
}

// Timeout overrides River's default 1-minute job timeout. Correlate + Ladybug sync
// currently takes several minutes end to end; 20 minutes gives headroom for growth.
func (w *CorrelateWorker) Timeout(_ *river.Job[CorrelateArgs]) time.Duration {
	return 20 * time.Minute
}

func (w *CorrelateWorker) Work(ctx context.Context, job *river.Job[CorrelateArgs]) error {
	if len(job.Args.ChangedIDs) > 0 {
		// A partial correlate older than the full-sweep interval is dead work:
		// the periodic whole-graph sweep has already re-derived every edge it
		// would compute. Skipping (instead of running superseded joins) is what
		// lets a backed-up correlate queue burn off — a large backlog of stale
		// partials can otherwise starve this queue's periodic ticks.
		// 2× the default interval gives headroom for an env-tuned longer sweep.
		if time.Since(job.CreatedAt) > 2*defaultCorrelateInterval {
			log.FromContext(ctx).Info().Time("created_at", job.CreatedAt).
				Int("changed_ids", len(job.Args.ChangedIDs)).
				Msg("partial correlate stale — skipped (superseded by full sweep)")
			return nil
		}
		return w.workPartial(ctx, job.Args.ChangedIDs)
	}
	return w.workFull(ctx)
}

// correlateSweepStatus classifies a Correlate/PartialCorrelate error for the
// graph_correlate_sweeps_total metric that GraphCorrelateSweepsFailing pages
// on. context.Canceled is carved out to its own "cancelled" status rather
// than folded into "error", because a full sweep running during a pod
// termination (rolling deploy, node preemption, scale-down) can outlive
// SoftStopTimeout's grace period and get cancelled by River even though
// nothing on the data side went wrong — indistinguishable from a genuine
// ClickHouse timeout or view truncation if counted as "error".
//
// A context.DeadlineExceeded is deliberately NOT carved out: that is a
// genuine "this took too long" signal, exactly what the alert exists to
// catch, and the alert's ratio already excludes "cancelled" from its
// numerator while still counting it in the denominator, so a burst of
// shutdown cancellations lowers the error ratio instead of inflating it.
func correlateSweepStatus(err error) string {
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "error"
}

func (w *CorrelateWorker) workPartial(ctx context.Context, changedIDs []string) error {
	start := time.Now()
	n, err := w.correlate.PartialCorrelate(ctx, changedIDs)
	if err != nil {
		w.metrics.ObserveCorrelateSweep("partial", correlateSweepStatus(err))
		return fmt.Errorf("workPartial: %w", err)
	}
	w.metrics.ObserveCorrelateSweep("partial", "ok")
	log.FromContext(ctx).Info().
		Int("edges", n).
		Int("changed_ids", len(changedIDs)).
		Dur("elapsed", time.Since(start)).
		Msg("partial correlation complete")
	return nil
}

func (w *CorrelateWorker) workFull(ctx context.Context) error {
	start := time.Now()
	n, err := w.correlate.Correlate(ctx)
	if err != nil {
		w.metrics.ObserveCorrelateSweep("full", correlateSweepStatus(err))
		return fmt.Errorf("workFull: %w", err)
	}
	// Stamped only on a sweep that COMPLETED. This is the signal a duration
	// histogram cannot carry: it only samples the runs that finish, so "most
	// full sweeps stopped completing for a long stretch" is unrepresentable there.
	w.metrics.ObserveCorrelateSweep("full", "ok")
	w.metrics.ObserveCorrelateFullSuccess(float64(time.Now().Unix()))
	log.FromContext(ctx).Info().
		Int("edges", n).
		Dur("elapsed", time.Since(start)).
		Msg("correlation sweep complete")

	// Post-correlate: bump asset scores from high/critical findings so BFS
	// propagates vulnerability risk through the graph on the next Ladybug sync.
	if w.findingsList != nil && w.assetsByIDs != nil {
		scoreAssetsFromFindings(ctx, w.findingsList, w.assetsByIDs)
	}

	// Post-correlate: invalidate enrich cache for exposed assets.
	if w.assets != nil && w.findings != nil && w.enrichCache != nil {
		invalidateExposedFindings(ctx, w.assets, w.findings, w.enrichCache)
	}

	// Post-correlate: bump the topology version so the Ladybug sync closure
	// hands the rebuild enqueued below to SyncFromSources rather than taking
	// its signal-only path.
	if w.topoBumper != nil {
		if err := w.topoBumper.BumpTopologyVersion(ctx); err != nil {
			log.FromContext(ctx).Warn().Err(err).Msg("topology version bump failed — the next Ladybug sync sees an unchanged version and refreshes signals only, so this sweep's topology changes are not loaded until a later bump succeeds or the worker restarts")
		}
	}

	// Post-correlate: enqueue the Ladybug rebuild, the worker's only rebuild
	// trigger once its boot-time syncs are done. LadybugRebuildArgs is unique-while-queued,
	// so a burst of correlate completions produces at most one queued rebuild.
	if w.ladybug != nil {
		client := river.ClientFromContext[pgx.Tx](ctx)
		if _, err := client.Insert(ctx, LadybugRebuildArgs{}, nil); err != nil {
			log.FromContext(ctx).Warn().Err(err).Msg("ladybug rebuild enqueue failed — graph queries may be stale")
		}
	}

	// Post-correlate: enqueue a verify_ci_role job for every AWS CI-workflow
	// target the CIAccess rule couldn't match to a live iam_role node this sweep.
	// VerifyCIRoleArgs is unique-while-queued, so this is safe to call
	// every sweep even though PendingLiveVerify resets each run — a target still
	// unresolved next sweep is deduplicated against its own still-pending job,
	// not re-queued on top of it.
	if w.ciAccess != nil {
		enqueueVerifyCIRole(ctx, w.ciAccess.PendingLiveVerify())
	}
	return nil
}

// enqueueVerifyCIRole inserts one VerifyCIRoleArgs job per pending target,
// deduped by (RepoID, TargetARN) — the join key CIAccess used to decide there
// was no live match. Uses the ctx-bound River client so the insert lands in
// the same job-execution transaction as the correlate sweep that produced it;
// the edges/annotations correlate itself writes go to ClickHouse,
// which cannot share this Postgres transaction (see enqueueEnrich), so this is
// the closest equivalent available — same pattern as the LadybugRebuildArgs
// enqueue just above. Best-effort: a single insert failure is logged, not fatal.
func enqueueVerifyCIRole(ctx context.Context, pending []correlate.PendingVerify) {
	if len(pending) == 0 {
		return
	}
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("enqueue verify_ci_role: no river client in context")
		return
	}
	seen := make(map[string]bool, len(pending))
	for _, p := range pending {
		key := p.RepoID + "|" + p.TargetARN
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, err := client.Insert(ctx, VerifyCIRoleArgs{
			RepoID: p.RepoID, TargetARN: p.TargetARN, AccountID: p.AccountID,
			WorkflowPath: p.WorkflowPath,
		}, nil); err != nil {
			log.FromContext(ctx).Error().Err(err).Str("repo", p.RepoID).Str("target_arn", p.TargetARN).
				Msg("enqueue verify_ci_role failed")
		}
	}
}

// scoreAssetsFromFindings loads all high/critical findings, groups them by
// resource, and re-ingests the affected assets with bumped risk scores. BFS
// then propagates those scores outward on the next Ladybug graph rebuild.
func scoreAssetsFromFindings(ctx context.Context, src FindingLister, assets AssetsByIDsAndIngest) {
	logger := log.FromContext(ctx)
	const limit = 20000

	// Load critical then high severity findings. Two queries because the filter
	// does an exact severity match — no min-severity predicate available.
	var found []finding.Finding
	for _, sev := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh} {
		batch, err := src.List(ctx, finding.Filter{Severity: sev, Limit: limit})
		if err != nil {
			logger.Warn().Err(err).Str("severity", string(sev)).Msg("finding scorer: list failed")
			continue
		}
		found = append(found, batch...)
	}
	if len(found) == 0 {
		return
	}

	// Dedupe resource IDs and find the worst severity per resource.
	worstSev := make(map[string]finding.Severity, len(found))
	for _, f := range found {
		if f.ResourceID == "" {
			continue
		}
		if existing, ok := worstSev[f.ResourceID]; !ok || severityRank(f.Severity) > severityRank(existing) {
			worstSev[f.ResourceID] = f.Severity
		}
	}
	if len(worstSev) == 0 {
		return
	}

	ids := make([]string, 0, len(worstSev))
	for id := range worstSev {
		ids = append(ids, id)
	}

	affected, err := assets.ByIDs(ctx, ids)
	if err != nil {
		logger.Warn().Err(err).Msg("finding scorer: load assets failed")
		return
	}

	bumped := make([]asset.Asset, 0, len(affected))
	for _, a := range affected {
		sev, ok := worstSev[a.ID]
		if !ok {
			continue
		}
		score := findingSeverityScore(sev)
		if score <= a.RiskScore {
			continue
		}
		a.RiskScore = score
		bumped = append(bumped, a)
	}
	if len(bumped) == 0 {
		return
	}

	if err := assets.Ingest(ctx, bumped, nil); err != nil {
		logger.Warn().Err(err).Int("assets", len(bumped)).Msg("finding scorer: ingest failed")
		return
	}
	logger.Info().Int("assets", len(bumped)).Msg("finding scorer: asset scores updated")
}

func severityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 4
	case finding.SeverityHigh:
		return 3
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 1
	}
	return 0
}

func findingSeverityScore(s finding.Severity) uint8 {
	switch s {
	case finding.SeverityCritical:
		return 80
	case finding.SeverityHigh:
		return 60
	}
	return 0
}

// invalidateExposedFindings:
//  1. Fetches IDs of the most-recently-seen internet-facing assets, up to
//     maxExposedAssets
//  2. Finds their findings
//  3. Clears those open findings' enrich-cache fingerprints
//  4. Re-enqueues enrichment — River deduplicates if already pending
//
// This is a fast, bounded refresh of the maxExposedAssets most-recently-seen
// exposed assets (ordered by last_seen, not by any exposure-change signal). It
// does not cover the whole exposed population; it reaches only
// maxExposedAssets per sweep.
// Full-corpus coverage relies on EnrichSweepWorker's Phase 2 drift pass
// (enrich.go): its StaleFirst sort is self-balancing (re-enriching a finding
// bumps its enriched_at, pushing it to the back of that same sort), so it
// eventually reaches every finding without a persisted cursor. That guarantee
// is conditional on Phase 2 actually getting budget each tick — see
// enrich.go's own comments for the gates that can zero it out.
func invalidateExposedFindings(
	ctx context.Context,
	assets AssetExposer,
	findings FindingsByResource,
	cache EnrichCacheInvalidator,
) {
	logger := log.FromContext(ctx)

	assetIDs, err := assets.ListExternalIDs(ctx, maxExposedAssets)
	if err != nil {
		logger.Warn().Err(err).Msg("post-correlate: list exposed assets failed")
		return
	}
	if len(assetIDs) == 0 {
		return
	}

	// Process in batches to avoid loading all findings at once.
	const batchSize = 500
	var totalEnqueued int
	for i := 0; i < len(assetIDs); i += batchSize {
		end := i + batchSize
		if end > len(assetIDs) {
			end = len(assetIDs)
		}
		batch := assetIDs[i:end]

		rows, err := findings.ByResourceIDs(ctx, batch)
		if err != nil {
			logger.Warn().Err(err).Msg("post-correlate: list affected findings failed (batch)")
			continue
		}
		// ByResourceIDs returns resolved findings too; re-enriching those every
		// sweep is what re-sent "New finding" for already-fixed CVEs.
		affected := make([]finding.Finding, 0, len(rows))
		for _, f := range rows {
			if !f.Resolved() {
				affected = append(affected, f)
			}
		}
		if len(affected) == 0 {
			continue
		}

		ids := make([]string, len(affected))
		for j, f := range affected {
			ids[j] = f.ID
		}
		if err := cache.InvalidateFingerprints(ctx, ids); err != nil {
			logger.Warn().Err(err).Msg("post-correlate: cache invalidation failed (batch)")
			continue
		}
		enqueueEnrich(ctx, affected)
		totalEnqueued += len(affected)
	}
	if totalEnqueued > 0 {
		logger.Info().Int("count", totalEnqueued).Msg("post-correlate enrich enqueued")
	}
}
