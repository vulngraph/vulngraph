// Package jobs holds the River background workers: the periodic enqueuer that
// fans out per-connector syncs, and the sync worker that runs one connector's
// collector and ingests the result.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// SyncConnectorArgs runs a full sync of one connector.
type SyncConnectorArgs struct {
	ConnectorID string `json:"connector_id" river:"unique"`
}

func (SyncConnectorArgs) Kind() string { return "sync_connector" }

// InsertOpts keeps the job in the sync queue and unique while queued/running,
// so overlapping schedules can't double-sync one connector. MaxAttempts is
// capped low so a failing connector retries only a couple of times before
// waiting for the next periodic sweep — a failed sync resets SyncStreak to 0
// (see cleanNoOp), so that next check (EnqueueWorker's own tick, every
// enqueueCheckInterval) finds it due again at base cadence — instead of
// hammering the shared workers for River's default 25 attempts. Permanent
// failures are cancelled outright in Work (see collect.ErrPermanent).
func (SyncConnectorArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       queueSync,
		MaxAttempts: 3,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// scopeForgetter evaluates what deletion enforcement WOULD forget for the
// scopes a sweep proved it enumerated completely. Injected so sync.go
// does not import the forget domain, and nil-able because a pod without it must
// sync exactly as before.
//
// It is handed the sweep's own facts and nothing else — in particular NOT the
// collected asset set: the decision is taken against what STORAGE holds, and
// re-deriving that from the sweep in memory is how a partial collection would
// talk itself into a deletion.
type scopeForgetter interface {
	Evaluate(ctx context.Context, sw forget.Sweep) (int, error)
}

// SyncWorker collects a connector's inventory, ingests it, runs CSPM checks
// over what was collected, and records the findings. The outcome is always
// recorded on the connector, success or failure.
type SyncWorker struct {
	river.WorkerDefaults[SyncConnectorArgs]
	connectors *connector.Service
	registry   *collect.Registry
	assets     *asset.Service
	findings   *finding.Service
	checks     *checks.Registry
	metrics    *obs.Metrics   // nil when metrics are disabled
	forget     scopeForgetter // nil when the deletion evaluation is disabled
	// suppressions carries a suppression across a check split (sync_supersede.go);
	// nil disables the carry.
	suppressions SuppressionCarrier
	// inventory applies package-inventory sources outside the collectors (disk
	// scan, later a customer's agent); nil applies none (sync_diskscan.go).
	inventory *inventoryOverlay
}

// Timeout overrides River's default 1-minute timeout. Large AWS accounts with
// thousands of resources take 5-10 min to collect; GCP with many projects
// similarly. 30 minutes gives headroom without risking indefinitely stuck jobs.
func (SyncWorker) Timeout(_ *river.Job[SyncConnectorArgs]) time.Duration {
	return 30 * time.Minute
}

func (w *SyncWorker) Work(ctx context.Context, job *river.Job[SyncConnectorArgs]) error {
	logger := log.FromContext(ctx)
	start := time.Now()

	c, err := w.connectors.Get(ctx, job.Args.ConnectorID)
	if err != nil {
		return fmt.Errorf("Work: load connector: %w", err)
	}

	// A connector disabled after this job was enqueued must not run — cancel
	// rather than sync, so disabled accounts can't occupy the shared workers.
	if !c.Enabled {
		return river.JobCancel(fmt.Errorf("Work: connector %s is disabled", c.ID))
	}

	// An aws_org connector is reconciled by DiscoverAWSOrgsArgs; recording a
	// "no collector" error here would overwrite its discovery status.
	if c.Type == connector.TypeAWSOrg {
		return river.JobCancel(fmt.Errorf("Work: connector %s is an aws_org connector; discovery syncs it", c.ID))
	}

	collector, err := w.registry.For(c.Type)
	if err != nil {
		// No collector for this type yet — record it and stop. Retrying won't help.
		// cleanNoOp=false, partial=false explicitly: res/skipped/res.Partial don't
		// exist yet at this point in the function, so there is nothing to compute
		// either from.
		if recErr := recordSync(ctx, w.connectors, c.ID, err, false, false); recErr != nil {
			logger.Error().Err(recErr).Msg("record sync failed")
		}
		return river.JobCancel(err)
	}

	res, runErr := collector.Collect(ctx, configWithProvenCapabilities(ctx, w.connectors, c))
	// Persist any capability this sweep proved (e.g. AWS Identity Center's
	// sso_admin — internal/collect/aws/identitycenter.go) regardless of runErr:
	// a collector can prove a capability in one region/scope and still fail
	// overall in another, and the proof must survive that failure the same
	// way CompletedEnumerations does. See sync_capabilities.go.
	if len(res.ProvenCapabilities) > 0 {
		recordProvenCapabilities(ctx, w.connectors, c.ID, res.ProvenCapabilities, time.Now())
	}
	if runErr == nil {
		w.inventory.apply(ctx, c, &res)
	}
	var findingCount, changedAssets int
	var skipped bool
	// changedAssetIDs tracks which assets were new/changed so CSPM checks only
	// run against them — unchanged assets' findings already exist in CH with
	// their enriched scores and must not be overwritten with Score=0.
	var changedAssetIDs map[string]bool
	// toIngest and currentHashes are hoisted here so the post-ingest hash-update
	// block can reference them without re-declaring inside the inner else scope.
	var toIngest []asset.Asset
	var currentHashes map[string]connector.StoredAssetHash
	// Observe-only deletion signal: how many stored asset hashes this sweep did
	// not see, whether or not reconciliation was allowed to act on them.
	// candidatesKnown stays false when the stored set was never loaded, so an
	// unmeasured sweep does not publish a zero (see recordDeletionSignal).
	var deletionCandidates int
	var candidatesKnown bool
	// needBackfill: the deployed check registry differs from the one recorded on
	// this connector's stored fingerprint, so new/changed checks must run against
	// ALL collected assets (not just changed ones) to backfill immediately.
	// Persisted per connector inside sync_fingerprint, never in memory on the
	// shared SyncWorker: a per-process value would backfill only the FIRST
	// connector synced per worker process; every other connector's unchanged
	// assets would never be re-checked, so newly deployed checks with real
	// violations would produce zero findings on every connector but the first.
	checksFP := w.checks.Fingerprint()
	needBackfill := false
	// stored is what the last successful sweep recorded; day is the UTC day
	// the time-dependent checks last ran on every asset, advanced below only
	// when this sweep actually re-ran them (recheckTimeDependent).
	stored := splitSyncFingerprint(c.SyncFingerprint)
	today := clockDay(start)
	day := stored.day
	// CIEM runs before the fingerprint so its privilege-tier stamps are part
	// of what is hashed, ingested and checked (see analyzeIAM).
	var ciemInput []asset.Asset
	var ciemResult ciem.AnalysisResult
	// partial widens res.Partial with a CIEM input that could not be read
	// (an account's SCP set): the privesc findings it withheld must not be
	// resolved for their absence, and the sweep is not a clean no-op.
	partial := res.Partial
	if runErr == nil {
		stampProvenance(res.Assets, c)
		stampFindingProvenance(res.Findings, c.ID)
		var ciemPartial bool
		ciemInput, ciemResult, ciemPartial, runErr = analyzeIAM(ctx, w.assets, res.Assets)
		partial = partial || ciemPartial
	}
	if runErr == nil {
		needBackfill = stored.checksFP != checksFP

		// Phase 1: connector-level short-circuit. Compute a combined
		// fingerprint over all collected assets. If it matches what we stored
		// after the last successful ingest AND the check registry is unchanged,
		// nothing to do — skip entirely. This is the dominant win: most
		// sweeps change nothing. A pending check backfill must NOT short-circuit:
		// the skip path bypasses the check run, which is exactly how new checks
		// stayed dark on stable connectors.
		newFP := asset.ConnectorFingerprint(res.Assets)
		if newFP != "" && !needBackfill && newFP == stored.assetFP {
			skipped = true
			// Assets AND edges are ALWAYS re-stamped, even on a no-change sweep,
			// for the same reason: both tables are ReplacingMergeTree with no
			// delete path, so a row that stops being re-inserted is
			// indistinguishable from one that still exists. Every graph_edges
			// reader filters on synced_at freshness
			// (graphschema.EdgeFreshnessCond) and every asset liveness gate
			// filters on last_seen (asset.EphemeralLivenessCond) —
			// skipping either write evicts a stable connector's live rows from
			// the graph. RMT dedups on merge; the write volume is trivial.
			//
			// The write is deliberately NOT gated on the content diff. See
			// restampLastSeen for why "wrote nothing because nothing changed"
			// silently turns last_seen into "last CHANGED" and drops stable live
			// assets from the graph.
			runErr = w.assets.Ingest(ctx, restampLastSeen(res.Assets, time.Now()), res.Edges)
			logger.Info().Str("connector_id", c.ID).
				Int("assets", len(res.Assets)).Int("edges", len(res.Edges)).
				Msg("connector sync: no changes — skipped enrich, re-stamped assets + edges")
		} else {
			// Phase 2: per-asset diff — only write new/changed assets.
			// Load current hashes from Postgres (indexed read, O(connector size))
			// instead of from ClickHouse (full table scan, O(total assets)).
			var diffErr error
			currentHashes, diffErr = w.connectors.GetAssetHashes(ctx, c.ID)
			if diffErr != nil {
				// Diff query failed — fall back to full write (all assets changed).
				log.FromContext(ctx).Warn().Err(diffErr).
					Str("connector_id", c.ID).Msg("sync: asset diff failed, falling back to full write")
				toIngest = res.Assets
			} else {
				changedAssetIDs = make(map[string]bool)
				var changedExistingIDs []string // existed before AND changed — diffable
				for _, a := range res.Assets {
					h, exists := currentHashes[a.ID]
					if !exists || h.Hash != asset.ContentHash(a) {
						toIngest = append(toIngest, a)
						changedAssetIDs[a.ID] = true
						if exists {
							changedExistingIDs = append(changedExistingIDs, a.ID)
						}
					}
				}
				// Per-field change log: fetch the pre-write versions of changed
				// assets, diff against the new ones, and append to the audit log so
				// the drift timeline can show exactly what changed. Best-effort.
				w.writeAssetChangeLog(ctx, c.ID, res.Assets, changedExistingIDs)
			}
			changedAssets = len(toIngest)
			logger.Debug().Str("connector_id", c.ID).
				Int("total", len(res.Assets)).Int("changed", changedAssets).
				Msg("connector sync: per-asset diff")
			// Write EVERY collected asset, not just the changed ones, and always
			// refresh edges (topology changes even when asset content is stable).
			// The diff still decides what gets re-CHECKED and re-ENRICHED
			// (changedAssetIDs below) — that is the expensive half the diff exists
			// to skip. It must not also decide what gets re-OBSERVED: see
			// restampLastSeen.
			runErr = w.assets.Ingest(ctx, restampLastSeen(res.Assets, time.Now()), res.Edges)
		}
	}

	// Persist the CIEM analysis (run above, before the fingerprint).
	// ScoredAssets: re-ingest with bumped RiskScore so BFS propagates outward.
	// Paths: emit can_escalate_to edges into ClickHouse so the graph shows the
	// full CIEM attack chain, not only the CanAssume edges from trust policies.
	// Runs on skipped sweeps too: the can_escalate_to edges must be re-stamped
	// each sweep (freshness eviction, see above) — only the ScoredAssets
	// re-ingest is skipped, since asset content is unchanged by definition.
	if runErr == nil {
		if !skipped && len(ciemResult.ScoredAssets) > 0 {
			if err := w.assets.Ingest(ctx, ciemResult.ScoredAssets, nil); err != nil {
				log.FromContext(ctx).Warn().Err(err).Msg("ciem: score ingest failed")
			}
		}
		ciemEdges, dangling := ciemEscalationEdges(ciemInput, ciemResult.Paths)
		if dangling > 0 {
			log.FromContext(ctx).Debug().Int("dangling", dangling).
				Msg("ciem: escalation targets outside this sweep's asset set, not written")
		}
		if len(ciemEdges) > 0 {
			if err := w.assets.IngestEdges(ctx, ciemEdges); err != nil {
				log.FromContext(ctx).Warn().Err(err).
					Int("edges", len(ciemEdges)).Msg("ciem: escalation edge ingest failed")
			} else {
				log.FromContext(ctx).Debug().
					Int("edges", len(ciemEdges)).Msg("ciem: escalation edges written")
			}
		}
	}

	// Run CSPM checks over what was collected and record the findings. A check
	// failure must not mask a successful collection, so it only sets runErr if
	// collection itself succeeded.
	if !skipped && runErr == nil {
		// CSPM checks run on changed/new assets by default. Unchanged
		// assets already have findings with enriched scores — re-recording with
		// Score=0 would overwrite them. The exception: if the check registry
		// changed (new checks deployed), run ALL assets so new checks backfill
		// immediately instead of waiting for assets to change naturally.
		// Provider-native findings (GuardDuty, GHAS, GCP SCC) are always included.
		checkTargets := res.Assets
		if changedAssetIDs != nil && !needBackfill {
			// Normal path: only run checks on changed assets.
			checkTargets = make([]asset.Asset, 0, len(changedAssetIDs))
			for _, a := range res.Assets {
				if changedAssetIDs[a.ID] {
					checkTargets = append(checkTargets, a)
				}
			}
		} else if needBackfill {
			log.FromContext(ctx).Info().
				Str("checks_fingerprint", checksFP).
				Str("connector_id", c.ID).
				Int("assets", len(res.Assets)).
				Msg("sync: check registry changed — running all assets for backfill")
		}
		// Publish how much of this connector's estate each check can actually
		// evaluate, over the FULL collected set rather than the changed-asset
		// subset — the question is what the check can see, not what moved.
		recordCheckEvaluability(w.metrics, c.ID, w.checks, res.Assets)
		now := time.Now()
		found := w.checks.Run(checkTargets, now)
		found = append(found, res.Findings...) // provider-native: GuardDuty, GHAS, etc.
		// CIEM privesc findings come from the unified engine, not the
		// check registry — scoped to the same changed-asset target set as CSPM.
		var ciemTargets map[string]bool
		if len(checkTargets) != len(res.Assets) {
			ciemTargets = make(map[string]bool, len(checkTargets))
			for _, a := range checkTargets {
				ciemTargets[a.ID] = true
			}
		}
		found = append(found, ciemFindings(ciemResult.Findings, ciemTargets, now)...)
		findingCount = len(found)
		if runErr = w.findings.RecordObserved(ctx, found); runErr == nil {
			// Only enqueue enrich if the queue isn't already backed up.
			// This prevents a sync wave (many connectors × N findings) from
			// flooding the enrich queue and competing with the sweep backstop.
			// If the enrich queue is full, the periodic enrich sweep picks these up.
			carrySuppressions(ctx, w.suppressions, found)
			enqueueEnrichIfCapacity(ctx, found)

			// Lifecycle reconcile: the checks just ran against
			// checkTargets — any stored open check finding on those resources
			// that was NOT re-emitted is fixed. Best-effort: a reconcile error
			// must not fail a successful sync; the next sweep retries.
			reconcileResolvedFindings(ctx, w.findings, w.checks, checkTargets, found, partial)
			if len(checkTargets) == len(res.Assets) {
				day = today // the full registry, time-dependent checks included, just ran on every asset
			}
		}
	}

	// Time-dependent checks (an end-of-life date compared to today) re-run on
	// every applicable asset once per UTC day — on a skipped sweep too, which
	// is exactly the stable fleet whose finding would otherwise never fire.
	if runErr == nil && day != today {
		ran := make(map[string]bool, len(changedAssetIDs))
		if !skipped {
			for id := range changedAssetIDs {
				ran[id] = true
			}
		}
		n, err := recheckTimeDependent(ctx, w.findings, w.findings, w.checks.TimeDependent(), res.Assets, ran, partial, time.Now())
		if err != nil {
			runErr = fmt.Errorf("Work: %w", err)
		} else {
			day = today
			findingCount += n
		}
	}

	// Provider-native findings are not derived from assets, so an unchanged
	// asset fingerprint says nothing about them: a new GuardDuty detection on a
	// stable account would otherwise never be recorded, and an un-archived one
	// would stay resolved. Record them on a no-change sweep too.
	if skipped && runErr == nil && len(res.Findings) > 0 {
		findingCount += len(res.Findings)
		if runErr = w.findings.RecordObserved(ctx, res.Findings); runErr == nil {
			enqueueEnrichIfCapacity(ctx, res.Findings)
		}
	}

	// Only after this sweep's findings are recorded: a finding the listing
	// returned must be stored as open before anything reasons about what the
	// listing did not return. Best-effort, like the reconcile above.
	if runErr == nil {
		reconcileGuardDutyFindings(ctx, w.findings, c.ID, res.CompletedEnumerations, res.Findings)
		reconcileProviderClosures(ctx, w.findings, c.ID, res.ClosedFindings, res.Findings)
	}

	// On a successful full ingest (not skipped), store the new fingerprint so the
	// next sweep can short-circuit if nothing changes again. Best-effort — a
	// fingerprint write failure must not fail a successful sync.
	// A skipped sweep writes it only to advance the re-check day.
	if runErr == nil && (!skipped || day != stored.day) {
		newFP := combineSyncFingerprint(syncFingerprint{assetFP: asset.ConnectorFingerprint(res.Assets), checksFP: checksFP, day: day})
		if err := w.connectors.UpdateSyncFingerprint(ctx, c.ID, newFP); err != nil {
			logger.Warn().Err(err).Str("connector_id", c.ID).
				Msg("sync: fingerprint update failed (next sweep will re-sync)")
		}
	}
	if runErr == nil {
		// Lifecycle reconciliation follows observations, including unchanged ones.
		// Content deduplication only skips checks and enrichment.
		if skipped {
			var err error
			currentHashes, err = w.connectors.GetAssetHashes(ctx, c.ID)
			if err != nil {
				currentHashes = nil
				logger.Warn().Err(err).Str("connector_id", c.ID).Msg("sync: lifecycle hash read failed; reconciliation will retry")
			}
		}
		// Update per-asset hashes in Postgres for changed assets. Best-effort.
		if len(toIngest) > 0 {
			entries := make([]connector.AssetHashEntry, len(toIngest))
			for i, a := range toIngest {
				entries[i] = connector.AssetHashEntry{
					AssetID:     a.ID,
					Hash:        asset.ContentHash(a),
					PubIP:       a.PublicIP,
					PubIPUnread: asset.PublicIPUnread(a),
					AssetName:   a.Name,
					AssetType:   a.Type,
					Region:      a.Region,
				}
			}
			if err := w.connectors.UpsertAssetHashEntries(ctx, c.ID, entries); err != nil {
				logger.Warn().Err(err).Str("connector_id", c.ID).Msg("sync: hash upsert failed")
			}
		}

		// Remove hashes for assets no longer returned by the collector (deleted in
		// cloud) and resolve their findings. ONLY on a COMPLETE collection: a
		// best-effort skip or partial listing (res.Partial) means an absent asset
		// may just be un-fetched this sweep, not deleted — pruning/resolving on
		// that would wrongly churn hashes and auto-resolve live findings.
		//
		// res.Partial is the outer guard; scope-awareness
		// (findDeletedAssets narrowing to (region, type) pairs a completed scope
		// this sweep proved it fully enumerated, collect.Result.
		// CompletedEnumerations) is an ADDITIONAL narrowing on top of it, not a
		// replacement — see findDeletedAssets' doc comment.
		covered := coveredScopes(res.CompletedEnumerations)
		decision := findDeletedAssets(currentHashes, res.Assets, covered)
		deletedIDs := decision.Deleted
		// candidatesKnown/deletionCandidates feed recordDeletionSignal, which
		// publishes graph_sync_deletion_candidates{completeness=...}. The value
		// differs by branch on purpose — see recordDeletionSignal's doc comment
		// for the full reasoning:
		//   - res.Partial: EVERY absent hash (decision.Considered) is refused
		//     by the outer partial gate regardless of type/scope, so the raw
		//     count IS the honest "refused" volume.
		//   - !res.Partial: only decision.Deleted was actually acted on;
		//     decision.Considered also counts rows this sweep intentionally
		//     left alone (untyped, uncovered, or over-cap-refused), so
		//     publishing it into the "complete"/acted bucket would overstate
		//     what happened. len(decision.Deleted) is what actually ran.
		deletionCandidates, candidatesKnown = decision.Considered, currentHashes != nil
		if !res.Partial {
			deletionCandidates = len(decision.Deleted)
			if len(deletedIDs) > 0 {
				applyDeletions(ctx, w.connectors, w.findings, c.ID, deletedIDs, start)
			}
			// A connector whose collector declares no scope that forget's audited
			// allow-list accepts (see coveredScopes; Azure, GitHub and Kubernetes
			// declare scopes, but none is on that list)
			// completes every sweep clean and yet reconciles nothing at all for
			// the affected types: covered==nil (or missing the right (region,
			// type) key) makes every candidate of that type "unscoped" forever.
			// That is the deliberate, safe interim state, but it must be VISIBLE
			// rather than silently inert — an operator watching only
			// deletion_candidates{completeness="complete"} drop to 0 for a whole
			// connector would otherwise have no explanation for it. untyped vs
			// uncovered are logged separately because they point at different
			// fixes: untyped means the collector stored the asset without a type,
			// uncovered means no scope has proven this (region, type) complete
			// THIS sweep (structural, until MarkComplete coverage grows).
			if decision.Considered > 0 && len(deletedIDs) < decision.Considered {
				logger.Info().Str("connector_id", c.ID).
					Int("candidates", decision.Considered).
					Int("untyped", decision.UnscopedNoType).
					Int("uncovered", decision.UnscopedUncovered).
					Int("accepted", len(deletedIDs)).
					Msg("sync: some deletion candidates suppressed — untyped means the collector stored no asset_type for that row, uncovered means no completed scope proved that (region, type) enumerated this sweep")
			}
			if decision.Refused > 0 {
				// ABSOLUTE REFUSAL, not a trim: acting on `deletionCap` of these
				// and reconsidering only the remainder next sweep would still
				// bound the worst case at deletionCap PER SWEEP, not per
				// incident — at any regular sync cadence that is unbounded over
				// time. Refusing the whole set keeps this sweep's action at
				// zero and makes the refusal itself, logged with both numbers,
				// the reviewable signal (see deletionCap's doc comment).
				logger.Warn().Str("connector_id", c.ID).
					Int("candidates", decision.Refused).Int("cap", deletionCap).
					Msg("sync: deletion candidates exceeded the per-sweep cap — refusing ALL of them this sweep (none pruned or resolved), reconsidered next sweep")
			}
		} else {
			logger.Info().Str("connector_id", c.ID).
				Int("deletion_candidates", decision.Considered).
				Int("completed_scopes", len(res.CompletedEnumerations)).
				Msg("sync: partial collection — skipping deletion reconciliation (absent≠deleted)")
		}

		if len(changedAssetIDs) > 0 {
			// Enqueue a partial correlate for changed assets so graph edges are
			// updated immediately rather than waiting for the next full sweep.
			// Cap at maxPartialCorrelateIDs: the LoadByIDs IN clause is interpolated
			// into the CH query string; with hundreds of long ARN/DNS IDs it hits
			// CH's max_query_size (256KB). Mass updates fall back to the full sweep.
			if len(changedAssetIDs) <= maxPartialCorrelateIDs {
				ids := make([]string, 0, len(changedAssetIDs))
				for id := range changedAssetIDs {
					ids = append(ids, id)
				}
				enqueuePartialCorrelate(ids)
			}

		}
	}

	// Observe-only (nothing is deleted or resolved off the back of this): publish
	// which collector scopes proved a complete enumeration this sweep, and how
	// much stored inventory the sweep would have judged deleted. Only on a
	// successful collection — a failed Collect's asset set is not a statement
	// about what exists.
	if runErr == nil {
		recordDeletionSignal(w.metrics, c.ID, res, deletionCandidates, candidatesKnown, time.Now())
		evaluateForget(ctx, w.forget, w.metrics, c.ID, res, start)
	}

	if recErr := recordSync(ctx, w.connectors, c.ID, runErr, cleanNoOp(runErr, skipped, partial, needBackfill), partial); recErr != nil {
		logger.Error().Err(recErr).Msg("record sync failed")
	}
	if runErr != nil {
		// A permanent failure (e.g. the hub can't assume this account's role)
		// will fail identically on every retry, so cancel instead of burning
		// attempts and worker slots.
		if errors.Is(runErr, collect.ErrPermanent) {
			return river.JobCancel(fmt.Errorf("Work: sync connector %s (permanent): %w", c.ID, runErr))
		}
		return fmt.Errorf("Work: sync connector %s: %w", c.ID, runErr)
	}
	logger.Info().Str("connector_id", c.ID).
		Int("assets", len(res.Assets)).Int("changed", changedAssets).Int("findings", findingCount).
		Bool("skipped", skipped).
		Dur("elapsed", time.Since(start)).
		Msg("connector synced")
	return nil
}

// writeAssetChangeLog computes per-field diffs for assets that existed and
// changed this sweep, and appends them to the asset change-log audit table.
// Best-effort: a failure here never affects the sync itself.
func (w *SyncWorker) writeAssetChangeLog(ctx context.Context, connectorID string, current []asset.Asset, changedExistingIDs []string) {
	if len(changedExistingIDs) == 0 {
		return
	}
	// Cap the diff work so a first-sync-style mass change doesn't issue a huge
	// ByIDs read; the timeline is observability, partial coverage is acceptable.
	if len(changedExistingIDs) > maxPartialCorrelateIDs {
		changedExistingIDs = changedExistingIDs[:maxPartialCorrelateIDs]
	}
	oldAssets, err := w.assets.ByIDs(ctx, changedExistingIDs)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("connector_id", connectorID).
			Msg("sync: change-log old-asset fetch failed")
		return
	}
	oldByID := make(map[string]asset.Asset, len(oldAssets))
	for _, a := range oldAssets {
		oldByID[a.ID] = a
	}
	newByID := make(map[string]asset.Asset, len(current))
	for _, a := range current {
		newByID[a.ID] = a
	}
	var changes []asset.FieldChange
	for _, id := range changedExistingIDs {
		old, ok := oldByID[id]
		next, ok2 := newByID[id]
		if !ok || !ok2 {
			continue
		}
		changes = append(changes, asset.DiffFields(old, next)...)
	}
	if err := w.assets.WriteChangeLog(ctx, connectorID, changes); err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("connector_id", connectorID).
			Msg("sync: change-log write failed")
	}
}

// stampProvenance records which connector produced each asset, in reserved
// prov_ metadata keys, so the reasoner can weigh an asset's origin.
// Done here at the single sync chokepoint — no collector needs to know its own
// connector, and the prov_ prefix keeps it clear of collector-set metadata.
func stampProvenance(assets []asset.Asset, c connector.Connector) {
	for i := range assets {
		if assets[i].Metadata == nil {
			assets[i].Metadata = map[string]string{}
		}
		assets[i].Metadata["prov_connector_id"] = c.ID
		assets[i].Metadata["prov_connector_type"] = string(c.Type)
	}
}

// restampLastSeen returns assets with LastSeen set to this sweep's clock, so
// "we saw it" is recorded for every collected asset rather than only the ones
// whose content changed.
//
// Liveness is last_seen, not row presence. The per-asset content diff writes
// ONLY changed assets, and asset.ContentHash deliberately excludes LastSeen —
// so without this, a stable, unchanging resource would never have its
// last_seen refreshed, and the column would quietly come to mean "last
// CHANGED" instead of "last observed". Every liveness gate, staleness report,
// and TTL that reads last_seen as "still exists" depends on it being
// refreshed every sweep regardless of whether the asset's content moved —
// stable, long-lived infrastructure is exactly what such a gap would misread
// as gone.
//
// The diff itself is untouched and still gates the expensive half — which
// assets get re-checked and re-enriched (changedAssetIDs). This only
// decouples "what we re-observe" from "what we re-evaluate"; the extra write
// is a ReplacingMergeTree insert that dedups on merge, the same trade already
// accepted for edges.
func restampLastSeen(assets []asset.Asset, now time.Time) []asset.Asset {
	out := make([]asset.Asset, len(assets))
	copy(out, assets)
	for i := range out {
		out[i].LastSeen = now
	}
	return out
}
