package jobs

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// The dangling-finding sweep is the complement to the sync-time
// resolution: that path resolves a finding when its emitting check re-runs on a
// still-present resource and no longer reports it, or when a connector's
// hash-diff detects the resource was deleted; for GuardDuty and SCC,
// closeUnlistedFindings also closes findings a complete listing stopped
// returning (ReasonProviderClosed), and GHAS findings close when GitHub reports
// the alert closed (reconcileProviderClosures). None of these revisits a resource that was
// gone before the finding lifecycle shipped, and a provider feed that still
// lists a finding on a deleted resource is never diffed against inventory — so
// findings on long-deleted resources dangle until the 365-day TTL. This sweep pages open
// findings, asks the asset store which of their resource_ids still have a live
// asset row, and auto-resolves those with none.
//
// SAFETY — the join key must be exact. A finding is resolved ONLY when its
// resource_id is byte-identical to an asset id, so "no asset row" truly means
// "resource gone" and not "different id scheme". That correspondence is NOT
// universal: GuardDuty's iam_user findings carry the user NAME while iam_user
// assets are keyed by ARN, so name-vs-ARN would never match and would wrongly
// resolve every one. Only the (source, resource_type) pairs proven 1:1 are swept
// (danglingJoinSpecs); everything else is left for the 365d TTL / a future,
// verified spec rather than resolved on a guess.

const (
	// danglingPageSize is the finding.List page size for the sweep.
	danglingPageSize = finding.DefaultLimit

	// danglingResolveMax caps findings auto-resolved per tick — the drain rate and
	// the ClickHouse write bound. The backlog can be sizeable (e.g. GuardDuty
	// threats on deleted EC2 instances); 3000/tick × hourly drains it in
	// about a day, then no-ops down to whatever the deletion path missed since.
	danglingResolveMax = 3000

	// danglingScanMax is a per-source, per-tick ceiling on findings EXAMINED — a
	// safety valve so a source that unexpectedly balloons can't make one tick
	// scan-storm ClickHouse. In normal operation a candidate source is drained
	// (orphans vastly outnumber live findings in it), so a tick reaches
	// danglingResolveMax long before this. Hitting it is logged as a warning.
	danglingScanMax = 25000

	// resourceGoneGrace is how far behind its provider's high-water mark an asset's
	// last_seen must fall before its findings are treated as belonging to a resource
	// that no longer exists. Generous on purpose: a pod missed by one or two
	// collection ticks (a throttled list, a partial sweep) must never be resolved
	// as gone, and a resolved finding that was actually live simply reappears on
	// the next check run — but only after a needless alert-state flap, so the
	// conservative side is the right one.
	resourceGoneGrace = 72 * time.Hour
)

// danglingJoinSpec declares a finding source and the resource_types within it
// whose resource_id equals an asset id 1:1. Only these are swept — see the
// SAFETY note above.
type danglingJoinSpec struct {
	source        string
	resourceTypes map[string]bool
}

// danglingJoinSpecs is the allowlist of asset-joinable (source, resource_type)
// pairs. Conservative on purpose: adding a source requires verifying its
// collector sets resource_id to the exact asset id for that type.
//
//   - aws_guardduty / ec2_instance: resource_id is the EC2 instance id, which is
//     the ec2_instance asset id (collectInstances). 1:1. Dominant orphan class.
//   - aws_guardduty / s3_bucket: resource_id is the bucket name, which is the
//     s3_bucket asset id (globally unique). 1:1.
//
// Deliberately excluded (resource_id is NOT the asset id, or coverage is
// uncertain — left to the 365d TTL until verified):
//   - aws_guardduty / iam_user: resource_id is the user NAME; asset id is the ARN.
//   - aws_guardduty fallback types (AccessKey, Instance, …): resource_id is a
//     generic GuardDuty resource-type label, not any asset id.
//   - gcp_scc: resource_id is a "project/instance" path or the raw SCC resource
//     name; its correspondence to the gce_instance asset id is unverified.
//   - ghas_secrets / ghas_code_scanning / iac: resource_id is the repo FullName
//     (which IS the github_repo asset id), but GitHub asset collection can be
//     rate-limit starved, so a missing repo asset does not reliably mean deletion.
//     GHAS findings close when GitHub reports the alert closed
//     (reconcileProviderClosures), and on a repo a complete repo listing stops
//     returning through sync-time deletion, not here.
//   - cspm: sync-time reconciliation (sync_deletion_scope.go's findDeletedAssets)
//     only resolves a resource-deletion finding when the asset's stored
//     (region, type) was proven fully enumerated by a completed scope this
//     sweep, gated through internal/app/forget's audited scope grammar and
//     limited to the families in forget's enforceableFamilies allow-list. Every
//     other collector/type does not get sync-time resolution and dangles here
//     until the allow-list grows or the TTL expires. cspm is deliberately NOT
//     added below regardless: resource_id↔asset_id 1:1 correspondence across
//     cspm's many resource_types has not been separately audited the way
//     aws_guardduty's was, and widening coverage here is a distinct decision
//     from the sync-time gate. The one exception already handled outside this
//     allowlist is k8s_pod lifecycle churn (rolling deployments replacing pod
//     names), which no absence-based mechanism can see — that gets its own
//     checkID-scoped lifecycle sweep, resourceLifecycleSpecs, below.
var danglingJoinSpecs = []danglingJoinSpec{
	{source: "aws_guardduty", resourceTypes: map[string]bool{
		"ec2_instance": true,
		"s3_bucket":    true,
	}},
}

// staleStateSpec declares a finding source/resource_type whose CURRENT asset
// metadata (not its absence) proves the finding is stale — e.g. an EC2 check
// finding on an instance that is now terminated. This is a DIFFERENT signal
// than danglingJoinSpecs (no asset row at all): the asset row still exists
// (terminated instances linger for a time), but its state makes the finding
// moot. Needed because the sync-time deletion diff only detects a resource as
// gone when its content hash was previously cached, so a resource that stopped
// changing before the hash cache caught up to it is invisible to that diff and
// never resolves through it.
type staleStateSpec struct {
	// checkIDs, not source: "cspm" spans the findings of every check, and CH's
	// finding.List has no resource_type filter — paging the whole source looking for ec2_instance candidates blew the 10s
	// query deadline (context deadline exceeded / i/o timeout). Filter.CheckID is
	// an exact match and drops the scan to just these checks' findings, the same
	// order of magnitude as the aws_guardduty existence-check sweep.
	checkIDs      []string
	resourceTypes map[string]bool
	stateKey      string            // asset.Metadata key the predicate reads
	isStale       func(string) bool // reports whether that metadata value makes findings on it moot
}

// staleStateSpecs is the allowlist for the asset-state sweep, deliberately
// narrow like danglingJoinSpecs — only checks whose predicate is entirely
// superseded by the resource's current metadata. Keep in sync with
// internal/checks' check logic.
var staleStateSpecs = []staleStateSpec{
	{
		// EC2 instance checks: terminated/shutting-down instances can never
		// legitimately violate again (sync-time reconcile only revisits CHANGED
		// resources — and a long-terminated instance stops changing).
		checkIDs:      []string{"aws-ec2-public-ip", "aws-ec2-no-iam-role", "aws-ec2-imdsv2-not-required"},
		resourceTypes: map[string]bool{"ec2_instance": true},
		stateKey:      "state",
		isStale: func(v string) bool {
			return v == "terminated" || v == "shutting-down"
		},
	},
	{
		// The pod-security checks that exempt system namespaces via isK8sSystemPod
		// (checks.hygiene.go): k8s-host-network-pod, k8s-privileged-container,
		// k8s-dangerous-capabilities. The exemption is an in-code predicate change,
		// not a check-ID change — the registry-fingerprint backfill can't see it,
		// so pre-exemption findings on system-namespace pods (CNI/CSI/security agents/etc.,
		// privileged by necessity) never naturally re-resolve on a stable pod and
		// linger as open noise. This sweep resolves them directly. (isStale reads
		// the static namespace list only; the PSA-enforce=privileged path in
		// isK8sSystemPod is not covered here, and the sync deletion diff does
		// not reconcile k8s_pod either — see ephemeralLivenessSpecs.)
		checkIDs:      []string{"k8s-host-network-pod", "k8s-privileged-container", "k8s-dangerous-capabilities"},
		resourceTypes: map[string]bool{"k8s_pod": true},
		stateKey:      "namespace",
		isStale:       checks.IsK8sSystemNamespace,
	},
}

// DanglingSweepArgs is the periodic tick that auto-resolves open findings whose
// resource no longer has an asset row.
type DanglingSweepArgs struct{}

func (DanglingSweepArgs) Kind() string { return "dangling_sweep" }

// MaxAttempts 2, not River's library default of 25: this sweep re-derives its
// whole work set every hourly tick, so one retry absorbs a genuine transient
// blip — past that it should surface via recordSweepPhase rather than restart
// the entire monolithic sweep from scratch for up to 25 attempts, adding load
// to ClickHouse while it's already contended.
func (DanglingSweepArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueDangling, 2)
}

// danglingRetryMinDelay/danglingRetryMaxDelay bound the gap NextRetry (below)
// puts between attempt 1 and attempt 2.
const (
	danglingRetryMinDelay = 20 * time.Second
	danglingRetryMaxDelay = 45 * time.Second
)

// NextRetry overrides River's default retry policy (errorCount^4 seconds),
// which would schedule attempt 2 about 1s after the first failure — far too
// short against the ClickHouse contention windows (tens of seconds, shared
// with correlate sweeps) that actually kill attempt 1, since a ~1s gap lands
// the retry right back inside the same window it likely just failed in. This
// override's floor just needs to clear that contention window.
//
// 20-45s, randomized rather than fixed, so a retry can't itself become a
// synchronized re-collision: a fixed delay would have every dangling_sweep
// retry in a bad tick re-fire at the identical offset, which if it lined up
// with a periodic correlate sweep's own cadence would recreate exactly the
// contention it's trying to dodge, tick after tick.
func (DanglingSweepWorker) NextRetry(_ *river.Job[DanglingSweepArgs]) time.Time {
	delay := danglingRetryMinDelay + rand.N(danglingRetryMaxDelay-danglingRetryMinDelay)
	return time.Now().Add(delay)
}

// danglingFindingStore is the slice of the finding service the sweep needs.
type danglingFindingStore interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
	Resolve(ctx context.Context, findings []finding.Finding, reason finding.ResolutionReason) error
}

// assetExistence reports which of a batch of ids still have an asset row, and
// fetches full asset rows (for metadata-based staleness) by id. *asset.Service
// implements it.
type assetExistence interface {
	ExistingIDs(ctx context.Context, ids []string) ([]string, error)
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
	ProviderHighWater(ctx context.Context, provider string) (time.Time, error)
	// LiveIDs applies asset.EphemeralLivenessCond — the single definition of "this
	// ephemeral resource still exists" shared with the graph load.
	LiveIDs(ctx context.Context, ids []string) ([]string, error)
	// TypeHighWater is the fail-safe guard for the ephemeral sweep: zero means the
	// type has no assets at all, so there is no basis on which to judge anything gone.
	TypeHighWater(ctx context.Context, assetType string) (time.Time, error)
}

// lifecycleBudgetFor is the resource-lifecycle phase's share of a tick budget: what
// is left after the dangling and stale-state phases take their reserved cuts.
// Exported to the package so tests size a backlog against the REAL split instead
// of hard-coding a number that silently drifts when the percentages change.
func lifecycleBudgetFor(tickBudget int) int {
	return tickBudget -
		tickBudget*danglingBudgetPct/100 -
		tickBudget*staleBudgetPct/100 -
		tickBudget*ephemeralBudgetPct/100
}

// fairShare returns the resolve budget for the i-th of n specs in a sweep phase,
// given how much of that phase's budget is already spent. Dividing what remains
// by the number of specs STILL TO RUN (not the total) means a spec that drains
// early donates its unused share to the ones after it, while a spec with a deep
// backlog can never take the whole phase budget and starve its siblings — the
// first spec in a phase would otherwise take the entire budget every tick and
// every later spec would resolve nothing, forever.
//
// Returns 0 only when the phase budget is exhausted, so a caller can treat 0 as
// "stop". Never returns 0 for a spec that still has budget available: handing out
// a zero budget would silently skip that spec.
func fairShare(budget, spent, i, n int) int {
	remaining := budget - spent
	if remaining <= 0 || i >= n {
		return 0
	}
	if share := remaining / (n - i); share > 0 {
		return share
	}
	return 1
}

// DanglingSweepWorker resolves findings whose resource is gone. It runs the whole
// job inline (list → existence check → resolve) rather than fanning out per
// finding: resolution is a cheap batch ClickHouse rewrite, so a per-finding job
// per orphan would be pure overhead.
type DanglingSweepWorker struct {
	river.WorkerDefaults[DanglingSweepArgs]
	findings danglingFindingStore
	assets   assetExistence
	metrics  *obs.Metrics
}

// Budget shares for the sweep phases. Weighted, not an even split: the
// GuardDuty existence-check phase is the only one fighting an active arrival
// rate, so it gets the largest guaranteed share with headroom above that rate;
// stale-state checks only need to keep up with new occurrences; ephemeral
// liveness covers the highest-churn resource types.
const (
	danglingBudgetPct  = 50 // GuardDuty existence-check — must clear the arrival rate
	staleBudgetPct     = 15 // EC2 terminated/shutting-down + k8s-host-network-pod
	ephemeralBudgetPct = 25 // ephemeral-liveness sweep
	// The resource-lifecycle phase takes what is left (10%); it covers GCE only,
	// since the ephemeral phase owns k8s pods.
)

// Timeout overrides River's 1-minute default. Each phase paginates up to its
// budget share of danglingScanMax findings; on a high-volume check that's
// dozens of List()/ExistingIDs() calls in one job execution, and the
// cumulative time across enough pages under concurrent CH load can exceed a
// minute even when each individual query is fast — the same failure class
// EnrichSweepWorker.Timeout documents.
func (DanglingSweepWorker) Timeout(_ *river.Job[DanglingSweepArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *DanglingSweepWorker) Work(ctx context.Context, _ *river.Job[DanglingSweepArgs]) error {
	// Each phase gets a RESERVED slice of the per-tick budget — not a shared
	// pool consumed first-come. Without this, a large existence-check backlog
	// starves the other phases indefinitely: they never even get a turn until
	// the dominant phase's backlog drains below the cap.
	danglingBudget := danglingResolveMax * danglingBudgetPct / 100
	staleBudget := danglingResolveMax * staleBudgetPct / 100
	lifecycleBudget := lifecycleBudgetFor(danglingResolveMax)

	var scanned, resolved int
	for i, spec := range danglingJoinSpecs {
		share := fairShare(danglingBudget, resolved, i, len(danglingJoinSpecs))
		if share == 0 {
			break
		}
		s, r, err := w.sweepSource(ctx, spec, share)
		if err != nil {
			return fmt.Errorf("Work: source %s: %w", spec.source, err)
		}
		scanned += s
		resolved += r
	}
	// Flattened so fair-share counts CHECKS, not specs: staleStateSpecs nests
	// checkIDs inside a spec, and sharing by spec would still let the first
	// checkID of a multi-check spec starve its siblings.
	var staleScanned, staleResolved int
	type staleTarget struct {
		checkID string
		spec    staleStateSpec
	}
	var staleTargets []staleTarget
	for _, spec := range staleStateSpecs {
		for _, checkID := range spec.checkIDs {
			staleTargets = append(staleTargets, staleTarget{checkID, spec})
		}
	}
	for i, t := range staleTargets {
		share := fairShare(staleBudget, staleResolved, i, len(staleTargets))
		if share == 0 {
			break
		}
		s, r, err := w.sweepStaleState(ctx, t.checkID, t.spec, share)
		if err != nil {
			return fmt.Errorf("Work: stale-state %s: %w", t.checkID, err)
		}
		staleScanned += s
		staleResolved += r
	}
	// Lifecycle phase: one budget shared fairly across every churning-resource spec
	// regardless of provider, but scanned/resolved accumulated PER PHASE LABEL so
	// k8s pod churn and GCE instance churn stay separately measurable — adding a
	// resource family must not silently change what an existing alert is watching.
	var lifecycleScanned, lifecycleResolved int
	scannedByPhase := map[string]int{}
	resolvedByPhase := map[string]int{}
	for i, spec := range resourceLifecycleSpecs {
		share := fairShare(lifecycleBudget, lifecycleResolved, i, len(resourceLifecycleSpecs))
		if share == 0 {
			break
		}
		s, r, err := w.sweepResourceLifecycle(ctx, spec, share)
		if err != nil {
			return fmt.Errorf("Work: resource lifecycle %s: %w", spec.checkID, err)
		}
		scannedByPhase[spec.phase] += s
		resolvedByPhase[spec.phase] += r
		lifecycleScanned += s
		lifecycleResolved += r
	}

	// Ephemeral-liveness phase: the positive sweep over ephemeral resource types
	// (dangling_ephemeral.go). A RESERVED share of the same per-tick budget as the
	// other standing phases, not a budget of its own — see ephemeralPhase.
	ephemeralScanned, ephemeralResolved, err := w.ephemeralPhase(ctx,
		danglingResolveMax*ephemeralBudgetPct/100, scannedByPhase, resolvedByPhase)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}

	log.FromContext(ctx).Info().
		Int("scanned", scanned).Int("resolved", resolved).
		Int("stale_state_scanned", staleScanned).Int("stale_state_resolved", staleResolved).
		Int("k8s_lifecycle_scanned", scannedByPhase[sweepPhaseK8sLifecycle]).
		Int("k8s_lifecycle_resolved", resolvedByPhase[sweepPhaseK8sLifecycle]).
		Int("gce_lifecycle_scanned", scannedByPhase[sweepPhaseGCELifecycle]).
		Int("gce_lifecycle_resolved", resolvedByPhase[sweepPhaseGCELifecycle]).
		Int("ephemeral_scanned", ephemeralScanned).Int("ephemeral_resolved", ephemeralResolved).
		Msg("dangling sweep complete")

	// Sweep-effectiveness metrics (see dangling_obs.go): scanned is recorded
	// even when resolved is zero — "resolved: 0 against a huge backlog" is
	// exactly the failure mode that otherwise runs silent (an observability
	// gap). recordSweepPhase stamps last-resolved only when resolved > 0, so a
	// stuck phase shows a stale (non-advancing) timestamp instead of a fresh one.
	recordSweepPhase(w.metrics, sweepPhaseDangling, scanned, resolved)
	recordSweepPhase(w.metrics, sweepPhaseStaleState, staleScanned, staleResolved)
	recordSweepPhase(w.metrics, sweepPhaseK8sLifecycle, scannedByPhase[sweepPhaseK8sLifecycle], resolvedByPhase[sweepPhaseK8sLifecycle])
	recordSweepPhase(w.metrics, sweepPhaseGCELifecycle, scannedByPhase[sweepPhaseGCELifecycle], resolvedByPhase[sweepPhaseGCELifecycle])

	return nil
}

// sweepSource pages the open findings of one source OLDEST-first, resolving
// those whose resource has no asset row, until it resolves resolveBudget of
// them, hits the per-source scan ceiling, or exhausts the source. Returns
// findings examined and findings resolved.
//
// Must page oldest-first, not newest-first: if a source's open-but-live volume
// near the head is itself bigger than the per-tick scan/resolve budget, a
// newest-first cursor that resets every tick re-examines the same live slice
// forever and never advances into the actual backlog sitting further back
// (sweepResourceLifecycle pages oldest-first for the same reason). Unlike
// sweepResourceLifecycle there is no time-based cutoff here — this is a pure
// existence check via ExistingIDs, not a staleness comparison — so oldest-first
// paging alone is sufficient: each tick's progress naturally shrinks what
// oldest-first sees next tick.
func (w *DanglingSweepWorker) sweepSource(ctx context.Context, spec danglingJoinSpec, resolveBudget int) (scanned, resolved int, err error) {
	f := finding.Filter{Source: spec.source, Limit: danglingPageSize, OldestFirst: true}
	var cursor string
	for scanned < danglingScanMax && resolved < resolveBudget {
		f.Cursor = cursor
		batch, err := w.findings.List(ctx, f)
		if err != nil {
			return scanned, resolved, fmt.Errorf("list (cursor=%q): %w", cursor, err)
		}
		if len(batch) == 0 {
			break
		}
		scanned += len(batch)

		// Candidates: joinable resource_type + non-empty resource_id only. Anything
		// else is skipped — never resolved — because its id can't be trusted against
		// the asset store (the SAFETY note).
		var candidates []finding.Finding
		var ids []string
		seen := map[string]bool{}
		for _, fnd := range batch {
			if fnd.ResourceID == "" || !spec.resourceTypes[fnd.ResourceType] {
				continue
			}
			candidates = append(candidates, fnd)
			if !seen[fnd.ResourceID] {
				seen[fnd.ResourceID] = true
				ids = append(ids, fnd.ResourceID)
			}
		}

		if len(candidates) > 0 {
			existing, err := w.assets.ExistingIDs(ctx, ids)
			if err != nil {
				return scanned, resolved, fmt.Errorf("existing ids: %w", err)
			}
			live := make(map[string]bool, len(existing))
			for _, id := range existing {
				live[id] = true
			}
			var orphans []finding.Finding
			for _, fnd := range candidates {
				if !live[fnd.ResourceID] {
					orphans = append(orphans, fnd)
				}
			}
			if remaining := resolveBudget - resolved; len(orphans) > remaining {
				orphans = orphans[:remaining] // honour the resolve budget exactly
			}
			if len(orphans) > 0 {
				if err := w.findings.Resolve(ctx, orphans, finding.ReasonResourceGone); err != nil {
					return scanned, resolved, fmt.Errorf("resolve %d: %w", len(orphans), err)
				}
				resolved += len(orphans)
			}
		}

		if len(batch) < danglingPageSize {
			break // last page for this source
		}
		cursor = finding.EncodeCursor(batch[len(batch)-1], false)
	}
	if scanned >= danglingScanMax && resolved < resolveBudget {
		log.FromContext(ctx).Warn().
			Str("source", spec.source).Int("scanned", scanned).
			Msg("dangling sweep hit per-source scan ceiling — source not fully swept this tick")
	}
	return scanned, resolved, nil
}

// sweepStaleState pages the open findings of one check_id OLDEST-first,
// resolving those whose resource's CURRENT metadata[spec.stateKey] satisfies
// spec.isStale (the asset row still exists — this is a state check, not an
// existence check; see staleStateSpec) — until it resolves resolveBudget of
// them, hits the per-check scan ceiling, or exhausts the check. Returns
// examined and resolved.
//
// Same fix, same reasoning, as sweepSource's doc comment: newest-first with a
// per-tick-reset cursor means a check whose live-state volume near the head
// alone exceeds the per-tick budget can starve its own deeper backlog
// forever. No time cutoff is needed here either — spec.isStale reads current
// metadata, not staleness-vs-time.
func (w *DanglingSweepWorker) sweepStaleState(ctx context.Context, checkID string, spec staleStateSpec, resolveBudget int) (scanned, resolved int, err error) {
	f := finding.Filter{CheckID: checkID, Limit: danglingPageSize, OldestFirst: true}
	var cursor string
	for scanned < danglingScanMax && resolved < resolveBudget {
		f.Cursor = cursor
		batch, err := w.findings.List(ctx, f)
		if err != nil {
			return scanned, resolved, fmt.Errorf("list (cursor=%q): %w", cursor, err)
		}
		if len(batch) == 0 {
			break
		}
		scanned += len(batch)

		var candidates []finding.Finding
		var ids []string
		seen := map[string]bool{}
		for _, fnd := range batch {
			if fnd.ResourceID == "" || !spec.resourceTypes[fnd.ResourceType] {
				continue
			}
			candidates = append(candidates, fnd)
			if !seen[fnd.ResourceID] {
				seen[fnd.ResourceID] = true
				ids = append(ids, fnd.ResourceID)
			}
		}

		if len(candidates) > 0 {
			assets, err := w.assets.ByIDs(ctx, ids)
			if err != nil {
				return scanned, resolved, fmt.Errorf("by ids: %w", err)
			}
			stale := make(map[string]bool, len(assets))
			for _, a := range assets {
				if spec.isStale(a.Metadata[spec.stateKey]) {
					stale[a.ID] = true
				}
			}
			var moot []finding.Finding
			for _, fnd := range candidates {
				if stale[fnd.ResourceID] {
					moot = append(moot, fnd)
				}
			}
			if remaining := resolveBudget - resolved; len(moot) > remaining {
				moot = moot[:remaining] // honour the resolve budget exactly
			}
			if len(moot) > 0 {
				if err := w.findings.Resolve(ctx, moot, finding.ReasonResourceGone); err != nil {
					return scanned, resolved, fmt.Errorf("resolve %d: %w", len(moot), err)
				}
				resolved += len(moot)
			}
		}

		if len(batch) < danglingPageSize {
			break // last page for this source
		}
		cursor = finding.EncodeCursor(batch[len(batch)-1], false)
	}
	if scanned >= danglingScanMax && resolved < resolveBudget {
		log.FromContext(ctx).Warn().
			Str("check_id", checkID).Int("scanned", scanned).
			Msg("stale-state sweep hit per-check scan ceiling — check not fully swept this tick")
	}
	return scanned, resolved, nil
}
