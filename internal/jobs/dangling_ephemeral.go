package jobs

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ephemeralLivenessSpec declares an EPHEMERAL asset type whose open findings are
// swept positively: for every finding under one of its checks, ask the asset
// store whether the resource is still live, and resolve the ones that are not.
//
// This is the type-scoped counterpart to resourceLifecycleSpec. Both the
// sync-time reconcile and the changed-asset diff only revisit resources that
// APPEAR in a diff, so a pod deleted between two collection sweeps never appears
// in one again and its findings become unreachable by any other path.
//
// Liveness is NOT redefined here. It is asset.EphemeralLivenessCond, applied in
// SQL by Assets.LiveIDs — the same condition that keeps dead pods out of the Ladybug
// load and the correlate LoadView. One definition, three consumers: a pod cannot
// be dead enough to drop from the graph but alive enough to keep its findings.
//
// The high-water anchor protects against TOTAL collection failure (the cutoff is
// one global max(last_seen) over the type, so a stopped collector freezes it and
// nothing further is judged gone) but NOT against PARTIAL collection: if some
// pods keep being re-stamped while others silently stop, the frozen-but-live ones
// can fall past the grace cliff and be resolved as resource_gone. Three things
// bound that damage: resolving is self-healing (the next check run re-emits the
// same deterministic finding ID, so the cost is an alert-state flap, not a
// permanent loss), the phase is rate-limited to a fixed share of
// danglingResolveMax per tick, and the grace window absorbs ordinary staleness. A
// real guard — refusing to sweep when a type's live fraction collapses — needs a
// per-connector collection-health baseline this domain doesn't have; a low live
// fraction is normal for ephemeral types, so a static floor would either fire
// constantly or never.
type ephemeralLivenessSpec struct {
	resourceType string
	// checkIDs scopes the paging: finding.Filter has no resource_type predicate,
	// so paging an entire source to find candidates of one type blows the query
	// deadline. It is the subset of the type's checks whose resource_id
	// precondition has been verified (see ephemeralLivenessSpecs), not every
	// check emitting on the type.
	checkIDs []string
	// phase is the obs sweep-phase label. k8s_pod deliberately keeps the existing
	// k8s_lifecycle label so dashboards and alerts built on it keep working.
	phase string
}

// ephemeralLivenessSpecs is the allowlist for the positive liveness sweep. Only
// asset.EphemeralTypes may appear here — for anything else, "not collected
// recently" means a slow or broken collector, not a deleted resource, and
// resolving on that basis would close findings on live infrastructure
// (TestEphemeralLivenessSpecs pins it).
//
// resource_id byte-equals the k8s_pod asset id for every check listed: all are
// generic-Check findings (internal/checks/checks.go eval: ResourceID: a.ID), and
// the k8s_pod asset id is deterministic from cluster/namespace/pod name
// (collect/kubernetes podAsset), so a rolling deployment's replacement pod never
// collides with the id of the one it replaced.
//
// This is the set of checks whose k8s_pod findings have had their resource_id
// precondition verified against real findings rather than by reading check
// source. Every other registered k8s_pod check (k8s-host-network-pod,
// k8s-dangerous-capabilities, k8s-container-allow-privilege-escalation,
// k8s-container-writable-root-fs, the seccomp/AppArmor/NET_RAW checks and the
// rest — TestEphemeralLivenessPodChecksAreLive lists them) stays off it until
// that is verified. No sweep closes their findings on a deleted pod: the sync
// deletion diff does not reconcile k8s_pod (it is not in forget's enforceable
// families), so those findings stay open until the findings TTL.
// k8s-host-network-pod and k8s-dangerous-capabilities in system namespaces are
// the exception, closed by staleStateSpecs.
var ephemeralLivenessSpecs = []ephemeralLivenessSpec{
	{
		resourceType: "k8s_pod",
		checkIDs: []string{
			"k8s-automount-sa-token",
			"k8s-image-latest-tag",
			"k8s-pod-no-resource-limits",
			"k8s-container-runs-as-root",
			"k8s-privileged-container",
		},
		phase: sweepPhaseK8sLifecycle,
	},
}

// ephemeralPhase runs the positive liveness sweep across every ephemeral spec,
// accumulating scanned/resolved into the caller's per-phase-label maps so each
// resource family stays separately measurable. It returns the phase totals.
//
// budget is this phase's RESERVED share of danglingResolveMax (ephemeralBudgetPct),
// not a budget of its own — giving it a full danglingResolveMax would multiply
// the blast radius of any misjudgement for a one-time drain that finishes either
// way. Fair share counts CHECKS, not specs, since one check can dominate a type's
// finding corpus and would otherwise starve every check behind it.
func (w *DanglingSweepWorker) ephemeralPhase(ctx context.Context, budget int, scannedByPhase, resolvedByPhase map[string]int) (scanned, resolved int, err error) {
	type target struct {
		checkID string
		spec    ephemeralLivenessSpec
	}
	var targets []target
	for _, spec := range ephemeralLivenessSpecs {
		for _, checkID := range spec.checkIDs {
			targets = append(targets, target{checkID, spec})
		}
	}
	for i, t := range targets {
		share := fairShare(budget, resolved, i, len(targets))
		if share == 0 {
			break
		}
		s, r, sweepErr := w.sweepEphemeralLiveness(ctx, t.spec, t.checkID, share)
		if sweepErr != nil {
			return scanned, resolved, fmt.Errorf("ephemeralPhase: %s: %w", t.checkID, sweepErr)
		}
		scannedByPhase[t.spec.phase] += s
		resolvedByPhase[t.spec.phase] += r
		scanned += s
		resolved += r
	}
	return scanned, resolved, nil
}

// sweepEphemeralLiveness pages the open findings of one ephemeral-type check
// oldest-first and resolves those whose resource is no longer live, until it
// resolves resolveBudget of them, hits the per-check scan ceiling, or exhausts
// the check. Returns findings examined and findings resolved.
//
// Liveness comes entirely from Assets.LiveIDs (asset.EphemeralLivenessCond) —
// this function deliberately owns no staleness arithmetic of its own, so it
// cannot drift from the definition the graph load uses.
func (w *DanglingSweepWorker) sweepEphemeralLiveness(ctx context.Context, spec ephemeralLivenessSpec, checkID string, resolveBudget int) (scanned, resolved int, err error) {
	// Fail-safe: with no assets of this type at all there is no high-water mark,
	// so nothing can be judged gone. Without this, an empty (or newly provisioned,
	// or wiped) assets table would make every finding look like it points at a
	// corpse and resolve the lot.
	highWater, err := w.assets.TypeHighWater(ctx, spec.resourceType)
	if err != nil {
		return 0, 0, fmt.Errorf("type high water: %w", err)
	}
	if highWater.IsZero() {
		return 0, 0, nil
	}
	// Bound the candidate set the same way the resource-lifecycle sweep does: a
	// finding detected inside the grace window cannot yet be judged gone (its pod
	// is still within EphemeralLivenessCond's grace), and paging oldest-first puts
	// the deep backlog under the scan ceiling instead of re-reading the newest
	// findings — on live pods — forever.
	cutoff := highWater.Add(-resourceGoneGrace)

	f := finding.Filter{
		CheckID:        checkID,
		Limit:          danglingPageSize,
		DetectedBefore: cutoff,
		OldestFirst:    true,
	}
	var cursor string
	for scanned < danglingScanMax && resolved < resolveBudget {
		f.Cursor = cursor
		batch, listErr := w.findings.List(ctx, f)
		if listErr != nil {
			return scanned, resolved, fmt.Errorf("list (cursor=%q): %w", cursor, listErr)
		}
		if len(batch) == 0 {
			break
		}
		scanned += len(batch)

		// Candidates: the spec's resource_type with a non-empty resource_id only —
		// the SAFETY note in danglingJoinSpecs applies here too.
		var candidates []finding.Finding
		var ids []string
		seen := map[string]bool{}
		for _, fnd := range batch {
			if fnd.ResourceID == "" || fnd.ResourceType != spec.resourceType {
				continue
			}
			candidates = append(candidates, fnd)
			if !seen[fnd.ResourceID] {
				seen[fnd.ResourceID] = true
				ids = append(ids, fnd.ResourceID)
			}
		}

		if len(candidates) > 0 {
			liveIDs, liveErr := w.assets.LiveIDs(ctx, ids)
			if liveErr != nil {
				return scanned, resolved, fmt.Errorf("live ids: %w", liveErr)
			}
			live := make(map[string]bool, len(liveIDs))
			for _, id := range liveIDs {
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
				if resErr := w.findings.Resolve(ctx, orphans, finding.ReasonResourceGone); resErr != nil {
					return scanned, resolved, fmt.Errorf("resolve %d: %w", len(orphans), resErr)
				}
				resolved += len(orphans)
			}
		}

		if len(batch) < danglingPageSize {
			break // last page for this check
		}
		cursor = finding.EncodeCursor(batch[len(batch)-1], false)
	}
	if scanned >= danglingScanMax && resolved < resolveBudget {
		log.FromContext(ctx).Warn().
			Str("check_id", checkID).Str("resource_type", spec.resourceType).Int("scanned", scanned).
			Msg("ephemeral liveness sweep hit per-check scan ceiling — check not fully swept this tick")
	}
	return scanned, resolved, nil
}
