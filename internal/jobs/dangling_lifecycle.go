package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// The resource lifecycle phase of the dangling sweep (DanglingSweepWorker):
// findings on churning resources whose asset row is stale rather than absent.

// resourceLifecycleSpec declares one CSPM check_id whose findings on churning
// resources should be liveness-checked against the asset store (not seen since
// the provider's staleness cutoff = resource gone), scoped by checkID rather
// than source. "cspm" spans the findings of every check, with no resource_type
// filter in finding.List, so paging the whole source for candidates blows the
// 10s query deadline — the same reason staleStateSpecs is scoped by checkID.
// checkID scoping keeps this sweep's cost in line with the checks it covers.
type resourceLifecycleSpec struct {
	checkID      string
	resourceType string
	// provider anchors the staleness cutoff to THAT provider's own high-water mark,
	// never wall-clock and never another provider's. A provider-wide outage
	// freezes the mark and nothing further is judged gone. The mark is per
	// provider, not per connector: with several connectors of one provider (two
	// GCP projects), a healthy one keeps the mark moving, so a single broken
	// connector's resources ARE judged gone after resourceGoneGrace.
	provider asset.Provider
	// phase is the obs sweep-phase label. Distinct per resource family so a
	// dashboard can tell k8s pod churn from GCE instance churn, and so adding a
	// family cannot silently change what an existing alert is measuring.
	phase string
}

// resourceLifecycleSpecs is the allowlist for the resource lifecycle sweep.
// resource_id byte-equals the target asset id for every check listed: all are
// generic-Check findings (internal/checks/checks.go eval: ResourceID: a.ID),
// and each asset id is deterministic from stable identifying fields, so a
// replacement resource's id never collides with the one it replaced.
// k8s_pod is deliberately NOT covered here — the ephemeral-liveness phase
// below owns the whole type and reports under the same k8s_lifecycle metric
// label, since checkID-scoped coverage here would only reach a fraction of the
// checks that actually emit pod findings.
var resourceLifecycleSpecs = []resourceLifecycleSpec{
	// GCE instances churn like k8s pods and for the same reasons: managed
	// instance groups, autoscalers, and scheduled CI jobs replace instances
	// under new names and tear the old one down shortly after the scan that
	// found it. The check then re-runs against the new instance and never
	// revisits the gone one, so the asset row (stale, not absent) never trips
	// the existence-based specs above.
	{checkID: "gcp-gce-no-oslogin", resourceType: "gce_instance",
		provider: asset.ProviderGCP, phase: sweepPhaseGCELifecycle},
	{checkID: "gcp-gce-project-ssh-keys", resourceType: "gce_instance",
		provider: asset.ProviderGCP, phase: sweepPhaseGCELifecycle},
	{checkID: "gcp-gce-public-ip", resourceType: "gce_instance",
		provider: asset.ProviderGCP, phase: sweepPhaseGCELifecycle},
	{checkID: "gcp-gce-default-sa", resourceType: "gce_instance",
		provider: asset.ProviderGCP, phase: sweepPhaseGCELifecycle},
}

// sweepResourceLifecycle pages the open findings of one check_id detected
// before the provider's staleness cutoff, oldest-first, resolving those whose
// resource (spec.resourceType) has not been seen since that cutoff —
// checkID-scoped like sweepStaleState instead of source-scoped like sweepSource
// (see resourceLifecycleSpec) — until it resolves resolveBudget of them, hits
// the per-check scan ceiling, or exhausts the check. Returns examined and
// resolved.
func (w *DanglingSweepWorker) sweepResourceLifecycle(ctx context.Context, spec resourceLifecycleSpec, resolveBudget int) (scanned, resolved int, err error) {
	// Anchor staleness to the provider's own high-water mark, never to wall clock.
	// A provider-wide outage freezes the cutoff; one broken connector among
	// several of the same provider does not (see resourceLifecycleSpec.provider).
	highWater, err := w.assets.ProviderHighWater(ctx, string(spec.provider))
	if err != nil {
		return 0, 0, fmt.Errorf("provider high water: %w", err)
	}
	if highWater.IsZero() {
		return 0, 0, nil // no assets for this provider at all — nothing to reason about
	}
	cutoff := highWater.Add(-resourceGoneGrace)

	// Page findings DETECTED BEFORE the cutoff, oldest first. Both halves matter.
	// Paging newest-first from a cursor that resets every tick, with a per-check
	// ceiling of danglingScanMax, re-examines the same newest findings forever —
	// all of them on live resources — and resolves nothing while the real backlog
	// sits deeper than the ceiling can reach: a large scanned count with zero
	// resolutions.
	f := finding.Filter{
		CheckID:        spec.checkID,
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

		// Candidates: joinable resource_type + non-empty resource_id only (the
		// SAFETY note in danglingJoinSpecs applies here too).
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
			// Liveness is last_seen, NOT row presence. Asset rows are never deleted
			// from the ReplacingMergeTree, so ExistingIDs returns a resource that
			// vanished months ago as though it were live, and the sweep could never
			// resolve a single finding no matter how far it paged.
			assets, byIDErr := w.assets.ByIDs(ctx, ids)
			if byIDErr != nil {
				return scanned, resolved, fmt.Errorf("by ids: %w", byIDErr)
			}
			lastSeen := make(map[string]time.Time, len(assets))
			for _, a := range assets {
				lastSeen[a.ID] = a.LastSeen
			}
			var orphans []finding.Finding
			for _, fnd := range candidates {
				seenAt, known := lastSeen[fnd.ResourceID]
				// Unknown id = the row really is absent — still gone. Known but not
				// seen since the cutoff = gone.
				if !known || seenAt.Before(cutoff) {
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
			Str("check_id", spec.checkID).Int("scanned", scanned).
			Msg("resource lifecycle sweep hit per-check scan ceiling — check not fully swept this tick")
	}
	return scanned, resolved, nil
}
