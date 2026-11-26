// Package jobs — the finding lifecycle edge of a connector sync.
//
// A sync answers two different questions about a stored finding, and this file
// keeps them apart: "did the resource disappear?" (resource_gone) and "did the
// check that raised this run again and stay silent?" (fixed). The second is
// only meaningful when the check could actually evaluate the resource — see
// reconcileResolvedFindings.
package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// findingLifecycler is the slice of finding.Service the sync-time lifecycle
// reconcile needs.
type findingLifecycler interface {
	ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
	Resolve(ctx context.Context, findings []finding.Finding, reason finding.ResolutionReason) error
}

// reconcileBatch is how many resource IDs are diffed per ByResourceIDs call.
//
// Sized from the read's cost profile, not a result cap. ByResourceIDs
// cannot prune on the IN-list: `findings`'s ordering means the resource_id bloom
// filter matches nearly every granule, so the query scans the whole table
// regardless of batch size and per-call cost is roughly fixed — the only lever on
// total ClickHouse load is making fewer calls. Capped at 1000 rather than higher
// because of Go-side result size and ClickHouse memory per in-flight call,
// multiplied by the client's concurrency slots.
//
// MUST NOT be raised while ByResourceIDs has a silent row cap — that combination
// converts occasional truncation into systematic truncation.
const reconcileBatch = 1000

// reconcileResolvedFindings implements the finding lifecycle's resolution edge:
// the check registry just ran against targets and emitted `emitted`. Any stored
// OPEN check-registry finding (source "cspm" — CSPM/CIEM/RBAC all record under
// it) on those resources that was NOT re-emitted no longer reproduces — mark it
// resolved. Absence is only meaningful for resources the checks actually ran on,
// so the diff never touches resources outside targets (the changed-assets
// confound). "iac_terraform" is reconciled the same way, since its findings are
// re-emitted every sweep the underlying condition persists. Provider-native
// findings (GuardDuty, SCC, GHAS) are not reconciled here — their producers
// have their own lifecycle semantics, all in sync_provider.go: GHAS findings
// close when GitHub reports the alert fixed, dismissed or resolved
// (reconcileProviderClosures), GuardDuty and SCC findings when a complete
// listing stops returning them (closeUnlistedFindings).
//
// ABSENCE IS NOT REMEDIATION. A check whose evidence key is missing from the
// asset correctly stays silent (observedNone, the (value, observed bool)
// collector convention, TestChecksNeverFireOnAbsentData) — but silence is not
// proof the underlying resource was fixed; it can just as easily mean the check
// could not evaluate it. registry gates on that: a check that could not evaluate
// the resource is skipped, and the finding simply stays open rather than being
// closed as remediated on the strength of missing evidence. A pod check's
// finding rolled up onto its workload (checks.WorkloadOwnerID) concludes only
// when at least one of the workload's pods was checked this sweep and every
// such pod was evaluable; a workload asset that changed while none of its pods
// did keeps its findings open.
//
// partial is the collection's res.Partial: some best-effort family failed
// somewhere this sweep. A registry check still answers for itself through
// checkCouldConclude (its evidence keys are either on the asset or not), but a
// finding from a producer outside the registry — CIEM privesc rules, IaC —
// may depend on the family that failed. Its absence after a partial collection
// is not evidence of a fix, so it is withheld. CIEM additionally requires a
// complete per-principal permission observation even when the family succeeded.
func reconcileResolvedFindings(ctx context.Context, svc findingLifecycler, registry *checks.Registry, targets []asset.Asset, emitted []finding.Finding, partial bool) {
	if len(targets) == 0 {
		return
	}
	logger := log.FromContext(ctx)
	emittedIDs := make(map[string]bool, len(emitted))
	for _, f := range emitted {
		emittedIDs[f.ID] = true
	}
	targetByID := make(map[string]asset.Asset, len(targets))
	checkedPods := map[string][]asset.Asset{} // workload asset ID → its pods in targets
	for _, a := range targets {
		targetByID[a.ID] = a
		if owner, ok := checks.WorkloadOwnerID(a); ok {
			checkedPods[owner] = append(checkedPods[owner], a)
		}
	}

	var toResolve []finding.Finding
	var withheld, withheldPartial int
	for start := 0; start < len(targets); start += reconcileBatch {
		end := min(start+reconcileBatch, len(targets))
		ids := make([]string, 0, end-start)
		for _, a := range targets[start:end] {
			ids = append(ids, a.ID)
		}
		stored, err := svc.ByResourceIDs(ctx, ids)
		if err != nil {
			logger.Warn().Err(err).Msg("sync: lifecycle reconcile read failed (batch skipped)")
			continue
		}
		for _, f := range stored {
			if (f.Source != "cspm" && f.Source != "iac_terraform") || f.Resolved() || emittedIDs[f.ID] {
				continue
			}
			if partial && !isRegistryCheck(registry, f.CheckID) {
				withheldPartial++
				continue
			}
			if !checkCouldConclude(registry, targetByID, checkedPods, f) {
				withheld++
				continue
			}
			toResolve = append(toResolve, f)
		}
	}
	if withheld > 0 {
		logger.Warn().Int("findings", withheld).
			Msg("sync: resolution withheld — emitting check could not evaluate the asset (evidence absent)")
	}
	if withheldPartial > 0 {
		logger.Warn().Int("findings", withheldPartial).
			Msg("sync: resolution withheld — partial collection, and the producer (CIEM/IaC) is not a registry check that can vouch for its inputs")
	}
	if len(toResolve) == 0 {
		return
	}
	if err := svc.Resolve(ctx, toResolve, finding.ReasonFixed); err != nil {
		logger.Warn().Err(err).Int("findings", len(toResolve)).Msg("sync: lifecycle resolve failed")
		return
	}
	logger.Info().Int("findings", len(toResolve)).Msg("sync: findings auto-resolved (no longer observed)")
}

// checkCouldConclude reports whether the check behind f actually evaluated f's
// resource this sweep, so its silence can be read as "the problem is gone".
//
// CIEM findings require a graded principal with observed permission data. An
// unknown check ID from other producers (removed from the registry or IaC), a
// finding whose resource is outside this sweep's targets, and a check that does not apply to the target asset
// type all answer true. Two cases answer false: the check applies to the
// asset and could not evaluate it; or the finding is a pod check rolled up
// onto a k8s workload (checks.WorkloadOwnerID) and checkedPods holds none of
// that workload's pods, or one it could not evaluate — the check never looked.
func checkCouldConclude(registry *checks.Registry, targetByID map[string]asset.Asset, checkedPods map[string][]asset.Asset, f finding.Finding) bool {
	if f.Type == "ciem_privesc" {
		a, observed := targetByID[f.ResourceID]
		return observed && ciem.Graded(a)
	}
	if registry == nil || f.CheckID == "" {
		return true
	}
	c, ok := registry.ByID(f.CheckID)
	if !ok {
		return true
	}
	a, ok := targetByID[f.ResourceID]
	if !ok {
		return true
	}
	if c.AppliesTo(a) {
		return c.Evaluable(a)
	}
	if c.AssetType != "k8s_pod" || !strings.HasPrefix(a.Type, "k8s_") {
		return true
	}
	pods := checkedPods[f.ResourceID]
	if len(pods) == 0 {
		return false
	}
	for _, p := range pods {
		if c.AppliesTo(p) && !c.Evaluable(p) {
			return false
		}
	}
	return true
}

// isRegistryCheck reports whether checkID is a check-registry check. A nil
// registry cannot vouch for anything, so it answers false.
func isRegistryCheck(registry *checks.Registry, checkID string) bool {
	if registry == nil {
		return false
	}
	_, ok := registry.ByID(checkID)
	return ok
}

// deletionApplier is the slice of connector.Service a sweep's deletion
// decision is applied through.
type deletionApplier interface {
	RecordAssetDeletions(ctx context.Context, connectorID string, ids []string, at time.Time) ([]string, error)
	DeleteAssetHashes(ctx context.Context, connectorID string, ids []string) error
}

// applyDeletions applies a complete sweep's deletion decision, record first.
// The record (asset_deletions) is the proof vm_vuln, base_image and package
// departures read in place of a lapsed last_seen; the hash delete is what
// stops the next sweep re-deciding. So if the record fails, nothing else is
// done: the hashes stay, the next complete sweep decides again and records
// it. Dropping the hashes without the record would lose the proof for good —
// the asset is no longer a deletion candidate, and its derived findings would
// wait out the absence fallback instead.
//
// Other connectors' ownership prevents a global deletion record. This
// connector still drops its own absent hashes, allowing the final owner to
// establish deletion when its complete listing also stops returning the asset.
func applyDeletions(ctx context.Context, conns deletionApplier, findings findingLifecycler, connectorID string, ids []string, at time.Time) {
	logger := log.FromContext(ctx).With().Str("connector_id", connectorID).Logger()
	proven, err := conns.RecordAssetDeletions(ctx, connectorID, ids, at)
	if err != nil {
		logger.Warn().Err(err).Int("assets", len(ids)).
			Msg("sync: deletion record failed — hashes kept, the next complete sweep re-decides")
		return
	}
	if err := resolveFindingsForDeletedAssets(ctx, findings, proven); err != nil {
		logger.Warn().Err(err).Msg("sync: deleted-asset reconciliation failed; hashes kept for retry")
		return
	}
	if err := conns.DeleteAssetHashes(ctx, connectorID, ids); err != nil {
		logger.Warn().Err(err).Msg("sync: hash delete failed")
	}
}

// derivedFromGroup reports whether f is a projection over a group rather than
// a fact about its resource: a vm_vuln fleet finding of a real fleet (ASG /
// MIG / AMI, filed on one member VM), a base-image root-cause finding (on one
// member image), or a supply_chain package finding (a purl every runner
// shares). Each has a job that reconciles membership — refresh_vm_vuln,
// refresh_base_images, refresh_osv — so the deletion of the resource it is
// filed on says nothing about whether the group still exists.
//
// Not derived: an "instance" fleet (a hand-built host is its own fleet, so its
// deletion IS the fleet's) and a base-image end-of-life finding (about that
// one image) — for those this complete sweep's deletion is the right proof.
func derivedFromGroup(f finding.Finding) bool {
	switch f.Source {
	case vmVulnSource:
		return f.Metadata["fleet_kind"] != "instance"
	case baseImageSource:
		return f.CheckID == baseImageGroupCheckID
	case "supply_chain":
		return f.ResourceType == "package"
	}
	return false
}

// resolveFindingsForDeletedAssets resolves every open finding about a resource
// the collector no longer returns — a deleted resource cannot have open
// findings. Derived group findings (derivedFromGroup) are left to their own
// job: the group outlives any one member.
func resolveFindingsForDeletedAssets(ctx context.Context, svc findingLifecycler, deletedIDs []string) error {
	logger := log.FromContext(ctx)
	var toResolve []finding.Finding
	for start := 0; start < len(deletedIDs); start += reconcileBatch {
		end := min(start+reconcileBatch, len(deletedIDs))
		stored, err := svc.ByResourceIDs(ctx, deletedIDs[start:end])
		if err != nil {
			return fmt.Errorf("read deleted-asset findings: %w", err)
		}
		for _, f := range stored {
			if !f.Resolved() && !derivedFromGroup(f) {
				toResolve = append(toResolve, f)
			}
		}
	}
	if len(toResolve) == 0 {
		return nil
	}
	if err := svc.Resolve(ctx, toResolve, finding.ReasonResourceGone); err != nil {
		return fmt.Errorf("resolve deleted-asset findings: %w", err)
	}
	logger.Info().Int("findings", len(toResolve)).Msg("sync: findings resolved for deleted assets")
	return nil
}

// recordCheckEvaluability publishes graph_check_evaluable_ratio for one
// connector's collected assets. Best-effort and nil-safe: an observability call
// must never affect a sync's outcome.
func recordCheckEvaluability(m *obs.Metrics, connectorID string, registry *checks.Registry, assets []asset.Asset) {
	if m == nil || registry == nil || len(assets) == 0 {
		return
	}
	ev := registry.Evaluability(assets)
	stats := make([]obs.CheckEvaluability, 0, len(ev))
	for _, e := range ev {
		if e.Applicable == 0 {
			continue // this connector holds none of these assets — not its reading to make
		}
		stats = append(stats, obs.CheckEvaluability{CheckID: e.CheckID, Applicable: e.Applicable, Evaluable: e.Evaluable})
	}
	m.ObserveCheckEvaluability(connectorID, stats)
}

// recordDeletionSignal publishes the OBSERVE-ONLY half of the deletion signal
// for one connector's sweep: which collector scopes proved they enumerated
// everything, and a deletion-candidate count — deletion reconciliation's own
// account of what it did (sweep complete) or could not even consider (sweep
// partial) this sweep.
//
// It deliberately measures the decision rather than being an independent check
// on it. Reconciliation is gated on !res.Partial, so `candidates` (its meaning
// set by the caller, sync.go's Work) is split on that same boolean: when
// res.Partial it is the raw absent count (the outer gate refuses all of it, so
// the raw count is the honest size of what this connector currently cannot
// reconcile); when !res.Partial it is the count actually deleted/resolved this
// sweep, not the raw absent count — some rows are deliberately left alone
// (uncovered by any completed scope, or refused for exceeding deletionCap) and
// publishing the raw count into the "acted on" bucket would overstate what
// happened.
//
// candidatesKnown is false when this sweep never loaded the connector's stored
// hashes at all. The candidate count is then UNKNOWN, not zero — the stored set
// may well hold dead ids nobody looked for — so those series are left untouched
// rather than published as a comforting 0. The scope watermarks are still
// stamped: the collector ran and its enumerations are just as provable.
//
// Best-effort and nil-safe: observability must never affect a sync's outcome.
func recordDeletionSignal(m *obs.Metrics, connectorID string, res collect.Result, candidates int, candidatesKnown bool, at time.Time) {
	if m == nil || connectorID == "" {
		return
	}
	if len(res.CompletedEnumerations) > 0 {
		scopes := make([]obs.ScopeCompletion, 0, len(res.CompletedEnumerations))
		for _, se := range res.CompletedEnumerations {
			scopes = append(scopes, obs.ScopeCompletion{Scope: se.Scope, Count: se.Count})
		}
		m.ObserveScopeCompletions(connectorID, scopes, float64(at.Unix()))
	}
	if candidatesKnown {
		m.ObserveDeletionCandidates(connectorID, candidates, !res.Partial)
	}
}

// evaluateForget runs the per-scope deletion decision for one sweep and records
// it. In shadow mode — the default — recording is ALL it does.
//
// sweepStart, not time.Now(): the cutoff a stored asset must have been
// re-stamped past to count as observed has to be the clock this sweep collected
// on, since collection can take several minutes and the evaluation's own
// wall-clock would read the sweep's earliest-collected assets as absent from it.
//
// Best-effort and nil-safe, in the same sense as every other lifecycle edge
// here: a sweep that succeeded must not be reported as failed because a
// decision RECORD could not be written. It is deliberately not the same sense
// as "carry on with what worked" — forget.Service abandons the whole
// connector's evaluation on any error rather than recording a partial one.
//
// res.Partial (the connector-wide "some best-effort family failed somewhere")
// is deliberately NOT passed through to forget.Sweep.Partial: a scope reaching
// forget.Evaluate at all already proved its OWN pagination loop read every page
// with no swallowed error (collect.Result.MarkComplete's contract), so gating it
// again on a sibling family's unrelated failure would poison every audited
// scope's decision on the strength of a problem elsewhere in the same sweep —
// defeating the point of auditing completeness per scope instead of per
// connector. The one gap a connector-wide check would catch, narrowly: a
// collector goroutine can call MarkComplete and then panic before its assets
// are appended to res.Assets, so a proven-complete scope with an empty or short
// payload can read exactly like "everything in this scope was deleted".
// checkDelivered below closes that gap directly, at the scope it actually
// concerns, instead of treating every scope in the connector as suspect because
// any family anywhere failed.
func evaluateForget(ctx context.Context, f scopeForgetter, m *obs.Metrics, connectorID string, res collect.Result, sweepStart time.Time) {
	if f == nil || len(res.CompletedEnumerations) == 0 {
		return
	}
	logger := log.FromContext(ctx)
	delivered := deliveredCounts(res.Assets)
	scopes := make([]forget.ScopeEnumeration, 0, len(res.CompletedEnumerations))
	for _, se := range res.CompletedEnumerations {
		if !checkDelivered(se, delivered) {
			logger.Warn().Str("connector_id", connectorID).Str("scope", se.Scope).Int("declared", se.Count).
				Msg("forget: scope declared complete but its assets did not all reach the sweep's result — dropped from this sweep's evaluation")
			m.ObserveForgetDeliveryMismatch()
			continue
		}
		scopes = append(scopes, forget.ScopeEnumeration{Scope: se.Scope, Types: se.Types, Count: se.Count})
	}
	n, err := f.Evaluate(ctx, forget.Sweep{
		ConnectorID: connectorID,
		At:          sweepStart,
		Scope:       scopes,
	})
	if err != nil {
		logger.Warn().Err(err).Str("connector_id", connectorID).
			Msg("forget: scope evaluation failed (nothing recorded, nothing acted on)")
		return
	}
	if n > 0 {
		logger.Info().Str("connector_id", connectorID).Int("forgettable", n).
			Msg("forget: assets passed every refusal — recorded (acted on only in enforce mode)")
	}
}

// deliveredKey identifies one (region, asset type) count actually collected
// this sweep — the payload half of checkDelivered's claim/payload comparison.
// Every asset is indexed twice: once under its own region, for RegionScoped
// families, and once under an empty region, for the global total a
// non-RegionScoped family's claim (forget.Scope.Region == "") is checked
// against.
type deliveredKey struct {
	region string
	typ    string
}

func deliveredCounts(assets []asset.Asset) map[deliveredKey]int {
	counts := make(map[deliveredKey]int, len(assets))
	for _, a := range assets {
		counts[deliveredKey{typ: a.Type}]++ // global total (empty region)
		// Only add a SEPARATE per-region increment when the asset actually has a
		// region: an asset with none (a global-family type like gce_instance)
		// already landed in the global key above under the SAME zero-value key,
		// and incrementing it again here would double-count it.
		if a.Region != "" {
			counts[deliveredKey{region: a.Region, typ: a.Type}]++
		}
	}
	return counts
}

// checkDelivered reports whether a collector's completeness claim
// (collect.ScopeEnumeration.Count, from MarkComplete) is corroborated by what
// actually reached res.Assets for that scope's type(s) — see evaluateForget's
// doc comment for why this exists in place of the connector-wide res.Partial
// check it replaced. ">=", not "==": more delivered than declared is not the
// failure mode this guards (there is no producer that emits the same
// enforceable type twice within one connector's Result), and a strict
// equality would make an unrelated harmless duplicate a false positive.
//
// A scope forget.ParseScope does not recognise as enforceable always passes
// unchanged: forget.Evaluate's own enforceable() filter drops those before
// they could ever reach a decision, so this check would only ever produce a
// false alarm for a family this package has no authority over in the first
// place.
func checkDelivered(se collect.ScopeEnumeration, delivered map[deliveredKey]int) bool {
	sc, ok := forget.ParseScope(se.Scope)
	if !ok {
		return true
	}
	for _, t := range se.Types {
		key := deliveredKey{typ: t}
		if sc.Family.RegionScoped {
			key.region = sc.Region
		}
		if delivered[key] < se.Count {
			return false
		}
	}
	return true
}
