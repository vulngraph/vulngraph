// Deletion-scoping logic for the sync worker: deciding which stored asset
// hashes absent from a sweep's collected set may actually be treated as
// deleted. Split out of sync.go because it is a cohesive, high-stakes unit —
// exactly the kind of "a zero value is not a measurement" logic that
// deserves its own scrutiny.
package jobs

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// deletionCap bounds the blast radius of one scope-aware deletion decision to
// something reviewable, reusing forget.MaxForgetPerSweep's VALUE (not its
// evaluation engine) rather than inventing a second number for the same kind
// of bound.
//
// Only the ABSOLUTE cap is implemented here, not forget's full refusal set
// (relative cap, consecutive-sweep confirmation, enumeration-shrink — see
// internal/app/forget/domain.go's Decide): that machinery is keyed on
// persistent per-(connector, scope, type) state this hash-pruning path does
// not have. The absolute cap needs no persisted history and is cheap to get
// right in one sweep; unifying the two deletion paths is deliberate follow-up
// work, not done here.
const deletionCap = forget.MaxForgetPerSweep

// deletionDecision is the outcome of scope-aware deletion reconciliation for
// one sweep — see findDeletedAssets.
type deletionDecision struct {
	// Deleted is what reconciliation will actually act on: hashes pruned from
	// Postgres and findings resolved as ReasonResourceGone. nil (not merely
	// short) when the candidate set was refused entirely for exceeding
	// deletionCap — see Refused.
	Deleted []string
	// Considered is the RAW absent count — every stored hash absent from this
	// sweep's collected set, before any type/scope narrowing or capping.
	Considered int
	// UnscopedNoType is, of Considered, how many were dropped because their
	// stored AssetType was empty: the collector wrote the asset without a type
	// (see connector.StoredAssetHash). It is reported separately from
	// UnscopedUncovered because it points at a different fix (the collector
	// vs. MarkComplete coverage).
	UnscopedNoType int
	// UnscopedUncovered is, of Considered, how many had a real stored
	// AssetType/Region but no completed scope this sweep proved covers that
	// exact (region, type) pair — either because no collector for that type
	// calls MarkComplete at all yet, or because a SIBLING region/scope of the
	// same type completed while this row's own region/scope did not (the
	// per-scope suppression collect.Result.MarkComplete's doc comment
	// requires, and the scope collapse isCovered/coveredScopes prevents).
	UnscopedUncovered int
	// Refused is how many otherwise-valid candidates were refused ENTIRELY
	// this sweep — not trimmed to deletionCap — because their count exceeded
	// deletionCap. See deletionCap's doc comment: forget.RefusalAbsoluteCap
	// refuses the whole scope rather than acting on a capped subset, and this
	// mirrors that rather than trimming, because trimming would still act on
	// up to deletionCap PER SWEEP with no cross-sweep bound, and the survivor
	// set would be an arbitrary (e.g. lexicographic) subset with no
	// operator-visible "N of M" meaning. When Refused > 0, Deleted is nil.
	Refused int
}

// coverageKey is one (region, type) pair a completed scope this sweep proved
// it fully enumerated. Region is "" for a family that is NOT region-scoped
// (forget.Family.RegionScoped == false, e.g. GCP's aggregatedList families) —
// such a family's completeness claim covers every region for its types, so
// its coverage is intentionally stored as a region-independent wildcard
// rather than one entry per region seen. A region-scoped family's coverage is
// always keyed on its actual region: see MarkComplete's "PER-SCOPE
// SUPPRESSION on truncation" paragraph — one region's completion must never
// license deletion in a sibling region of the same type.
type coverageKey struct {
	region string
	typ    string
}

// coveredScopes returns the set of (region, type) pairs this sweep PROVED
// were fully enumerated by at least one completed scope — the granularity
// collect.Result.CompletedEnumerations exists to provide, keyed the way
// isCovered/findDeletedAssets need to enforce per-scope (not just per-type)
// suppression.
//
// Reuses internal/app/forget's scope grammar (ParseScope, Family.RegionScoped)
// rather than inventing a second parser for the same key format. A scope this
// sweep reported that ParseScope does not recognise contributes NO coverage —
// fail closed, exactly like an empty/unknown stored AssetType.
//
// Deliberately iterates sc.Family.Types (the audited family's own type list),
// not the collector's own claimed types — the same choice
// forget.Service.Evaluate makes, so a collector cannot widen its own
// deletion authority by claiming a type MarkComplete was never audited
// against.
//
// An empty/nil result is the safe default: any collector without its own
// MarkComplete calls returns nil here, so findDeletedAssets treats every one
// of its stored (region, type) pairs as unproven and reconciles nothing for
// them — the deliberately safe direction, trading "reconciles nothing" for
// "never wrongly resolves a live finding".
func coveredScopes(completed []collect.ScopeEnumeration) map[coverageKey]bool {
	if len(completed) == 0 {
		return nil
	}
	var out map[coverageKey]bool
	for _, se := range completed {
		sc, ok := forget.ParseScope(se.Scope)
		if !ok {
			continue // unaudited/malformed scope: contributes no coverage
		}
		if out == nil {
			out = make(map[coverageKey]bool, len(completed))
		}
		region := ""
		if sc.Family.RegionScoped {
			region = sc.Region
		}
		for _, t := range sc.Family.Types {
			out[coverageKey{region: region, typ: t}] = true
		}
	}
	return out
}

// isCovered reports whether a stored row's (region, type) is proven-complete
// by `covered` this sweep. It checks the row's exact region first (the
// region-scoped case), then the region-independent wildcard (the
// non-region-scoped case) — never the reverse, and never a bare type-only
// match, which is exactly the scope collapse this function prevents: one
// region's completed scope must not license deletion for the same
// type in a sibling region that did not complete.
//
// A row with an empty/unrecorded region can only ever match the wildcard
// entry (a non-region-scoped family) — it can never match a region-scoped
// family's coverage, which fails closed exactly like an empty AssetType does.
func isCovered(covered map[coverageKey]bool, region, typ string) bool {
	if len(covered) == 0 {
		return false
	}
	if covered[coverageKey{region: region, typ: typ}] {
		return true
	}
	return covered[coverageKey{region: "", typ: typ}]
}

// findDeletedAssets narrows the flat set-difference (a stored hash absent
// from this sweep's collected set) to the (region, type) pairs `covered` says
// a completed scope this sweep proved it fully enumerated — instead of
// treating every absence as deletion regardless of which family of resource
// it belongs to or whether anything actually proved that family was looked
// at this sweep.
//
// A stored row's AssetType empty, or its (Region, AssetType) not covered, is
// NEVER treated as a candidate — see connector.StoredAssetHash's doc comment
// for why an empty/unknown type or region must read as "unknown", not as
// "not excluded". This includes the case covered == nil: every stored row is
// then unscoped, by construction.
//
// The cap is a REFUSAL, not a trim: if the candidate set exceeds
// deletionCap, NOTHING is deleted this sweep — see deletionCap's doc comment
// for why trimming to the cap would be wrong even though it looks more
// "helpful".
func findDeletedAssets(storedHashes map[string]connector.StoredAssetHash, collected []asset.Asset, covered map[coverageKey]bool) deletionDecision {
	if len(storedHashes) == 0 {
		return deletionDecision{}
	}
	seen := make(map[string]bool, len(collected))
	for _, a := range collected {
		seen[a.ID] = true
	}
	var candidates []string
	var considered, unscopedNoType, unscopedUncovered int
	for id, h := range storedHashes {
		if seen[id] {
			continue
		}
		considered++
		if h.AssetType == "" {
			unscopedNoType++
			continue
		}
		if !isCovered(covered, h.Region, h.AssetType) {
			unscopedUncovered++
			continue
		}
		candidates = append(candidates, id)
	}
	var refused int
	if len(candidates) > deletionCap {
		refused = len(candidates)
		candidates = nil
	}
	return deletionDecision{
		Deleted:           candidates,
		Considered:        considered,
		UnscopedNoType:    unscopedNoType,
		UnscopedUncovered: unscopedUncovered,
		Refused:           refused,
	}
}
