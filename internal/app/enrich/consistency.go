package enrich

import (
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Consistency-invariant labels, reported to the obs consistency-violation
// counter and the structured log line the gate emits. Kept short and stable —
// they are Prometheus label values, so renaming one silently breaks any
// dashboard or alert built on it.
const (
	consistencyInvIdentityZeroHop   = "inv1_identity_zero_hop"
	consistencyInvSuppressedMustFix = "inv2_suppressed_must_fix"
	consistencyInvContainedHighBand = "inv3_contained_high_band"
	consistencyInvSafeMustFix       = "inv4_safe_must_fix"
)

// sourceConsistencyGate is the factor source INV-3 attaches to the score
// breakdown when it caps a contained finding. The gate is the only part of enrich
// that changes a score without a source of its own having contributed, so it
// declares one: a signals row whose factors sum higher than the stored score, with
// nothing explaining the gap, is an unanswerable question at 3am.
const sourceConsistencyGate = "consistency_gate"

// consistencyResult is the reconciled scoring output: the (possibly re-aggregated)
// score, the (possibly demoted) must-fix classification, the (possibly demoted)
// structural safety class, and the invariants that fired. Violations is empty when
// nothing was wrong.
type consistencyResult struct {
	Score         Score
	MustFixClass  string
	MustFixReason string
	SafetyClass   string
	Violations    []string
}

// Flagged reports whether any consistency invariant fired for this finding.
func (r consistencyResult) Flagged() bool { return len(r.Violations) > 0 }

// reconcileConsistency is the per-finding safety net between scoring and persist:
// a pure, fail-safe check that a finding's score, must-fix class and safety class
// do not contradict each other or a structural fact about its resource.
//
// Fail-safe by construction: every branch either STRIPS an inflating factor,
// DEMOTES a class, or CAPS a score. It never adds points, never promotes, never
// fabricates a "contained"/"controlled" demotion that could hide a real finding,
// and never upgrades a safety class — so a bug in this gate can only under-claim,
// never over-claim.
//
// The invariants, in the order they run (each repair composes with the last):
//
//   - INV-1 (identity zero-hop): an identity (IAM user/role, service account) is a
//     principal, never itself a node on the internet, so a 0-hop "directly
//     reachable from the internet" reach factor on it is a category error. Strip
//     that factor, re-aggregate the band, and demote any reach-evidenced
//     must_fix/elevated class that leaned on it. A LEGITIMATE transitive reach (an
//     identity assumable from an exposed asset, hops>=1) carries no 0-hop factor,
//     so it is untouched.
//
//   - INV-2 (suppressed but must-fix): a source asserted "expected/benign"
//     (Suppress), Aggregate honoured it by capping the score into the monitor
//     band, and yet the must-fix tier still says must_fix/elevated. Those are two
//     opposite answers to "should a human act on this?" from one enrichment pass.
//     Demote the class, exactly as INV-1 does.
//
//   - INV-3 (contained but high band): "contained" is the definitive statement
//     that the resource is NOT internet-reachable, yet the aggregate score lands
//     in the high/page bands, the ones that ask a person to act soon or now.
//     Cap the score into the pipeline band so the
//     finding is still reasoned about, but stops paging on evidence that the same
//     enrichment pass contradicted. It guards the most expensive population to
//     get wrong: a single contradictory finding in high/page costs more than one
//     in monitor, since that band is what turns a score into a page.
//
//   - INV-4 (safe but must-fix): "safe" means nothing depends on this resource
//     and it is idle — it drives the Start-here worklist, i.e. "delete/change this
//     first". must_fix/elevated means the opposite. The repair demotes the SAFETY
//     class to caution, never the must-fix class: an over-stated safety claim
//     risks deleting something load-bearing, while demoting must_fix would hide a
//     real finding — only one of those two directions is fail-safe.
//
// The INV-1 and INV-2 demotions land on MustFixRoutine, not on "": "" means ONLY
// "enrichment has not run" (openapi finding.yaml, obs.descUnclassified), so
// writing it on an enriched finding would put those rows back into the ambiguity
// the class exists to remove, and poison the one gauge that proves it worked.
// Routine is also the honest verdict here: the urgency evidence was withdrawn, so
// what is left is "no evidence of urgency". It ranks below contained, promotes
// nothing, and stays adjudicatable (belief.NeedsAdjudication) — which is what
// keeps the "poisoned must_fix is demoted, then the LLM re-examines it" path
// intact.
//
// INV-2 and INV-3 both defer to a page-level Floor for the same reason Aggregate
// does: "this always pages" (KEV, CriticalFloor) is the strongest assertion a
// source can make, and it already beats suppression and ceilings in Aggregate. A
// gate that overrode it here would silently bury known-exploited findings.
//
// INV-6 (out-of-domain hops) is enforced structurally upstream — clampInternetHops
// in graphstore collapses out-of-domain hop counts to unknown before they ever
// reach a factor — so it needs no branch here.
func reconcileConsistency(f finding.Finding, score Score, mustFixClass, mustFixReason string) consistencyResult {
	res := consistencyResult{
		Score:         score,
		MustFixClass:  mustFixClass,
		MustFixReason: mustFixReason,
		SafetyClass:   f.SafetyClass,
	}
	res = inv1IdentityZeroHop(f, res)
	res = inv2SuppressedMustFix(res)
	res = inv3ContainedHighBand(res)
	res = inv4SafeMustFix(res)
	return res
}

// inv1IdentityZeroHop drops any 0-hop direct-exposure reach factor on an identity
// and unwinds a must-fix class that rested on that (false) reachability evidence.
func inv1IdentityZeroHop(f finding.Finding, res consistencyResult) consistencyResult {
	if !IsIdentityResource(f.ResourceType) {
		return res
	}
	kept := make([]Factor, 0, len(res.Score.Factors))
	stripped := false
	for _, fac := range res.Score.Factors {
		if fac.Source == sourceInternetReach && fac.Points == directExposurePoints {
			stripped = true
			continue
		}
		kept = append(kept, fac)
	}
	if !stripped {
		return res
	}

	res.Score = Aggregate(kept)
	res.Violations = append(res.Violations, consistencyInvIdentityZeroHop)
	// A class earned on other grounds (a KEV floor, a controlled/contained
	// demotion) is left as-is — only the reach-evidenced promotion is unwound.
	if ReachabilityEvidenced(res.MustFixClass, res.MustFixReason) {
		res.MustFixClass = MustFixRoutine
		res.MustFixReason = "no urgency evidence: the reachability evidence was a category error (an identity is a principal, not a node on the internet)"
	}
	return res
}

// inv2SuppressedMustFix demotes a must-fix class on a finding whose score a source
// suppressed into the monitor band. Only the class moves: Aggregate has already
// applied the suppression to the score.
func inv2SuppressedMustFix(res consistencyResult) consistencyResult {
	if !isMustFixTier(res.MustFixClass) || !suppressionApplied(res.Score.Factors) {
		return res
	}
	res.Violations = append(res.Violations, consistencyInvSuppressedMustFix)
	res.MustFixClass = MustFixRoutine
	res.MustFixReason = "no urgency evidence: a source asserted this is expected/benign, which contradicts the urgency tier"
	return res
}

// inv3ContainedHighBand caps a "definitively not internet-reachable" finding out
// of the high/page action bands and into pipeline, where it is still reasoned
// about.
//
// The cap is expressed as a Ceiling FACTOR and re-aggregated, not as a direct
// write to Score.Value, for two reasons. It keeps the breakdown honest — the
// signals row shows a factor saying why the score is lower than its parts, the way
// INV-1 re-aggregates after stripping. And it reuses Aggregate's ceiling rule
// rather than restating it, which is where the page-floor exception lives: a
// source that declared "this always pages" (KEV, CriticalFloor) outranks any
// ceiling, so a known-exploited finding on an internal host keeps paging. If that
// exception is ever changed, it changes in one place.
//
// Also skipped when a threat or signal floor put the finding in the high band
// (an active C&C beacon, a leaked credential not shown to be test-mode or
// inactive, a cluster-admin RBAC grant):
// those sources assert urgency independent of internet reachability, so
// "contained" does not contradict them — capping would bury a GuardDuty
// Backdoor on an internal EC2 at 60.
//
// Only applied when it actually lowers the score, so a finding the ceiling cannot
// touch is left byte-for-byte alone and is not counted as a violation.
func inv3ContainedHighBand(res consistencyResult) consistencyResult {
	if res.MustFixClass != MustFixContained || res.Score.Value < ThresholdHigh || hasReachIndependentHighFloor(res.Score.Factors) {
		return res
	}
	capped := Aggregate(append(append([]Factor{}, res.Score.Factors...), Factor{
		Source:  sourceConsistencyGate,
		Ceiling: ThresholdHigh,
		Detail:  "capped below the high band: classified contained (not internet-reachable)",
	}))
	if capped.Value >= res.Score.Value {
		return res // a page floor outranks the ceiling — leave it paging
	}
	res.Violations = append(res.Violations, consistencyInvContainedHighBand)
	res.Score = capped
	return res
}

// inv4SafeMustFix demotes a "safe to fix" claim that contradicts a must-fix
// class. The must-fix class is deliberately left alone — see reconcileConsistency.
//
// Dependents and Unused are NOT touched, and the resulting row reads
// "caution, dependents 0, unused true". That looks inconsistent and is in fact the
// most honest thing available: those two are MEASUREMENTS, while the class is a
// CONCLUSION, and only the conclusion is contradicted. The row is then saying
// exactly what happened — "we found nothing depending on this and it looks idle,
// yet the must-fix evidence says otherwise, so verify before acting" — which is
// what `caution` means. Overwriting the measurements to match the class would
// destroy the only evidence that a graph-coverage gap is what produced the
// contradiction, and coverage gaps are how every one of these arises.
func inv4SafeMustFix(res consistencyResult) consistencyResult {
	if res.SafetyClass != SafetySafe || !isMustFixTier(res.MustFixClass) {
		return res
	}
	res.Violations = append(res.Violations, consistencyInvSafeMustFix)
	res.SafetyClass = SafetyCaution
	return res
}

// isMustFixTier reports whether a must-fix class is one of the two ACTIONABLE
// tiers — the ones that put a finding in front of a human. contained/controlled/
// routine are demotions and blank is "unenriched"; none of them can contradict
// anything, so none of them is a repair target.
func isMustFixTier(class string) bool {
	return class == MustFix || class == MustFixElevated
}

// hasPageFloor reports whether any source asserted "this always pages" (KEV,
// CriticalFloor). Mirrors Aggregate's floor handling: a page floor outranks
// suppression and ceilings there, so it outranks the demoting invariants here.
func hasPageFloor(factors []Factor) bool {
	for _, f := range factors {
		if f.Floor >= ThresholdPage {
			return true
		}
	}
	return false
}

// hasReachIndependentHighFloor reports whether a threat or signal floor lifted
// the finding into the high band or above — urgency those sources assert
// regardless of internet reachability.
func hasReachIndependentHighFloor(factors []Factor) bool {
	for _, f := range factors {
		if (f.Source == sourceThreatFloor || f.Source == sourceSignalFloor) && f.Floor >= ThresholdHigh {
			return true
		}
	}
	return false
}

// suppressionApplied reports whether a Suppress factor actually took effect —
// i.e. a source asserted "expected/benign" and no page floor overrode it. This is
// the same condition Aggregate uses to cap the score, so the invariant can never
// fire on a finding whose suppression was itself overruled.
func suppressionApplied(factors []Factor) bool {
	suppressed := false
	for _, f := range factors {
		if f.Suppress {
			suppressed = true
		}
	}
	return suppressed && !hasPageFloor(factors)
}
