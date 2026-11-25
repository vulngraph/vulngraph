package enrich

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// contextIndependentCriticals are checks whose finding is critical REGARDLESS of
// any graph context — no reachability, blast radius, or trust posture makes them
// acceptable. Graph-signal scoring can't see WHY they matter (a root user has no
// exposure/blast edges), so it leaves them in the monitor band and a score-sorted
// worklist buries them. This source floors them into the page band. Kept
// deliberately tiny and unambiguous — only add a check here when there is genuinely
// no context in which it is not critical.
var contextIndependentCriticals = map[string]string{
	"aws-iam-root-active-key": "the account root has an active access key — a standing full-account credential that must never exist, independent of graph context",
}

const sourceCriticalFloor = "critical_floor"

// CriticalFloor floors context-independent critical checks into the page band so
// enrichment's graph-signal scoring can never leave them unprioritized. Two ways
// in: an exact CheckID map (contextIndependentCriticals) and a predicate
// (isMaliciousPackage) for a whole advisory family rather than one fixed ID.
type CriticalFloor struct{}

// Name identifies the source in the score breakdown.
func (CriticalFloor) Name() string { return sourceCriticalFloor }

// Evaluate floors a listed check, or any confirmed malicious package, to the
// page band; all other findings pass through.
func (CriticalFloor) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	if reason, ok := contextIndependentCriticals[f.CheckID]; ok {
		return Factor{
			Source: sourceCriticalFloor,
			Floor:  ThresholdPage,
			Detail: reason,
		}, true, nil
	}
	// A malicious package's floor exists independent of the check-ID map above
	// because the SupplyChainExposure score (sources_supply_chain.go) is
	// exposure-based and would otherwise leave a not-yet-deployed malicious
	// package at 0 points — the same reachability category error already fixed
	// on the must-fix axis in assessSupplyChainMustFix (mustfix.go). Flooring
	// here is belt-and-suspenders: since the floor equals ThresholdPage,
	// Aggregate's own "floor < ThresholdPage" guard also structurally disables
	// any ceiling for this finding, the same immunity KEV-critical findings get.
	if isMaliciousPackage(f) {
		return Factor{
			Source: sourceCriticalFloor,
			Floor:  ThresholdPage,
			Detail: "OpenSSF malicious-packages advisory — the package artefact itself is hostile, not merely vulnerable; install-time compromise already occurred independent of deployment or exposure",
		}, true, nil
	}
	return Factor{}, false, nil
}
