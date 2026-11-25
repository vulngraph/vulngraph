// Package enrich turns a raw finding into a contextual risk score before it is
// surfaced or reasoned about. About twenty pluggable Sources (severity, KEV,
// EPSS, blast radius, internet reach, identity hygiene, principal class, attack
// paths, supply chain, takeover, age, ...) each contribute a Factor. Aggregate
// (score.go) combines their points, floors, ceilings, suppression and
// root-cause delegation into one 0–100 score that REPLACES raw scanner severity
// as the value the product shows, sorts, and gates decisions on. Adding a
// signal means implementing a Source (source.go) and registering it.
package enrich

import (
	"errors"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Band classifies a score into an urgency tier (the thresholds below). A band
// says how soon a human should look; none of them executes anything (ADR 087).
type Band string

const (
	BandPage     Band = "page"     // >= ThresholdPage:     actively dangerous, wake someone
	BandHigh     Band = "high"     // >= ThresholdHigh:     fix soon
	BandPipeline Band = "pipeline" // >= ThresholdPipeline: enters the reasoning pipeline
	BandMonitor  Band = "monitor"  // below ThresholdPipeline: monitored, not reasoned
)

// Score thresholds. A score at or above ThresholdPipeline enters the decision
// pipeline (LLM reasoning + decide job); below it the finding is recorded but
// not reasoned about. Kept high enough that only findings with meaningful
// attack paths, blast radius, or KEV signals reach LLM reasoning — a lower
// threshold would queue reasoning for nearly every finding and saturate the
// pipeline.
const (
	ThresholdPipeline = 50
	ThresholdHigh     = 61
	ThresholdPage     = 81
)

// Factor is one source's contribution to a finding's score. Points are additive;
// Floor (0 = none) raises the final score to at least that value, letting a
// source express "this always matters" (e.g. a KEV hit always pages). Suppress
// caps the final score into the monitor band regardless of points or floors —
// the "this is expected/benign" signal (e.g. a privesc finding on an SSO admin
// role). Suppression overrides floors by design; sources must not suppress a
// known-exploited finding.
//
// Ceiling (0 = none) caps the final score to strictly below the given
// threshold — the "this can never wake someone up on its own" signal (e.g. an
// IAM right-sizing suggestion, however dangerous the underlying principal is
// by OTHER findings on the same resource). Unlike Suppress, a Ceiling only
// bounds the top; it never lowers a score that is already below it. A hard
// page floor (KEV, CriticalFloor) still wins — Aggregate never lets a Ceiling
// breach an actual "this always pages" assertion from another source.
//
// RootCause is the one cap a page floor does NOT beat: the finding's urgency is
// carried by root-cause findings it links to (a package run only by VM fleets
// whose own vm_vuln findings page per fleet), so its own score stays below
// page — the root causes page instead, once each, rather than the same CVE
// paging once per fleet plus once for the package.
type Factor struct {
	Source    string `json:"source"`
	Points    int    `json:"points"`
	Floor     int    `json:"floor,omitempty"`
	Ceiling   int    `json:"ceiling,omitempty"`
	Suppress  bool   `json:"suppress,omitempty"`
	RootCause bool   `json:"root_cause,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Score is the enriched, contextual risk assessment for a finding.
type Score struct {
	Value   uint8
	Band    Band
	Factors []Factor
	// Unmeasured names the sources that errored for this finding. Their
	// contribution is unknown, not zero: the score is a best effort without
	// them, and the caller must not treat it as settled (the enrich worker
	// re-enriches such a finding sooner than its freshness backstop).
	Unmeasured []string
	// Owner and Environment are the routing context stamped beside the score
	// (ADR 089), returned so an alert routes on exactly what was persisted.
	// Owner's zero value is "unresolved"; Environment "" is "not classified".
	Owner       asset.Ownership
	Environment string
	// MustFixClass is the persisted must-fix class (after the consistency
	// gate), returned so alerting keys on exactly what was stored: a must_fix
	// transition alerts whatever the band.
	MustFixClass string
}

var ErrNotFound = errors.New("enrich: not found")

// ErrSourceNotReady is a source's "I cannot answer yet" — e.g. the EPSS
// catalog before its first successful load. The source is unmeasured for the
// finding (Score.Unmeasured), exactly like any other source error, but it is
// an expected state rather than a fault, so it is not logged as a warning.
var ErrSourceNotReady = errors.New("enrich: source not ready")
