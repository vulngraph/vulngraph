package belief

import (
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// SeverityInputs are the cited facts the deterministic reconciler weighs. Every
// field that influences the verdict becomes an Evidence clause, so the resulting
// belief can defend itself.
type SeverityInputs struct {
	FindingID, ResourceID string
	Score                 uint8
	Band                  string // enrich.Band value: page|high|pipeline|monitor
	// MustFixClass is the enrich must-fix class:
	// must_fix|elevated|contained|controlled|routine|"" (unenriched). Only the three
	// decisive ones move the severity below; routine and elevated leave it
	// band-derived, which is what makes them adjudicatable (disagreement.go).
	MustFixClass  string
	MustFixReason string
	TrustEntry    string // iam_role inbound assumability, if known
	// PageFloor reports that an enrich source asserted "this always pages"
	// (KEV, a page-level active-compromise detection, a context-independent
	// critical). No must-fix demotion may ground such a finding below the
	// severity of the page band.
	PageFloor bool
	// HighFloor reports a reach-independent threat/signal floor at the high
	// band or above (a GuardDuty C&C/Backdoor detection on an internal host, a
	// live leaked credential). The same rule as PageFloor one band down: a
	// contained/controlled verdict is a claim about the internet path, which
	// this floor asserts urgency independently of.
	HighFloor bool
}

// bandToSeverity maps an enrich band to a severity floor for the score-derived case.
func bandToSeverity(band string) finding.Severity {
	switch band {
	case string(enrich.BandPage):
		return finding.SeverityCritical
	case string(enrich.BandHigh):
		return finding.SeverityHigh
	case string(enrich.BandPipeline):
		return finding.SeverityMedium
	default:
		return finding.SeverityLow
	}
}

// Reconcile derives a grounded true-severity Belief from a finding's enrich score
// and must-fix classification. must-fix is strong evidence and can cap the raw
// score band — closing the "score 92 but not urgent" incoherence. Deterministic
// beliefs are self-confirmed at high confidence; every branch cites its fact.
func Reconcile(in SeverityInputs, now time.Time) Belief {
	ev := []Evidence{{
		Clause: fmt.Sprintf("enriched risk score %d (band %q)", in.Score, in.Band),
		Source: "enrich_score",
		Fact:   fmt.Sprintf("%d/%s", in.Score, in.Band),
	}}
	sev := bandToSeverity(in.Band)
	claim := "score-derived true severity; no must-fix signal"

	switch in.MustFixClass {
	case "controlled":
		sev = finding.SeverityLow
		claim = "controlled — an observed compensating control (MFA-required or non-admin SSO entry, or an inactive or MFA-gated keyless user) gates the path, so the high score overstates true severity"
		// Fact is the instance-specific control detail (in.MustFixReason),
		// not the coarse class label "controlled" — two DIFFERENT resources'
		// controlled-by-different-controls facts must never collapse under
		// dedupeEvidence's (Source, Fact) key just because they share a
		// class. See dedupeEvidence's doc for why Fact must be the observed
		// value, not a category.
		ev = append(ev, Evidence{Clause: in.MustFixReason, Source: "must_fix", Fact: in.MustFixReason})
		if in.TrustEntry != "" {
			ev = append(ev, Evidence{Clause: "role inbound assumability", Source: "trust_entry", Fact: in.TrustEntry})
		}
	case "contained":
		sev = finding.SeverityLow
		claim = "contained — no internet-reachable attack path; internal/lateral risk only"
		ev = append(ev, Evidence{Clause: "no reachable path from the internet", Source: "must_fix", Fact: "contained"})
	case "must_fix":
		sev = finding.SeverityCritical
		claim = "must-fix — the full must-fix evidence is present"
		// Cite the same accurate, already-computed reason string every other
		// must-fix-derived branch uses (mustFixReason in enrich/mustfix.go) —
		// not a synthesized "reachable=%t hops=%d" clause, whose inputs
		// (SeverityInputs.Reachable/Hops) were never populated by any caller
		// and always rendered Go's zero values, contradicting the "must-fix
		// — reachable..." claim on the very same belief.
		reason := in.MustFixReason
		if reason == "" {
			reason = "must-fix evidence recorded without a reason string"
		}
		// Fact is the instance-specific reason string, not the coarse class
		// label "must_fix" — see the "controlled" branch's comment above for
		// why.
		ev = append(ev, Evidence{Clause: reason, Source: "must_fix", Fact: reason})
	case "elevated":
		claim = "elevated — high-signal but not the full must-fix picture"
		// Cite in.MustFixReason, not a static generic clause — elevated is the
		// ONLY class that can carry the "blast radius unmeasured" fragment
		// (must_fix itself requires blastKnown, see mustfix.go's promotion
		// condition), so a generic "partial must-fix conditions met" clause
		// discarded exactly the disclosure that fragment exists to
		// surface. Same instance-specific-Fact rule as the other branches above.
		reason := in.MustFixReason
		if reason == "" {
			reason = "partial must-fix conditions met"
		}
		ev = append(ev, Evidence{Clause: reason, Source: "must_fix", Fact: reason})
	}

	// A page floor outranks the must-fix demotions, exactly as it outranks
	// suppression and ceilings in enrich.Aggregate: a demotion here would
	// confirm a known-exploited finding as Low and take it out of adjudication.
	if pageSev := bandToSeverity("page"); in.PageFloor && sev != pageSev {
		sev = pageSev
		claim += " — but an active page-level signal (KEV / active compromise) floors it at " + string(pageSev)
		ev = append(ev, Evidence{Clause: "an enrich source floored this finding to the page band", Source: "enrich_score", Fact: "page_floor"})
	}
	if in.HighFloor && (sev == finding.SeverityLow || sev == finding.SeverityMedium) {
		sev = finding.SeverityHigh
		claim += " — but a reach-independent active-threat or leaked-credential signal floors it at " + string(sev)
		ev = append(ev, Evidence{Clause: "a reach-independent enrich source floored this finding to the high band", Source: "enrich_score", Fact: "high_floor"})
	}

	return Belief{
		FindingID:  in.FindingID,
		ResourceID: in.ResourceID,
		Claim:      claim,
		Severity:   sev,
		Confidence: ConfidenceHigh,
		Status:     StatusConfirmed,
		Evidence:   ev,
		Provenance: "deterministic",
		CreatedAt:  now,
	}
}
