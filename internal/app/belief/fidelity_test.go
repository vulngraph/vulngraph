package belief

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// allKnown is every witness's Known bit set true — the baseline for every
// fixture below except the ones specifically testing a failed/unknown
// witness. GroundingFacts{} (the bare zero value) would leave every Known
// bit false, which — after the Known-polarity fix — means "unknown", not
// "no witness"; using it directly as a fixture would spuriously trip the
// !Known conflict cases below instead of testing what each fixture intends.
func allKnown() GroundingFacts {
	return GroundingFacts{PublicAccessKnown: true, ExposedEdgeKnown: true, ExposurePeersKnown: true, BlastKnown: true}
}

func TestCorroborationConflict(t *testing.T) {
	confirmed := allKnown()
	confirmed.PublicAccessConfirmed = true
	exposure := allKnown()
	exposure.ExposureConfirmed = true
	exposedEdge := allKnown()
	exposedEdge.ExposedEdgePresent = true
	// Reachability evidence ALONE — the same (poisonable) signal the verdict already
	// reasoned over. This must NO LONGER veto a demotion (the defect this whole
	// change fixes: vetoing on it made the gate structurally defend false-highs).
	reachOnly := allKnown()
	reachOnly.ReachabilityEvidenced, reachOnly.ReachabilityReason = true, "assumable from an internet-exposed asset"
	// Reachability evidence CORROBORATED by an independent fresh exposed-edge witness.
	reachCorroborated := allKnown()
	reachCorroborated.ExposedEdgePresent, reachCorroborated.ReachabilityEvidenced, reachCorroborated.ReachabilityReason =
		true, true, "internet-exposed"
	// none: every witness checked (or not applicable) and found nothing — the
	// genuinely correct, common "no independent witness" case, NOT the same
	// as GroundingFacts{}'s bare zero value (which would mean "unknown").
	none := allKnown()

	tests := []struct {
		name    string
		verdict finding.Severity
		facts   GroundingFacts
		want    bool
	}{
		// Dangerous direction: a demotion contradicted by an INDEPENDENT witness.
		{"demote to low + public-access confirmed → conflict", finding.SeverityLow, confirmed, true},
		{"demote to medium + public-access confirmed → conflict", finding.SeverityMedium, confirmed, true},
		{"demote to medium + fresh exposed-edge witness → conflict", finding.SeverityMedium, exposedEdge, true},
		{"demote to medium + exposure peer → conflict", finding.SeverityMedium, exposure, true},
		{"demote to medium + reachability corroborated by exposed edge → conflict", finding.SeverityMedium, reachCorroborated, true},

		// THE FIX: reachability evidence ALONE (no independent witness) no longer
		// vetoes. This is what made the gate defend a non-exposed identity falsely
		// scored 0-hop — the LLM's demotion is now allowed to stand.
		{"demote to medium + reachability evidence ALONE → NO conflict", finding.SeverityMedium, reachOnly, false},

		// Correct demotions — the common case (e.g. an IAM identity, public_tier None).
		{"demote to low + no witness → no conflict", finding.SeverityLow, none, false},
		{"demote to medium + no witness → no conflict", finding.SeverityMedium, none, false},

		// A FAILED lookup must never read the same as a confirmed-false
		// witness (none, above): flag it for review instead of silently
		// letting the demotion stand on a witness that was never actually
		// checked. See GroundingFacts' doc comment.
		// PublicAccessKnown/ExposedEdgeKnown deliberately omitted (zero
		// value = false = "not known") on the ONE witness under test;
		// ExposurePeersKnown is set true so only the witness under test
		// triggers a conflict, not an unrelated one.
		{"demote to medium + public-access lookup failed → conflict", finding.SeverityMedium, GroundingFacts{ExposedEdgeKnown: true, ExposurePeersKnown: true, BlastKnown: true}, true},
		{"demote to low + exposed-edge lookup failed → conflict", finding.SeverityLow, GroundingFacts{PublicAccessKnown: true, ExposurePeersKnown: true, BlastKnown: true}, true},
		{"demote to low + blast walk failed → conflict", finding.SeverityLow, GroundingFacts{PublicAccessKnown: true, ExposedEdgeKnown: true, ExposurePeersKnown: true}, true},
		{"hold high + blast walk failed → no conflict", finding.SeverityHigh, GroundingFacts{PublicAccessKnown: true, ExposedEdgeKnown: true, ExposurePeersKnown: true}, false},
		{"hold high + public-access lookup failed → no conflict (holding needs no corroboration)", finding.SeverityHigh, GroundingFacts{ExposedEdgeKnown: true, ExposurePeersKnown: true, BlastKnown: true}, false},

		// Safe direction: holding high/critical never needs corroboration.
		{"hold high + public-access confirmed → no conflict", finding.SeverityHigh, confirmed, false},
		{"hold critical + public-access confirmed → no conflict", finding.SeverityCritical, confirmed, false},
		{"hold high + exposed-edge witness → no conflict", finding.SeverityHigh, exposedEdge, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ev := corroborationConflict(tt.verdict, tt.facts)
			require.Equal(t, tt.want, got)
			if got {
				require.NotEmpty(t, ev.Source)
				require.NotEmpty(t, ev.Fact)
				require.NotEmpty(t, ev.Clause)
			}
		})
	}
}

func TestDowngradeForConflict(t *testing.T) {
	b := Belief{
		FindingID: "f1", ResourceID: "arn:s3", Claim: "adjudicated low — all 3 samples agreed",
		Severity: finding.SeverityLow, Confidence: ConfidenceHigh, Status: StatusConfirmed,
		Provenance: ProvenanceAdjudicator,
		Evidence:   []Evidence{{Clause: "unreachable", Source: "reachability", Fact: "no path"}},
	}
	_, conflict := corroborationConflict(finding.SeverityLow, GroundingFacts{PublicAccessConfirmed: true})
	got := downgradeForConflict(b, conflict)

	require.Equal(t, ConfidenceLow, got.Confidence)
	require.Equal(t, StatusProposed, got.Status)
	require.Contains(t, got.Claim, "needs review")
	require.Len(t, got.Evidence, 2, "verdict evidence preserved + conflict appended")
	require.NoError(t, got.Validate(), "downgraded belief stays grounded")
	// The conflict clause cites the independent public-access witness, tagged
	// with the gate's own source so it can never be mistaken for LLM output.
	var cited bool
	for _, e := range got.Evidence {
		if e.Source == corroborationGateSource && e.Fact == "public_access=confirmed" {
			cited = true
		}
	}
	require.True(t, cited, "conflict evidence cites the public-access witness")
}

// When an INDEPENDENT exposed-edge witness fires alongside reachability evidence,
// the cited Fact names both — the reachability reason plus the fresh edge witness —
// so a reviewer sees exactly which independent signal the demotion contradicted.
func TestCorroborationConflict_CitesReachabilityReasonWhenCorroborated(t *testing.T) {
	got, ev := corroborationConflict(finding.SeverityMedium, GroundingFacts{
		ExposedEdgePresent:    true,
		ReachabilityEvidenced: true,
		ReachabilityReason:    "internet-exposed",
	})
	require.True(t, got)
	require.Contains(t, ev.Fact, "internet-exposed")
	require.Contains(t, ev.Fact, "exposed_to_internet_edge=present")
}

// Reachability evidence with NO independent witness does not fire the gate — the
// regression guard for the false-high defense the gate used to provide.
func TestCorroborationConflict_ReachabilityAloneDoesNotVeto(t *testing.T) {
	facts := allKnown()
	facts.ReachabilityEvidenced = true
	facts.ReachabilityReason = "assumable from an internet-exposed asset"
	got, _ := corroborationConflict(finding.SeverityMedium, facts)
	require.False(t, got, "reachability evidence alone must not veto a demotion")
}

// TestCorroborationConflict_SourceNeverCollidesWithModelEvidence pins the
// bug where adjudicator beliefs carried a gate-appended clause ("demotion
// contradicted by...") under the SAME Source tag ("must_fix") the model itself
// uses for its own must-fix citations — so the persisted belief read as the model contradicting its own
// verdict in its own audit trail. The model's samples were not actually
// self-contradictory; the gate's clause was conflated with LLM output. Every
// conflict clause must use a source outside the model's evidence-source enum
// (reachability|trust_entry|must_fix|enrich_score|blast_radius|exploitability)
// so a reviewer (or future code) can always tell the two apart.
func TestCorroborationConflict_SourceNeverCollidesWithModelEvidence(t *testing.T) {
	modelSources := map[string]bool{
		"reachability": true, "trust_entry": true, "must_fix": true,
		"enrich_score": true, "blast_radius": true, "exploitability": true,
	}
	facts := []GroundingFacts{
		{PublicAccessConfirmed: true},
		{ExposedEdgePresent: true},
		{ExposureConfirmed: true},
		{ExposedEdgePresent: true, ReachabilityEvidenced: true, ReachabilityReason: "internet-exposed"},
	}
	for _, f := range facts {
		_, ev := corroborationConflict(finding.SeverityMedium, f)
		require.False(t, modelSources[ev.Source], "gate source %q collides with a model evidence source", ev.Source)
		require.Equal(t, corroborationGateSource, ev.Source)
	}
}
