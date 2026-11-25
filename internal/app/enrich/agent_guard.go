package enrich

import "github.com/vulngraph/vulngraph/internal/app/finding"

// AgentRefusal names why a finding may not be silenced or closed by a caller
// that may be an agent (the MCP suppress_finding tool, and REST suppress,
// suppression review and finding resolve on an API key), or "" when it may.
// Such a finding is left to a person on a signed-in session. An unscored
// finding is refused: its urgency is unknown, not low.
func AgentRefusal(f finding.Finding) string {
	switch {
	case f.EnrichedAt.IsZero() || f.ScoreBand == "" || f.MustFixClass == "":
		return "not yet scored"
	case f.Severity == finding.SeverityCritical:
		return "critical severity"
	case f.MustFixClass == MustFix:
		return "classed must-fix"
	case f.ScoreBand == string(BandPage) || f.ScoreBand == string(BandHigh):
		return "urgent score band"
	}
	return ""
}
