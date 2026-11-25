package enrich

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestAgentRefusal(t *testing.T) {
	scored := func(sev finding.Severity, band Band, class string) finding.Finding {
		return finding.Finding{Severity: sev, ScoreBand: string(band), MustFixClass: class, EnrichedAt: time.Unix(1, 0)}
	}
	cases := []struct {
		name string
		f    finding.Finding
		want string
	}{
		{"low-urgency scored finding", scored(finding.SeverityMedium, BandMonitor, "routine"), ""},
		{"pipeline band", scored(finding.SeverityHigh, BandPipeline, "elevated"), ""},
		{"never enriched", finding.Finding{Severity: finding.SeverityLow, ScoreBand: string(BandMonitor), MustFixClass: "routine"}, "not yet scored"},
		{"no band", scored(finding.SeverityLow, "", "routine"), "not yet scored"},
		{"no must-fix class", scored(finding.SeverityLow, BandMonitor, ""), "not yet scored"},
		{"critical severity", scored(finding.SeverityCritical, BandMonitor, "routine"), "critical severity"},
		{"must-fix", scored(finding.SeverityLow, BandMonitor, MustFix), "classed must-fix"},
		{"page band", scored(finding.SeverityLow, BandPage, "routine"), "urgent score band"},
		{"high band", scored(finding.SeverityLow, BandHigh, "routine"), "urgent score band"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, AgentRefusal(tc.f))
		})
	}
}
