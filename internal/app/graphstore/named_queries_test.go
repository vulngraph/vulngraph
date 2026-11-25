package graphstore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
)

// A named query that calls its assets "high risk" filters at the high band's
// threshold, the same number the findings bands and the UI use.
func TestHighRiskNamedQueriesUseTheHighBandThreshold(t *testing.T) {
	want := fmt.Sprintf("score >= %d", enrich.ThresholdHigh)
	for _, name := range []string{"internet_exposed_high_risk", "repos_deploying_to_exposed", "high_risk_package_dependents"} {
		var q string
		for _, nq := range NamedQueries {
			if nq.Name == name {
				q = nq.Query
			}
		}
		require.NotEmpty(t, q, name)
		require.Contains(t, q, want, name)
		require.Equal(t, strings.Count(q, "score >= "), strings.Count(q, want), name)
	}
}
