package enrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestCriticalFloor(t *testing.T) {
	// A root access key floors to the page band regardless of (absent) graph signal.
	f, applied, err := CriticalFloor{}.Evaluate(context.Background(),
		finding.Finding{CheckID: "aws-iam-root-active-key"})
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, ThresholdPage, f.Floor)
	require.NotEmpty(t, f.Detail)

	// Any other check is untouched by this source.
	_, applied, err = CriticalFloor{}.Evaluate(context.Background(),
		finding.Finding{CheckID: "aws-ebs-unencrypted"})
	require.NoError(t, err)
	require.False(t, applied)
}

// End-to-end through the scorer: a root-key finding with no other signal still
// lands in the page band (the whole point — graph scoring left it at monitor).
func TestCriticalFloor_ReachesPageBand(t *testing.T) {
	f, _, _ := CriticalFloor{}.Evaluate(context.Background(), finding.Finding{CheckID: "aws-iam-root-active-key"})
	s := Aggregate([]Factor{f})
	require.GreaterOrEqual(t, int(s.Value), ThresholdPage)
	require.Equal(t, BandPage, s.Band)
}

// TestCriticalFloor_MaliciousPackage covers the score-axis half of the
// category-error fix: a MAL-* package finding floors to the page band even
// with zero contribution from SupplyChainExposure (not-deployed case, 0
// points) — the reachability-based scoring that correctly gates an ordinary
// CVE must not also gate a confirmed malicious package.
func TestCriticalFloor_MaliciousPackage(t *testing.T) {
	malFinding := finding.Finding{
		Source: "supply_chain", ResourceType: "package", CheckID: "MAL-2026-11524",
	}
	f, applied, err := CriticalFloor{}.Evaluate(context.Background(), malFinding)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, ThresholdPage, f.Floor)
	require.NotEmpty(t, f.Detail)

	// An ordinary CVE package finding (no MAL- CheckID) is untouched by this source.
	_, applied, err = CriticalFloor{}.Evaluate(context.Background(),
		finding.Finding{Source: "supply_chain", ResourceType: "package", CheckID: "CVE-2023-44487"})
	require.NoError(t, err)
	require.False(t, applied)

	// End-to-end: the floor alone (no SupplyChainExposure contribution — the
	// not-deployed case scores 0 points) still lands in the page band.
	s := Aggregate([]Factor{f})
	require.GreaterOrEqual(t, int(s.Value), ThresholdPage)
	require.Equal(t, BandPage, s.Band)
}
