package belief

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func sig(rt, band, mfc string) PatternSignature {
	return PatternSignature{ResourceType: rt, Band: band, MustFixClass: mfc}
}

// n copies of one (signature, severity) input.
func inputs(s PatternSignature, sev finding.Severity, n int) []CrystallizationInput {
	out := make([]CrystallizationInput, n)
	for i := range out {
		out[i] = CrystallizationInput{Sig: s, Severity: sev}
	}
	return out
}

func TestMineCandidates(t *testing.T) {
	identity := sig("iam_user", "page", "elevated")

	t.Run("stable signature at threshold → candidate", func(t *testing.T) {
		got := MineCandidates(inputs(identity, finding.SeverityMedium, 20), 20)
		require.Len(t, got, 1)
		require.Equal(t, identity, got[0].Sig)
		require.Equal(t, finding.SeverityMedium, got[0].Severity)
		require.Equal(t, 20, got[0].Instances)
	})

	t.Run("below threshold → excluded", func(t *testing.T) {
		require.Empty(t, MineCandidates(inputs(identity, finding.SeverityMedium, 19), 20))
	})

	t.Run("dissent (two severities for one signature) → excluded", func(t *testing.T) {
		in := inputs(identity, finding.SeverityMedium, 25)
		in = append(in, CrystallizationInput{Sig: identity, Severity: finding.SeverityLow}) // one disagreement
		require.Empty(t, MineCandidates(in, 20), "an unstable shape must not crystallize")
	})

	t.Run("empty → none", func(t *testing.T) {
		require.Empty(t, MineCandidates(nil, 20))
	})

	t.Run("multiple signatures judged independently + ordered by instances", func(t *testing.T) {
		sa := sig("iam_user", "page", "elevated")     // 30, stable → candidate
		sb := sig("gcp_service_account", "high", "")  // 22, stable → candidate
		sc := sig("rds_instance", "page", "must_fix") // 5, below threshold → excluded
		var in []CrystallizationInput
		in = append(in, inputs(sa, finding.SeverityMedium, 30)...)
		in = append(in, inputs(sb, finding.SeverityLow, 22)...)
		in = append(in, inputs(sc, finding.SeverityCritical, 5)...)

		got := MineCandidates(in, 20)
		require.Len(t, got, 2)
		require.Equal(t, sa, got[0].Sig, "most instances first")
		require.Equal(t, 30, got[0].Instances)
		require.Equal(t, sb, got[1].Sig)
	})
}

func TestPatternSignature_String(t *testing.T) {
	require.Equal(t, "iam_user/page/elevated", sig("iam_user", "page", "elevated").String())
	require.Equal(t, "s3_bucket/high/-", sig("s3_bucket", "high", "").String(), "empty must_fix renders as -")
}
