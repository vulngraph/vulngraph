package belief

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func baseCandidate() Candidate {
	return Candidate{
		Input:                 AdjudicationInput{RawScore: 80, RawBand: "high", Context: "ctx"},
		DeterministicSeverity: finding.SeverityHigh,
		Facts:                 allKnown(),
	}
}

// TestCandidateFingerprint_KnownBitFlipChangesFingerprint is the regression
// test for a fingerprint that hashed *Confirmed/*Present/*Evidenced but not
// the three *Known bits they pair with, so a witness becoming unreachable (or recovering) between
// sweeps — which changes what corroborationConflict actually does with this
// candidate — left the cache reporting "still fresh" via cachedFresh for up
// to RevalidateAfter, with no other hashed value having moved.
func TestCandidateFingerprint_KnownBitFlipChangesFingerprint(t *testing.T) {
	base := baseCandidate()
	baseFP := base.fingerprint()

	for _, tc := range []struct {
		name   string
		mutate func(*GroundingFacts)
	}{
		{"PublicAccessKnown", func(f *GroundingFacts) { f.PublicAccessKnown = false }},
		{"ExposedEdgeKnown", func(f *GroundingFacts) { f.ExposedEdgeKnown = false }},
		{"ExposurePeersKnown", func(f *GroundingFacts) { f.ExposurePeersKnown = false }},
		{"BlastKnown", func(f *GroundingFacts) { f.BlastKnown = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mutate(&c.Facts)
			require.NotEqual(t, baseFP, c.fingerprint(),
				"%s flipping must change the fingerprint — the corroboration gate's behavior changed even though "+
					"every OTHER hashed field is identical", tc.name)
		})
	}
}
