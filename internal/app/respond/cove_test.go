package respond

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
)

func seed(a asset.Asset, reachable int, edges ...asset.Edge) asset.BlastRadius {
	assets := []asset.Asset{a}
	for range reachable {
		assets = append(assets, asset.Asset{ID: "n", Type: "ec2_instance"})
	}
	return asset.BlastRadius{Assets: assets, Edges: edges}
}

func highConf() memory.Confidence { return memory.Confidence{Band: memory.BandHigh} }

func TestCoVe_CleanLowRiskDoesNotEscalate(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1", Type: "ec2_instance"}, 1)
	r := verify(Plan{ActionClass: ClassRemediate}, finding.Finding{Score: 40}, br, highConf())
	require.False(t, r.escalate)
	require.Empty(t, r.concerns)
}

func TestCoVe_Check0_WeightedBlastCircuitBreaker(t *testing.T) {
	// 12 protected_by edges × blastRelWeights["protected_by"] (0.9) = 10.8 ≥
	// 10.0 threshold. This is the CoVe breaker's own weight table
	// (blastRelWeights) — deliberately not graphschema.WeightFor; see its
	// doc comment. Do not rewrite this to a different edge type (e.g.
	// can_assume) to make it pass: switching to the shared registry would
	// silently loosen the breaker's trip point.
	var edges []asset.Edge
	for range 12 {
		edges = append(edges, asset.Edge{EdgeType: "protected_by"})
	}
	br := seed(asset.Asset{ID: "i-1"}, 1, edges...)
	r := verify(Plan{ActionClass: ClassObserve}, finding.Finding{Score: 10}, br, highConf())
	require.True(t, r.escalate)
	require.Contains(t, r.concerns[0], "weighted blast radius")
}

// TestCoVe_Check0_JustBelowThresholdDoesNotEscalate pins the OTHER side of
// the trip point — one fewer protected_by edge (11 × 0.9 = 9.9 < 10.0) must
// not trip the breaker. Without this, a future weight/threshold change could
// widen the trip point (never escalating when it should) and the "≥" test
// above would stay green as long as ITS specific scenario still clears the
// bar — this catches the breaker becoming too permissive from the other
// direction.
func TestCoVe_Check0_JustBelowThresholdDoesNotEscalate(t *testing.T) {
	var edges []asset.Edge
	for range 11 {
		edges = append(edges, asset.Edge{EdgeType: "protected_by"})
	}
	br := seed(asset.Asset{ID: "i-1"}, 1, edges...)
	r := verify(Plan{ActionClass: ClassObserve}, finding.Finding{Score: 10}, br, highConf())
	require.False(t, r.escalate, "11 × 0.9 = 9.9 must stay below the 10.0 breaker threshold")
}

func TestCoVe_Check2_WideReachHighScore(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1"}, 5, asset.Edge{EdgeType: "runs_in"}) // 6 assets
	r := verify(Plan{ActionClass: ClassObserve}, finding.Finding{Score: 85}, br, highConf())
	require.True(t, r.escalate)
}

// TestCoVe_Check2_JustBelowThresholdDoesNotEscalate pins the OTHER side of
// Check 2's trip point — the boundary the seed exclusion moved
// (reachableAssets): before it, Check 2 compared len(br.Assets) (seed
// included) against 5, so a finding with 4 REACHABLE assets (5 total) used
// to trip it; now it compares the reachable count alone, so 4 must NOT trip
// it (nothing previously distinguished 4-reachable from 5-reachable).
func TestCoVe_Check2_JustBelowThresholdDoesNotEscalate(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1"}, 4, asset.Edge{EdgeType: "runs_in"}) // 5 assets, 4 reachable
	r := verify(Plan{ActionClass: ClassObserve}, finding.Finding{Score: 85}, br, highConf())
	require.False(t, r.escalate, "4 reachable assets must stay below Check 2's 5-reachable threshold")
}

func TestCoVe_Check3_DestructiveOnPublicAsset(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4"}, 0)
	r := verify(Plan{ActionClass: ClassDestroy}, finding.Finding{Score: 50}, br, highConf())
	require.True(t, r.escalate)
	require.Contains(t, concatConcerns(r), "internet-facing")
}

func TestCoVe_Check3_RemediateOnPublicDoesNotFire(t *testing.T) {
	// Non-destructive action on a public asset is allowed past Check 3.
	br := seed(asset.Asset{ID: "i-1", PublicIP: "1.2.3.4"}, 0)
	r := verify(Plan{ActionClass: ClassRemediate}, finding.Finding{Score: 50}, br, highConf())
	require.False(t, r.escalate)
}

func TestCoVe_Check4_ProductionDestructiveHighScore(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1", Tags: map[string]string{"environment": "production"}}, 0)
	r := verify(Plan{ActionClass: ClassIsolate}, finding.Finding{Score: 75}, br, highConf())
	require.True(t, r.escalate)
}

func TestCoVe_Check4_NonProductionDestructiveDoesNotFire(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1", Tags: map[string]string{"environment": "dev"}}, 0)
	r := verify(Plan{ActionClass: ClassDestroy}, finding.Finding{Score: 75}, br, highConf())
	// dev + destroy + high score: Check 4 needs production; Check 3 needs public IP (none).
	require.False(t, r.escalate)
}

// Check 4 reads asset.ClassifyEnvironment fail-closed: only a positive
// staging/dev classification escapes; unknown (and no seed at all) counts as
// production, and the concern says which of the two it was.
func TestCoVe_Check4_EnvironmentClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		br       asset.BlastRadius
		escalate bool
		concern  string
	}{
		{"tagged prod", seed(asset.Asset{ID: "i-1", Tags: map[string]string{"env": "prd"}}, 0), true, "on a production asset"},
		{"namespaced prod tag", seed(asset.Asset{ID: "i-1", Tags: map[string]string{"acme.io/stage": "live"}}, 0), true, "on a production asset"},
		{"GCP prod project", seed(asset.Asset{ID: "i-1", AccountID: "acme-prod-1"}, 0), true, "on a production asset"},
		{"untagged is unknown, treated as prod", seed(asset.Asset{ID: "i-1"}, 0), true, "unknown-environment (treated as production)"},
		{"conflicting tags are unknown", seed(asset.Asset{ID: "i-1", Tags: map[string]string{"env": "prod", "stage": "dev"}}, 0), true, "unknown-environment"},
		{"non-prod names no stage, so unknown", seed(asset.Asset{ID: "i-1", Tags: map[string]string{"env": "non-prod"}}, 0), true, "unknown-environment"},
		{"no seed is unknown", asset.BlastRadius{}, true, "unknown-environment"},
		{"staging escapes", seed(asset.Asset{ID: "i-1", Tags: map[string]string{"stage": "staging"}}, 0), false, ""},
		{"dev via metadata escapes", seed(asset.Asset{ID: "i-1", Metadata: map[string]string{"environment": "development"}}, 0), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := verify(Plan{ActionClass: ClassDestroy}, finding.Finding{Score: 75}, tc.br, highConf())
			require.Equal(t, tc.escalate, r.escalate, concatConcerns(r))
			if tc.concern != "" {
				require.Contains(t, concatConcerns(r), tc.concern)
			}
		})
	}
}

func TestCoVe_Check7_MediumConfidenceDestructive(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1", Tags: map[string]string{"environment": "dev"}}, 0)
	r := verify(Plan{ActionClass: ClassDestroy}, finding.Finding{Score: 20}, br,
		memory.Confidence{Band: memory.BandMedium})
	require.True(t, r.escalate)
	require.Contains(t, concatConcerns(r), "medium-confidence")
}

func TestCoVe_HighConfidenceRemediateNoConcern(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1", Tags: map[string]string{"environment": "dev"}}, 1)
	r := verify(Plan{ActionClass: ClassRemediate}, finding.Finding{Score: 50}, br, highConf())
	require.False(t, r.escalate)
}

// TestWeightedBlastScore_UnknownEdgeWeight pins weightedBlastScore's own
// table (blastRelWeights), including its unknown-edge-type fallback — this
// is deliberately NOT graphschema.WeightFor; see blastRelWeights' doc
// comment for why the two must stay independent.
func TestWeightedBlastScore_UnknownEdgeWeight(t *testing.T) {
	br := asset.BlastRadius{Edges: []asset.Edge{{EdgeType: "mystery"}, {EdgeType: "protected_by"}}}
	require.InDelta(t, 0.2+0.9, weightedBlastScore(br), 0.001)
}

func concatConcerns(r coveResult) string {
	out := ""
	for _, c := range r.concerns {
		out += c + " | "
	}
	return out
}
