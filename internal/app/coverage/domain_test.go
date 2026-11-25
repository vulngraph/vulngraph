package coverage

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// ProviderScopes is the one hand-declared list in this package, because scope is
// a product decision and not a fact about the data. This is the test that keeps
// it from rotting into dead text: it derives the truth from asset/domain.go and
// fails in BOTH directions, so a new provider must be classified and a removed
// one must be dropped.
func TestProviderScopeCoversEveryDeclaredProvider(t *testing.T) {
	declared := providerConstants(t, "../asset/domain.go")
	require.NotEmpty(t, declared, "no asset.Provider constants found — the scan broke, not the source")

	classified := map[string]int{}
	for _, s := range ProviderScopes {
		classified[s.Provider]++
	}
	for _, p := range declared {
		assert.Equal(t, 1, classified[p], "provider %q must be classified exactly once in ProviderScopes", p)
	}
	for p := range classified {
		assert.Contains(t, declared, p, "ProviderScopes names %q, which is no longer an asset.Provider constant", p)
	}
}

func TestProviderScopeReasonsAreStated(t *testing.T) {
	for _, s := range ProviderScopes {
		assert.NotEmpty(t, s.Reason, "provider %q is classified with no reason — an unreasoned scope decision is indistinguishable from an oversight", s.Provider)
	}
}

// providerConstants extracts `X Provider = "y"` constants from a source file.
func providerConstants(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	require.NoError(t, err)

	var out []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "Provider" {
				continue
			}
			for i := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				bl, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				v, err := strconv.Unquote(bl.Value)
				require.NoError(t, err)
				out = append(out, v)
			}
		}
	}
	return out
}

// The lineage chain is declared as data. A rename in either registry must turn
// it red rather than silently producing a zero in a document people trust.
func TestLineageStagesReferenceTheRegistries(t *testing.T) {
	edges := map[string]bool{}
	for _, e := range graphschema.EdgeTypes {
		edges[e.Type] = true
	}
	checkTypes := map[string]bool{}
	for _, c := range checks.Default().All() {
		if c.AssetType != "" {
			checkTypes[c.AssetType] = true
		}
	}
	names := map[string]bool{}
	for _, s := range LineageStages {
		names[s.Name] = true
	}

	for _, s := range LineageStages {
		assert.NotEmpty(t, s.Question, "stage %q must say what a zero would mean", s.Name)
		switch s.Kind {
		case StageAssets:
			assert.NotEmpty(t, s.Types, "asset stage %q names no asset types", s.Name)
			assert.Empty(t, s.EdgeType, "asset stage %q must not name an edge type", s.Name)
		case StageEdgeSrc, StageEdgeDst:
			assert.True(t, edges[s.EdgeType], "stage %q names edge type %q, absent from graphschema.EdgeTypes", s.Name, s.EdgeType)
		case StageAssetMeta:
			assert.NotEmpty(t, s.Types, "metadata stage %q names no asset types", s.Name)
			assert.NotEmpty(t, s.MetaKey, "metadata stage %q names no key", s.Name)
			assert.NotEmpty(t, s.MetaValues, "metadata stage %q counts no value", s.Name)
			assert.Empty(t, s.EdgeType, "metadata stage %q must not name an edge type", s.Name)
		default:
			t.Fatalf("stage %q has unknown kind %q", s.Name, s.Kind)
		}
		for _, ty := range s.Types {
			assert.True(t, checkTypes[ty], "stage %q names asset type %q, which no registered check targets", s.Name, ty)
		}
		if s.OfStage != "" {
			assert.True(t, names[s.OfStage], "stage %q is a percentage of %q, which is not a stage", s.Name, s.OfStage)
		}
	}
}

// A seed is not a movement edge, which is exactly why graphschema carries no
// flag for it and why this package has to declare it. If a named seed ever
// gains Reach it stopped being a seed, and if it leaves the registry the
// scoring rule is silently measuring nothing.
func TestScoringSeedsAreRegisteredNonReachTypes(t *testing.T) {
	require.NotEmpty(t, ScoringSeedEdgeTypes)
	byType := map[string]graphschema.EdgeType{}
	for _, e := range graphschema.EdgeTypes {
		byType[e.Type] = e
	}
	reach := graphschema.ReachEdgeTypes()
	for _, seed := range ScoringSeedEdgeTypes {
		e, ok := byType[seed]
		require.True(t, ok, "seed %q is not in graphschema.EdgeTypes", seed)
		assert.False(t, e.Reach, "seed %q is marked Reach — it is a movement edge now, not a seed", seed)
		assert.False(t, reach[seed], "seed %q is in the reach set", seed)
	}
}

func TestAxesAreThePipelineOrder(t *testing.T) {
	require.Len(t, Axes, 4)
	assert.Equal(t, []Axis{AxisCollected, AxisEvidence, AxisCheck, AxisGraph}, axisList(),
		"axis order is load-bearing: deriveAxis returns the first failing axis")
	for _, a := range Axes {
		assert.NotEmpty(t, a.Rule, "axis %q has no assignment rule, which makes it a judgement call", a.Axis)
	}
}

func TestEvidenceBoundIsAFraction(t *testing.T) {
	cases := []struct {
		name string
		c    CheckFact
		want float64
	}{
		{"structural check cannot lack evidence", CheckFact{}, 1},
		{"no applicable assets", CheckFact{RequiredKeys: []string{"k"}}, 0},
		{"partial", CheckFact{RequiredKeys: []string{"k"}, Applicable: 2000, WorstKeyPresent: 500}, 500.0 / 2000.0},
		{"complete", CheckFact{RequiredKeys: []string{"k"}, Applicable: 10, WorstKeyPresent: 10}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.InDelta(t, tc.want, tc.c.EvidenceBound(), 1e-9)
		})
	}
}

func TestStaleDaysDistinguishesNeverFromOld(t *testing.T) {
	now := mustTime(t, "2026-08-04T00:00:00Z")
	assert.Equal(t, -1, SourceFact{}.StaleDays(now), "never produced must not read as zero days stale")
	assert.Equal(t, 40, SourceFact{LastDetected: mustTime(t, "2026-06-25T00:00:00Z")}.StaleDays(now))
}
