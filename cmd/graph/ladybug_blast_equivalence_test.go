package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
)

// equivAssets/equivEdges are minimal graphstore.AssetSource/EdgeSource
// implementations for building a real, synced Ladybug graph in-memory — the same
// shape sync_test.go's stubAssets/stubEdges use, reimplemented here rather than
// exported cross-package for a one-test need.
type equivAssets struct{ a []asset.Asset }

func (s equivAssets) ListAll(context.Context, asset.SyncProjection) (asset.AssetSyncResult, error) {
	return asset.AssetSyncResult{Assets: s.a}, nil
}

type equivEdges struct{ e []asset.Edge }

func (s equivEdges) AllEdges(context.Context, asset.SyncProjection) (asset.EdgeSyncResult, error) {
	return asset.EdgeSyncResult{Edges: s.e}, nil
}

func (s equivEdges) VerifyDepartedAssets(context.Context, []string) (map[string]bool, error) {
	return nil, nil
}

// TestLadybugBlastEquivalence_RetainedAdjacencyMatchesCypherCount pins the two
// blast-radius walks together: graphstore has TWO
// independent implementations of "reachable from seed" over the same loaded
// topology — the live Cypher BFS (graphstore.BlastRadiusCount, what enrich's
// must-fix classification counts against) and the retained Go-side adjacency
// walk (ladybugBlastProvider.BlastRadius here, what respond.Decide counts
// against). graphschema.BlastDepth already unifies the DEPTH the two walk;
// this pins the SET they walk over, so a future change to either one's
// edge-type/label scope (a new rel added to LoadedRels() but not routed into
// buildBlastAdjacency, or vice versa) fails a test immediately instead of
// silently reintroducing the class of drift where respond counted the seed
// itself and enrich did not.
//
// Both counts below exclude the seed — reachableAssets' convention
// (respond/contextpack.go) — since that is what BOTH real callers agree
// on; a future change to either side's convention should
// break this test, not just drift silently past it.
func TestLadybugBlastEquivalence_RetainedAdjacencyMatchesCypherCount(t *testing.T) {
	ctx := context.Background()
	svc, err := graphstore.Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	// A 2-hop IamRole chain over can_assume — loaded, Reach-tiered, DirBoth
	// (graphschema.go). Deliberately homogeneous (one edge type, one label pair):
	// mixing in a cross-label edge type here would make a labelMismatch drop
	// during the Ladybug COPY step (copy_load_parity.go's own "a bug" case) a
	// confound in THIS test rather than a separate, already-tracked signal.
	assets := []asset.Asset{
		{ID: "role-1", Name: "role-1", Type: "iam_role", Provider: "aws"},
		{ID: "role-2", Name: "role-2", Type: "iam_role", Provider: "aws"},
		{ID: "role-3", Name: "role-3", Type: "iam_role", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "role-1", SrcType: "iam_role", DstID: "role-2", DstType: "iam_role", EdgeType: "can_assume"},
		{SrcID: "role-2", SrcType: "iam_role", DstID: "role-3", DstType: "iam_role", EdgeType: "can_assume"},
	}
	require.NoError(t, svc.SyncFromSources(ctx, 0, equivAssets{assets}, equivEdges{edges}, nil))

	provider := &ladybugBlastProvider{graph: svc, assets: nil} // no CH fallback expected — the seed is loaded

	for _, depth := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("depth=%d", depth), func(t *testing.T) {
			cypherCount, err := svc.BlastRadiusCount(ctx, "role-1", depth)
			require.NoError(t, err)

			br, err := provider.BlastRadius(ctx, "role-1", depth)
			require.NoError(t, err)
			require.Positive(t, len(br.Assets), "seed must resolve in the retained adjacency — CH fallback is nil")
			adjacencyCount := len(br.Assets) - 1 // exclude the seed at index 0, same convention as reachableAssets

			require.Equal(t, cypherCount, adjacencyCount,
				"the live Cypher BFS and the retained Go adjacency walk must agree on the reachable count "+
					"from the same seed over the same synced topology at depth %d — a mismatch means one side's "+
					"edge-type/label scope has drifted from the other's", depth)
		})
	}
}
