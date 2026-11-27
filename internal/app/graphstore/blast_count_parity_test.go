package graphstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestBlastCountAdjacencyMatchesNative(t *testing.T) {
	assets, edges := blastFixture()
	// Duplicates, cycles, unloaded relationships and label-invalid edges must
	// not change the native traversal's meaning.
	edges = append(edges, edges[0], asset.Edge{SrcID: "role-2", DstID: "role-1", SrcType: "iam_role", DstType: "iam_role", EdgeType: "can_assume"},
		asset.Edge{SrcID: "lb-a", DstID: "role-2", EdgeType: "peered_with"},
		asset.Edge{SrcID: "lb-a", DstID: "role-2", EdgeType: "connected_via_sg"})
	_, conn := openTestDB(t)
	require.NoError(t, bulkSync(t.Context(), conn, assets, edges, nil))
	adj := buildBlastAdjacency(assets, edges)
	for _, seed := range []string{"lb-a", "lb-c", "role-1", "missing"} {
		for _, depth := range []int{-1, 1, 2, 3, 5, 6} {
			want, err := blastRadiusCount(conn, seed, depth)
			require.NoError(t, err)
			got, err := adj.count(t.Context(), seed, depth)
			require.NoError(t, err)
			require.Equal(t, want, got, "seed=%s depth=%d", seed, depth)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := adj.count(ctx, "lb-a", 2)
	require.ErrorIs(t, err, context.Canceled)
}

func TestBlastCountAdjacencyMatchesNativeCap(t *testing.T) {
	assets := []asset.Asset{{ID: "hub", Type: "load_balancer"}}
	var edges []asset.Edge
	for i := 0; i < blastRadiusCountCap+10; i++ {
		id := fmt.Sprintf("leaf-%d", i)
		assets = append(assets, asset.Asset{ID: id, Type: "load_balancer"})
		edges = append(edges, asset.Edge{SrcID: "hub", DstID: id, EdgeType: "connected_via_sg"})
	}
	_, conn := openTestDB(t)
	require.NoError(t, bulkSync(t.Context(), conn, assets, edges, nil))
	want, err := blastRadiusCount(conn, "hub", 2)
	require.NoError(t, err)
	got, err := buildBlastAdjacency(assets, edges).count(t.Context(), "hub", 2)
	require.NoError(t, err)
	require.Equal(t, blastRadiusCountCap, want)
	require.Equal(t, want, got)
}
