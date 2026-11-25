package graphstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

// A cut frontier or a hit edge limit must be reported, never returned as if it
// were the whole neighbourhood.
func TestNeighbors_FlagsTruncation(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{{ID: "role-1", Type: "iam_role", Provider: "aws"}}
	var edges []asset.Edge
	var lbs []string
	for i := range maxQueryItems + 5 {
		id := fmt.Sprintf("lb-%04d", i)
		lbs = append(lbs, id)
		assets = append(assets, asset.Asset{ID: id, Type: "load_balancer", Provider: "aws"})
		edges = append(edges, asset.Edge{SrcID: id, SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role", EdgeType: "has_role"})
	}
	_, wc := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wc, assets, edges, nil))

	got, _, truncated, err := neighbors(wc, lbs[:3], nil, string(explore.DirectionOut), DefaultBudget)
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.False(t, truncated)

	_, _, truncated, err = neighbors(wc, lbs[:3], nil, string(explore.DirectionOut), QueryBudget{MaxEdges: 2})
	require.NoError(t, err)
	require.True(t, truncated, "hitting the edge limit is a truncation")

	_, _, truncated, err = neighbors(wc, lbs, nil, string(explore.DirectionOut), HardBudget)
	require.NoError(t, err)
	require.True(t, truncated, "a frontier past maxQueryItems is a truncation")

	// matchSeed chunks instead of cutting: the id past maxQueryItems resolves.
	nodes, err := matchSeed(wc, lbs, nil, "", 2000)
	require.NoError(t, err)
	require.Len(t, nodes, len(lbs))
}
