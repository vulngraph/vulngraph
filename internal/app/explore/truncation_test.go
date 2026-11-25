package explore

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// cutRepo answers every Neighbors call with one edge and truncated=true, as an
// engine that hit its own bound does.
type cutRepo struct{ edgeListRepo }

func (r cutRepo) Neighbors(ctx context.Context, ids, et []string, dir Direction) ([]Edge, []Node, bool, error) {
	edges, nodes, _, err := r.edgeListRepo.Neighbors(ctx, ids, et, dir)
	return edges, nodes, true, err
}

func TestRunAndExpand_PropagateEngineTruncation(t *testing.T) {
	repo := cutRepo{edgeListRepo{
		seeds: []Node{{ID: "a"}},
		edges: []Edge{{SrcID: "a", DstID: "b", EdgeType: "has_role"}},
	}}
	svc := NewService(repo)

	res, err := svc.Run(context.Background(), GraphQuerySpec{
		Seed:     NodeMatch{IDs: []string{"a"}},
		Traverse: []Traverse{{Direction: DirectionOut, MaxHops: 1}},
	})
	require.NoError(t, err)
	require.True(t, res.Truncated, "a truncated hop must mark the whole result truncated")

	res, err = svc.ExpandNode(context.Background(), "a", nil, DirectionOut)
	require.NoError(t, err)
	require.True(t, res.Truncated)
}

// Two nodes joined by several edge types are several edges; grouping the
// ClickHouse read by (src, dst) alone kept one arbitrary type.
func TestCHEdgeQueriesKeepEveryEdgeType(t *testing.T) {
	for _, q := range []string{edgesOut, edgesIn} {
		require.Contains(t, strings.Join(strings.Fields(q), " "), "GROUP BY src_id, dst_id, edge_type")
	}
}
