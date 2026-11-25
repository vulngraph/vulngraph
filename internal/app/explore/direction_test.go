package explore

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// edgeListRepo returns every stored edge touching the frontier in the requested
// direction, in stored (src→dst) orientation — the contract both the Ladybug and
// the ClickHouse Neighbors implement.
type edgeListRepo struct {
	seeds []Node
	edges []Edge
}

func (r edgeListRepo) MatchSeed(context.Context, NodeMatch, int) ([]Node, error) {
	return r.seeds, nil
}

func (r edgeListRepo) Neighbors(_ context.Context, ids, _ []string, dir Direction) ([]Edge, []Node, bool, error) {
	on := map[string]bool{}
	for _, id := range ids {
		on[id] = true
	}
	var out []Edge
	for _, e := range r.edges {
		if (dir != DirectionIn && on[e.SrcID]) || (dir != DirectionOut && on[e.DstID]) {
			out = append(out, e)
		}
	}
	return out, nil, false, nil
}

// Direction "both" must follow an inbound edge to its source. farEndpoint used
// to return DstID for every non-"in" walk, so an inbound edge's far end was the
// frontier node itself and the traversal never left it.
func TestRun_BothDirectionFollowsInboundEdges(t *testing.T) {
	repo := edgeListRepo{
		seeds: []Node{{ID: "c"}},
		edges: []Edge{
			{SrcID: "a", DstID: "c", EdgeType: "has_role"}, // inbound to c
			{SrcID: "c", DstID: "d", EdgeType: "runs_in"},  // outbound from c
			{SrcID: "x", DstID: "a", EdgeType: "has_role"}, // inbound to a, hop 2
		},
	}
	res, err := NewService(repo).Run(context.Background(), GraphQuerySpec{
		Seed:     NodeMatch{IDs: []string{"c"}},
		Traverse: []Traverse{{Direction: DirectionBoth, MaxHops: 2}},
	})
	require.NoError(t, err)
	got := ids(res)
	sort.Strings(got)
	require.Equal(t, []string{"a", "c", "d", "x"}, got)
}

func TestFarEndpoint(t *testing.T) {
	e := Edge{SrcID: "s", DstID: "d"}
	require.Equal(t, "d", farEndpoint(e, DirectionOut, map[string]bool{"s": true}))
	require.Equal(t, "s", farEndpoint(e, DirectionIn, map[string]bool{"d": true}))
	require.Equal(t, "d", farEndpoint(e, DirectionBoth, map[string]bool{"s": true}))
	require.Equal(t, "s", farEndpoint(e, DirectionBoth, map[string]bool{"d": true}))
}
