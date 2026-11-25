package explore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// The behaviour these tests pin: Ladybug is a FILTERED projection of ClickHouse
// (filterLadybugAssets prunes any asset with no retention edge and no risk score —
// typically many dns_record and dns_zone assets), so "zero rows, nil
// error" from a Ladybug tier is byte-identical to "no such asset". Both tier
// wrappers used to switch on err alone, which made a pruned node short-circuit
// the ClickHouse tier that still holds it: GET /api/graph/expand answered 200
// {"nodes":[],"edges":[]} and a seeded view answered 400 ErrNoSeed for an asset
// the inventory lists.

// graphRepo is a Repo stub that can return an empty-but-successful answer, the
// way Ladybug does for a pruned node.
type graphRepo struct {
	nodes []Node
	edges []Edge
	calls *int
}

func (g graphRepo) MatchSeed(_ context.Context, _ NodeMatch, _ int) ([]Node, error) {
	if g.calls != nil {
		*g.calls++
	}
	return g.nodes, nil
}

func (g graphRepo) Neighbors(_ context.Context, _, _ []string, _ Direction) ([]Edge, []Node, bool, error) {
	if g.calls != nil {
		*g.calls++
	}
	return g.edges, g.nodes, false, nil
}

type countingObserver struct{ ops []string }

func (c *countingObserver) ObserveGraphTierFallthrough(op string) { c.ops = append(c.ops, op) }

func TestFallbackRepo_PrunedNodeReachesClickHouse(t *testing.T) {
	ctx := context.Background()
	pruned := "arn:aws:route53:::record/foo.example.com/CNAME"

	ladybug := graphRepo{} // pruned: empty, nil error
	ch := graphRepo{
		nodes: []Node{{ID: pruned, Type: "dns_record"}},
		edges: []Edge{{SrcID: pruned, DstID: "zone-1", EdgeType: "member_of_zone"}},
	}
	obs := &countingObserver{}
	r := NewFallbackRepo(ladybug, ch, obs)

	seeds, err := r.MatchSeed(ctx, NodeMatch{IDs: []string{pruned}}, 1)
	require.NoError(t, err)
	require.Len(t, seeds, 1, "an ID-keyed seed Ladybug does not hold must be answered from ClickHouse, not reported absent")
	require.Equal(t, "dns_record", seeds[0].Type)

	edges, _, _, err := r.Neighbors(ctx, []string{pruned}, nil, DirectionBoth)
	require.NoError(t, err)
	require.Len(t, edges, 1, "an ID-keyed expand Ladybug does not hold must be answered from ClickHouse")

	require.Equal(t, []string{"seed", "neighbors"}, obs.ops,
		"the fall-through must be counted — a zero rate on graph_explore_tier_empty_fallthrough_total is how this ships inert")
}

func TestTieredRepo_PrunedNodeReachesClickHouse(t *testing.T) {
	ctx := context.Background()
	pruned := "arn:aws:route53:::record/foo.example.com/CNAME"

	var chCalls int
	ch := graphRepo{
		nodes: []Node{{ID: pruned, Type: "dns_record"}},
		edges: []Edge{{SrcID: pruned, DstID: "zone-1", EdgeType: "member_of_zone"}},
		calls: &chCalls,
	}
	obs := &countingObserver{}
	r := NewTieredRepo(graphRepo{}, graphRepo{}, ch, obs)

	seeds, err := r.MatchSeed(ctx, NodeMatch{IDs: []string{pruned}}, 1)
	require.NoError(t, err)
	require.Len(t, seeds, 1, "both Ladybug tiers answering empty must not short-circuit the ClickHouse tier")

	edges, _, _, err := r.Neighbors(ctx, []string{pruned}, nil, DirectionBoth)
	require.NoError(t, err)
	require.Len(t, edges, 1)

	require.Equal(t, 2, chCalls)
	require.Equal(t, []string{"seed", "neighbors"}, obs.ops)
}

// A loaded node whose Ladybug answer is legitimately populated must NOT pay for a
// ClickHouse round-trip, and a SELECTOR seed (types/provider, no ids) must keep
// its empty answer: "no such assets in the traversable graph" is a true statement
// about the graph, and falling through would seed views with the isolated nodes
// the prune exists to keep out.
func TestTierFallthrough_DoesNotFireForLoadedNodeOrSelectorSeed(t *testing.T) {
	ctx := context.Background()

	var chCalls int
	ch := graphRepo{nodes: []Node{{ID: "from-ch"}}, calls: &chCalls}
	obs := &countingObserver{}
	r := NewFallbackRepo(graphRepo{nodes: []Node{{ID: "loaded"}}}, ch, obs)

	seeds, err := r.MatchSeed(ctx, NodeMatch{IDs: []string{"loaded"}}, 1)
	require.NoError(t, err)
	require.Equal(t, "loaded", seeds[0].ID)
	require.Zero(t, chCalls)

	// Selector seed with an empty Ladybug answer: stays empty, no fall-through.
	r = NewFallbackRepo(graphRepo{}, ch, obs)
	seeds, err = r.MatchSeed(ctx, NodeMatch{Types: []string{"dns_record"}}, 10)
	require.NoError(t, err)
	require.Empty(t, seeds)
	require.Zero(t, chCalls, "a selector seed must not fall through to ClickHouse")
	require.Empty(t, obs.ops)
}

func TestEmptyIsMiss(t *testing.T) {
	require.True(t, emptyIsMiss(0, []string{"id-1"}), "empty answer to an ID-keyed lookup is a miss")
	require.False(t, emptyIsMiss(1, []string{"id-1"}), "a populated answer is never a miss")
	require.False(t, emptyIsMiss(0, nil), "a selector lookup's empty answer is a true answer")
}
