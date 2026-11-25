package explore

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeRepo is an in-memory graph for service tests.
type fakeRepo struct {
	seeds   []Node
	out     map[string][]Edge // edges by src id
	nodes   map[string]Node
	seedErr error
}

func (f *fakeRepo) MatchSeed(_ context.Context, _ NodeMatch, _ int) ([]Node, error) {
	return f.seeds, f.seedErr
}

func (f *fakeRepo) Neighbors(_ context.Context, ids, _ []string, dir Direction) ([]Edge, []Node, bool, error) {
	var edges []Edge
	nodeSet := map[string]Node{}
	for _, id := range ids {
		for _, e := range f.out[id] {
			edges = append(edges, e)
			if n, ok := f.nodes[e.DstID]; ok {
				nodeSet[e.DstID] = n
			}
		}
	}
	var nodes []Node
	for _, n := range nodeSet {
		nodes = append(nodes, n)
	}
	return edges, nodes, false, nil
}

func ids(r Result) []string {
	out := make([]string, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		out = append(out, n.ID)
	}
	return out
}

func graph() *fakeRepo {
	return &fakeRepo{
		nodes: map[string]Node{
			"a": {ID: "a", Type: "ec2_instance"}, "b": {ID: "b", Type: "security_group"},
			"c": {ID: "c", Type: "rds_instance"}, "d": {ID: "d", Type: "vpc"},
		},
		out: map[string][]Edge{
			"a": {{SrcID: "a", DstID: "b", EdgeType: "protected_by"}, {SrcID: "a", DstID: "c", EdgeType: "can_access"}},
			"c": {{SrcID: "c", DstID: "d", EdgeType: "runs_in"}},
		},
	}
}

func TestRun_NoSeed(t *testing.T) {
	_, err := NewService(&fakeRepo{}).Run(context.Background(), GraphQuerySpec{})
	require.ErrorIs(t, err, ErrNoSeed)
}

func TestRun_SingleHop(t *testing.T) {
	repo := graph()
	repo.seeds = []Node{{ID: "a", Type: "ec2_instance"}}
	res, err := NewService(repo).Run(context.Background(), GraphQuerySpec{
		Seed:     NodeMatch{IDs: []string{"a"}},
		Traverse: []Traverse{{Direction: DirectionOut, MaxHops: 1}},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "b", "c"}, ids(res))
	require.Len(t, res.Edges, 2)
}

func TestRun_MultiHopReachesGrandchild(t *testing.T) {
	repo := graph()
	repo.seeds = []Node{{ID: "a"}}
	res, err := NewService(repo).Run(context.Background(), GraphQuerySpec{
		Seed:     NodeMatch{IDs: []string{"a"}},
		Traverse: []Traverse{{Direction: DirectionOut, MaxHops: 3}},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "b", "c", "d"}, ids(res), "hop 2 reaches d via c")
}

func TestRun_HopsClampedAndDefaulted(t *testing.T) {
	repo := graph()
	repo.seeds = []Node{{ID: "a"}}
	// MaxHops 0 → defaults to 1; only direct neighbors.
	res, err := NewService(repo).Run(context.Background(), GraphQuerySpec{
		Seed:     NodeMatch{IDs: []string{"a"}},
		Traverse: []Traverse{{Direction: DirectionOut}},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "b", "c"}, ids(res), "default 1 hop, d not reached")
}

func TestRun_NodeBudgetTruncates(t *testing.T) {
	repo := &fakeRepo{nodes: map[string]Node{}, out: map[string][]Edge{"seed": {}}}
	repo.seeds = []Node{{ID: "seed"}}
	for i := 0; i < 50; i++ {
		id := "n" + strconv.Itoa(i)
		repo.nodes[id] = Node{ID: id}
		repo.out["seed"] = append(repo.out["seed"], Edge{SrcID: "seed", DstID: id, EdgeType: "x"})
	}
	res, err := NewService(repo).Run(context.Background(), GraphQuerySpec{
		Seed:     NodeMatch{IDs: []string{"seed"}},
		Traverse: []Traverse{{Direction: DirectionOut, MaxHops: 1}},
		MaxNodes: 10,
	})
	require.NoError(t, err)
	require.True(t, res.Truncated)
	require.LessOrEqual(t, len(res.Nodes), 11)
}

func TestRun_CycleSafe(t *testing.T) {
	repo := &fakeRepo{
		nodes: map[string]Node{"a": {ID: "a"}, "b": {ID: "b"}},
		out:   map[string][]Edge{"a": {{SrcID: "a", DstID: "b", EdgeType: "x"}}, "b": {{SrcID: "b", DstID: "a", EdgeType: "x"}}},
	}
	repo.seeds = []Node{{ID: "a"}}
	res, err := NewService(repo).Run(context.Background(), GraphQuerySpec{
		Seed:     NodeMatch{IDs: []string{"a"}},
		Traverse: []Traverse{{Direction: DirectionOut, MaxHops: 10}},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"a", "b"}, ids(res))
}

func TestExpandNode(t *testing.T) {
	repo := graph()
	res, err := NewService(repo).ExpandNode(context.Background(), "a", nil, DirectionOut)
	require.NoError(t, err)
	require.Len(t, res.Edges, 2)
}

func TestExpandNode_EmptyID(t *testing.T) {
	_, err := NewService(graph()).ExpandNode(context.Background(), "", nil, DirectionBoth)
	require.ErrorIs(t, err, ErrInvalidSpec)
}

type fakeTranslator struct {
	spec  GraphQuerySpec
	err   error
	gotNL string
}

func (f *fakeTranslator) Translate(_ context.Context, nl string) (GraphQuerySpec, error) {
	f.gotNL = nl
	return f.spec, f.err
}

func TestTranslate_Unavailable(t *testing.T) {
	_, err := NewService(graph()).Translate(context.Background(), "anything")
	require.ErrorIs(t, err, ErrTranslateUnavailable)
}

func TestTranslate_UsesTranslator(t *testing.T) {
	tr := &fakeTranslator{spec: GraphQuerySpec{Seed: NodeMatch{Types: []string{"ec2_instance"}}}}
	svc := NewService(graph(), WithTranslator(tr))

	spec, err := svc.Translate(context.Background(), "show me ec2 instances")
	require.NoError(t, err)
	require.Equal(t, []string{"ec2_instance"}, spec.Seed.Types)
	require.Equal(t, "show me ec2 instances", tr.gotNL)
}

func TestClamp(t *testing.T) {
	require.Equal(t, 5, clamp(0, 5, 100))
	require.Equal(t, 100, clamp(500, 5, 100))
	require.Equal(t, 42, clamp(42, 5, 100))
}

type fixedCypherTranslator struct{ q string }

func (f fixedCypherTranslator) TranslateToCypher(context.Context, string) (string, error) {
	return f.q, nil
}

type capRecordingCypher struct{ nodes, edges int }

func (c *capRecordingCypher) RunCypher(_ context.Context, _ string, maxNodes, maxEdges int) (Result, error) {
	c.nodes, c.edges = maxNodes, maxEdges
	return Result{}, nil
}

// TestTranslateAndRunCypher_ClampsRequestedCaps: the NL endpoint's max_nodes /
// max_edges reach the runner, unset means the defaults, and nothing above the
// hard cap gets through.
func TestTranslateAndRunCypher_ClampsRequestedCaps(t *testing.T) {
	svc := NewService(&fakeRepo{}, WithCypherTranslator(fixedCypherTranslator{q: "MATCH (a:Asset) RETURN a LIMIT 1"}))
	for _, tc := range []struct {
		name                 string
		reqNodes, reqEdges   int
		wantNodes, wantEdges int
	}{
		{"requested", 500, 2000, 500, 2000},
		{"unset", 0, 0, defaultMaxNodes, defaultMaxEdges},
		{"above hard cap", 1_000_000, 1_000_000, hardMaxNodes, hardMaxEdges},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &capRecordingCypher{}
			_, _, err := svc.TranslateAndRunCypher(context.Background(), run, "q", tc.reqNodes, tc.reqEdges)
			require.NoError(t, err)
			require.Equal(t, tc.wantNodes, run.nodes)
			require.Equal(t, tc.wantEdges, run.edges)
		})
	}
}
