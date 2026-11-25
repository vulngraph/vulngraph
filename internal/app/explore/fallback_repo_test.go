package explore

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type stubRepo struct {
	nodes []Node
	err   error
	calls *int
}

func (s stubRepo) MatchSeed(_ context.Context, _ NodeMatch, _ int) ([]Node, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.nodes, s.err
}
func (s stubRepo) Neighbors(_ context.Context, _, _ []string, _ Direction) ([]Edge, []Node, bool, error) {
	return nil, s.nodes, false, s.err
}

func TestFallbackRepo_UsesPrimaryThenFallsBack(t *testing.T) {
	ctx := context.Background()

	// Primary healthy → fallback never consulted.
	var fbCalls int
	r := NewFallbackRepo(
		stubRepo{nodes: []Node{{ID: "from-ladybug"}}},
		stubRepo{nodes: []Node{{ID: "from-ch"}}, calls: &fbCalls},
	)
	got, err := r.MatchSeed(ctx, NodeMatch{}, 10)
	require.NoError(t, err)
	require.Equal(t, "from-ladybug", got[0].ID)
	require.Zero(t, fbCalls, "fallback not consulted when primary succeeds")

	// Primary errors → fallback serves the result.
	r = NewFallbackRepo(
		stubRepo{err: errors.New("ladybug down")},
		stubRepo{nodes: []Node{{ID: "from-ch"}}},
	)
	got, err = r.MatchSeed(ctx, NodeMatch{}, 10)
	require.NoError(t, err)
	require.Equal(t, "from-ch", got[0].ID)
}

func TestNewFallbackRepo_NilPrimaryReturnsFallback(t *testing.T) {
	fb := stubRepo{nodes: []Node{{ID: "ch"}}}
	require.Equal(t, Repo(fb), NewFallbackRepo(nil, fb))
}

func TestResult_NonNil_NeverSerializesNull(t *testing.T) {
	// A nil-slice Result must marshal as [] arrays, not null — the frontend and
	// OpenAPI contract treat nodes/edges as required arrays.
	r := Result{}.NonNil()
	require.NotNil(t, r.Nodes)
	require.NotNil(t, r.Edges)
	require.Empty(t, r.Nodes)
	require.Empty(t, r.Edges)
}
