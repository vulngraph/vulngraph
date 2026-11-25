package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/explore"
)

type stubRiskTier struct {
	ready *bool
	nodes []explore.Node
	err   error
	asked [][]string
}

func (s *stubRiskTier) MatchSeed(_ context.Context, m explore.NodeMatch, _ int) ([]explore.Node, error) {
	s.asked = append(s.asked, m.IDs)
	if s.err != nil {
		return nil, s.err
	}
	var out []explore.Node
	for _, n := range s.nodes {
		for _, id := range m.IDs {
			if n.ID == id {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

func (s *stubRiskTier) Neighbors(context.Context, []string, []string, explore.Direction) ([]explore.Edge, []explore.Node, bool, error) {
	return nil, nil, false, nil
}

type readyRiskTier struct{ *stubRiskTier }

func (r readyRiskTier) Ready() bool { return *r.ready }

func TestLadybugRiskScores_TiersAndScoreColumn(t *testing.T) {
	notReady := false
	serve := readyRiskTier{&stubRiskTier{ready: &notReady, nodes: []explore.Node{{ID: "a", Type: "ec2_instance", Score: 1}}}}
	worker := &stubRiskTier{nodes: []explore.Node{
		{ID: "a", Type: "ec2_instance", Score: 80},
		{ID: "pkg", Type: "package", Score: 95},
	}}
	got, err := (&ladybugRiskScores{tiers: []explore.Repo{serve, worker}}).PropagatedRiskScores(context.Background(), []string{"a", "pkg", "gone"})
	require.NoError(t, err)
	assert.Empty(t, serve.asked, "an unready serve Ladybug is skipped, not trusted mid-sync")
	assert.Equal(t, map[string]uint8{"a": 80}, got, "a package's score column is a severity, and an id no tier holds stays absent")
}

func TestLadybugRiskScores_LaterTierAskedOnlyForMisses(t *testing.T) {
	ready := true
	serve := readyRiskTier{&stubRiskTier{ready: &ready, nodes: []explore.Node{{ID: "a", Type: "iam_role", Score: 60}}}}
	worker := &stubRiskTier{nodes: []explore.Node{{ID: "b", Type: "ec2_instance", Score: 30}}}
	got, err := (&ladybugRiskScores{tiers: []explore.Repo{serve, worker}}).PropagatedRiskScores(context.Background(), []string{"a", "b"})
	require.NoError(t, err)
	assert.Equal(t, map[string]uint8{"a": 60, "b": 30}, got)
	assert.Equal(t, [][]string{{"b"}}, worker.asked)
}

func TestLadybugRiskScores_AllTiersFailedIsAnError(t *testing.T) {
	failing := &stubRiskTier{err: errors.New("rpc down")}
	_, err := (&ladybugRiskScores{tiers: []explore.Repo{failing}}).PropagatedRiskScores(context.Background(), []string{"a"})
	require.Error(t, err, "a failed read must not read as 'engine holds none of these'")

	ok := &stubRiskTier{}
	got, err := (&ladybugRiskScores{tiers: []explore.Repo{failing, ok}}).PropagatedRiskScores(context.Background(), []string{"a"})
	require.NoError(t, err)
	assert.Empty(t, got)
}
