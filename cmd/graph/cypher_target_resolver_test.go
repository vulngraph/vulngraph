package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

type fakeCypherRunner struct{ res explore.Result }

func (f fakeCypherRunner) RunCypher(context.Context, string, int, int) (explore.Result, error) {
	return f.res, nil
}

type fakeResolverAssets struct{ called bool }

func (f *fakeResolverAssets) ByIDs(context.Context, []string) ([]asset.Asset, error) {
	f.called = true
	return nil, nil
}

// A result the engine flagged as possibly missing multi-hop rows cannot be a
// profile's target set: the scan would report the missing assets as out of scope.
func TestResolveFromCypher_RefusesFlaggedIncompleteResult(t *testing.T) {
	assets := &fakeResolverAssets{}
	r := &ladybugCypherTargetResolver{
		cypher: fakeCypherRunner{res: explore.Result{
			Nodes:                   []explore.Node{{ID: "a"}},
			MultiHopMayBeIncomplete: true,
		}},
		assets: assets,
	}
	targets, err := r.ResolveFromCypher(context.Background(), "MATCH (a)-[*1..3]->(b) RETURN b LIMIT 10")
	require.ErrorContains(t, err, "possibly incomplete")
	require.Nil(t, targets)
	require.False(t, assets.called)
}
