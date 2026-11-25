package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// boostFixture is two nodes and an edge that produce at least one BFS boost.
func boostFixture(roleScore uint8) ([]asset.Asset, []asset.Edge) {
	assets := []asset.Asset{
		{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50},
		{ID: "role-1", Name: "admin", Type: "iam_role", Provider: "aws", RiskScore: roleScore},
	}
	edges := []asset.Edge{{SrcID: "lb-1", SrcType: "load_balancer", DstID: "role-1",
		DstType: "iam_role", EdgeType: "has_role", Properties: map[string]string{}}}
	return assets, edges
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// A cancelled walk is an error, never a smaller map: a node the BFS never
// reached would keep its base score, which reads as less risk.
func TestComputeBoostedScores_CancelledContextIsAnError(t *testing.T) {
	assets, edges := boostFixture(10)

	boosted, err := computeBoostedScores(context.Background(), assets, edges)
	require.NoError(t, err)
	require.NotEmpty(t, boosted, "fixture must produce a boost to be meaningful")

	boosted, err = computeBoostedScores(cancelledContext(), assets, edges)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, boosted)
}

func TestPropagateRisk_CancelledContextIsAnError(t *testing.T) {
	db, err := openAndInit(64, 0, 0)
	require.NoError(t, err)
	defer db.close()
	assets, edges := boostFixture(10)

	boosted, applied, err := propagateRisk(cancelledContext(), db, assets, edges)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, applied)
	require.Nil(t, boosted)
}

// The in-place path writes nothing and leaves the stash alone, so the live
// graph keeps the scores it had.
func TestRefreshScores_CancelledBFSKeepsPreviousScores(t *testing.T) {
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets, edges := boostFixture(10)
	stash := map[string]uint8{"lb-1": 50, "role-1": 99}
	svc.lastScores.Store(&stash)

	err = svc.refreshScores(cancelledContext(), assets, edges)
	require.ErrorIs(t, err, context.Canceled)
	require.Same(t, &stash, svc.lastScores.Load(), "the stash must still describe the live graph")
}

// A sweep whose BFS is cancelled does not publish: the live graph, its score
// stash and its digest are the previous sweep's, so the next sweep repairs.
func TestSyncFromSources_CancelledBFSKeepsPreviousGraph(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets, edges := boostFixture(10)
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{}))

	scores := func() map[string]any {
		res, qErr := svc.RunCypher(ctx, `MATCH (n) WHERE n.id IN ['lb-1', 'role-1'] RETURN n.id AS id, n.score AS s`, 10, 10)
		require.NoError(t, qErr)
		out := map[string]any{}
		for _, r := range res.Rows {
			out[r["id"].(string)] = r["s"]
		}
		return out
	}
	before := scores()
	require.Len(t, before, 2)
	prevScores, prevDigest := svc.lastScores.Load(), svc.lastDigest.Load()
	require.NotNil(t, prevScores)
	require.NotNil(t, prevDigest)

	moved, _ := boostFixture(40) // the Scores half moves; topology does not
	err = svc.SyncFromSources(cancelledContext(), 0, stubAssets{moved}, stubEdges{edges}, stubSignals{})
	require.ErrorIs(t, err, context.Canceled)

	require.Equal(t, before, scores(), "the live graph keeps the previous sweep's scores")
	require.Same(t, prevScores, svc.lastScores.Load())
	require.Same(t, prevDigest, svc.lastDigest.Load())
}
