package graphstore

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type failingSignals struct{}

func (failingSignals) SignalsByResource(context.Context) (map[string]NodeSignals, error) {
	return nil, errors.New("clickhouse: timeout")
}

// signalFixture is a two-node graph: lb-1 (Asset) and role-1 (IamRole), both
// carrying KEV findings in the first rollup.
func signalFixture() ([]asset.Asset, []asset.Edge, map[string]NodeSignals) {
	assets := []asset.Asset{
		{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50},
		{ID: "role-1", Name: "admin", Type: "iam_role", Provider: "aws", RiskScore: 70},
	}
	edges := []asset.Edge{
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role",
			EdgeType: "has_role", Properties: map[string]string{}},
	}
	sigs := map[string]NodeSignals{
		"lb-1":   {HasKEV: true, Exploitable: true, MaxScore: 90, PrivescCount: 1},
		"role-1": {HasKEV: true, MaxScore: 80},
	}
	return assets, edges, sigs
}

func openSynced(t *testing.T, sigs map[string]NodeSignals) (*Service, []asset.Asset, []asset.Edge) {
	t.Helper()
	assets, edges, _ := signalFixture()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	require.NoError(t, svc.SyncFromSources(context.Background(), 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	return svc, assets, edges
}

// kevIDs returns the ids of every signal-bearing node the graph marks has_kev.
func kevIDs(t *testing.T, svc *Service) []string {
	t.Helper()
	var ids []string
	for _, label := range []string{NodeAsset, NodeIamRole} {
		res, err := svc.RunCypher(context.Background(), `MATCH (n:`+label+`) WHERE n.has_kev = 1 RETURN n`, 100, 100)
		require.NoError(t, err)
		for _, n := range res.Nodes {
			ids = append(ids, n.ID)
		}
	}
	return ids
}

func cachedSignals(t *testing.T, svc *Service, id string) NodeSignals {
	t.Helper()
	v, ok := svc.nodeSignalsCache.Load(id)
	require.Truef(t, ok, "%s not pre-warmed", id)
	return v.(NodeSignals)
}

// TestRefreshSignals_ResourceDroppedFromRollupGetsZeroed: the rollup only names
// resources with open findings, so a resource whose findings all resolved simply
// disappears from it. Both refresh callers must clear it in the graph, matching
// the zeroed cache entry and what a full rebuild would load.
func TestRefreshSignals_ResourceDroppedFromRollupGetsZeroed(t *testing.T) {
	_, _, sigs := signalFixture()
	dropped := map[string]NodeSignals{"lb-1": sigs["lb-1"]} // role-1's findings resolved

	t.Run("RefreshSignals", func(t *testing.T) {
		svc, _, _ := openSynced(t, sigs)
		require.ElementsMatch(t, []string{"lb-1", "role-1"}, kevIDs(t, svc))

		require.NoError(t, svc.RefreshSignals(context.Background(), stubSignals{dropped}))
		require.Equal(t, []string{"lb-1"}, kevIDs(t, svc), "role-1 left the rollup — has_kev must be cleared")
		require.False(t, cachedSignals(t, svc, "role-1").HasKEV)
		require.Zero(t, cachedSignals(t, svc, "role-1").MaxScore)
	})

	t.Run("digest cheap path", func(t *testing.T) {
		svc, assets, edges := openSynced(t, sigs)
		require.NoError(t, svc.SyncFromSources(context.Background(), 0, stubAssets{assets}, stubEdges{edges}, stubSignals{dropped}))
		require.Equal(t, syncPathSignals, svc.LastSyncPath())
		require.Equal(t, []string{"lb-1"}, kevIDs(t, svc))
		require.False(t, cachedSignals(t, svc, "role-1").HasKEV)
	})

	t.Run("everything resolved", func(t *testing.T) {
		svc, _, _ := openSynced(t, sigs)
		require.NoError(t, svc.RefreshSignals(context.Background(), stubSignals{map[string]NodeSignals{}}))
		require.Empty(t, kevIDs(t, svc))
	})
}

// holdWriteTx opens a second write transaction on the live graph. Ladybug allows
// one writer at a time, so every signal-refresh label write fails while it is held.
func holdWriteTx(t *testing.T, svc *Service) (release func()) {
	t.Helper()
	conn, err := svc.db.newWriteConn()
	require.NoError(t, err)
	res, err := conn.Query(`BEGIN TRANSACTION`)
	require.NoError(t, err)
	res.Close()
	probe, err := conn.Query(`MATCH (n:Asset {id: 'lb-1'}) SET n.name = 'held'`)
	require.NoError(t, err)
	probe.Close()
	return func() {
		if r, rErr := conn.Query(`ROLLBACK`); rErr == nil {
			r.Close()
		}
		conn.Close()
	}
}

// TestRefreshSignals_FailedLabelWriteFailsAndIsRetried: a label write that fails
// must fail the refresh and must not latch the digest, so the next sweep repairs
// the graph instead of comparing against a digest for signals it never applied.
func TestRefreshSignals_FailedLabelWriteFailsAndIsRetried(t *testing.T) {
	_, _, sigs := signalFixture()
	dropped := map[string]NodeSignals{"lb-1": sigs["lb-1"]}

	t.Run("RefreshSignals returns the error and the retry applies", func(t *testing.T) {
		svc, _, _ := openSynced(t, sigs)
		release := holdWriteTx(t, svc)
		err := svc.RefreshSignals(context.Background(), stubSignals{dropped})
		release()
		require.Error(t, err)
		require.Nil(t, svc.lastDigest.Load(), "a failed refresh must drop the latched digest")

		require.NoError(t, svc.RefreshSignals(context.Background(), stubSignals{dropped}))
		require.Equal(t, []string{"lb-1"}, kevIDs(t, svc))
	})

	t.Run("digest path rebuilds on the next sweep", func(t *testing.T) {
		svc, assets, edges := openSynced(t, sigs)
		// applySignals directly: the cheap path's own fall-through rebuild would swap
		// out (and close) the database the held transaction lives on.
		release := holdWriteTx(t, svc)
		err := svc.applySignals(context.Background(), dropped)
		release()
		require.Error(t, err)
		require.Nil(t, svc.lastDigest.Load())

		require.NoError(t, svc.SyncFromSources(context.Background(), 0, stubAssets{assets}, stubEdges{edges}, stubSignals{dropped}))
		require.Equal(t, syncPathFull, svc.LastSyncPath(), "no digest latched, so the next sweep must rebuild")
		require.Equal(t, []string{"lb-1"}, kevIDs(t, svc))
	})
}

// TestRefreshSignals_RebasesDigestSoARevertIsApplied: RefreshSignals writes
// outside SyncFromSources. If it left the latched Signals half on the previous
// rollup, a later sweep whose rollup reverted to it would no-op and keep serving
// the refreshed values.
func TestRefreshSignals_RebasesDigestSoARevertIsApplied(t *testing.T) {
	_, _, sigs := signalFixture()
	svc, assets, edges := openSynced(t, sigs)
	require.NoError(t, svc.RefreshSignals(context.Background(), stubSignals{map[string]NodeSignals{}}))
	require.Empty(t, kevIDs(t, svc))

	require.NoError(t, svc.SyncFromSources(context.Background(), 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.Equal(t, syncPathSignals, svc.LastSyncPath())
	require.ElementsMatch(t, []string{"lb-1", "role-1"}, kevIDs(t, svc))
}

// TestSignalRollupFailure_IsUnknownNotClean: a failed rollup must never publish
// zero signals as if measured — the rebuild, the cheap path and the warm start all
// fail and leave the previous graph serving.
func TestSignalRollupFailure_IsUnknownNotClean(t *testing.T) {
	_, _, sigs := signalFixture()
	ctx := context.Background()

	t.Run("cold rebuild publishes nothing", func(t *testing.T) {
		assets, edges, _ := signalFixture()
		svc, err := Open("", 64, 0, 0, "")
		require.NoError(t, err)
		defer svc.Close()
		require.Error(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, failingSignals{}))
		require.False(t, svc.Ready())
		_, cached := svc.nodeSignalsCache.Load("lb-1")
		require.False(t, cached, "no zeroed cache entries for a rollup that never arrived")
	})

	t.Run("warm graph keeps serving its signals", func(t *testing.T) {
		svc, assets, edges := openSynced(t, sigs)
		require.Error(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, failingSignals{}))
		require.ElementsMatch(t, []string{"lb-1", "role-1"}, kevIDs(t, svc))
		require.True(t, cachedSignals(t, svc, "lb-1").HasKEV)

		require.Error(t, svc.RefreshSignals(ctx, failingSignals{}))
		require.ElementsMatch(t, []string{"lb-1", "role-1"}, kevIDs(t, svc))
	})

	t.Run("warm start refuses the snapshot", func(t *testing.T) {
		assets, edges, _ := signalFixture()
		path := t.TempDir() + "/graph.snap"
		first, err := Open("", 64, 0, 0, path)
		require.NoError(t, err)
		defer first.Close()
		require.NoError(t, first.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))

		second, err := Open("", 64, 0, 0, path)
		require.NoError(t, err)
		defer second.Close()
		require.Error(t, second.LoadFromSnapshot(ctx, failingSignals{}))
		require.False(t, second.Ready(), "a snapshot loaded without signals would read as KEV-free everywhere")
	})
}
