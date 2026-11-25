package graphstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestOversizedNodeTables_Threshold(t *testing.T) {
	for _, tc := range []struct {
		rows int64
		want bool
	}{
		{0, false},
		{1, false},
		{LadybugNodeGroupRows - 1, false},
		{LadybugNodeGroupRows, false}, // exactly one full node group
		{LadybugNodeGroupRows + 1, true},
		{3 * LadybugNodeGroupRows, true},
	} {
		got := oversizedNodeTables(map[string]int64{NodePackage: tc.rows, NodeRepo: 5})
		_, over := got[NodePackage]
		require.Equalf(t, tc.want, over, "%d rows", tc.rows)
		require.NotContains(t, got, NodeRepo)
	}
}

// The count is the engine's own, sentinels included: an estate with one asset
// fewer than a node group still crosses it once the loader adds its sentinel
// rows.
func TestBulkSyncCopy_CountsNodeTablesFromTheEngine(t *testing.T) {
	if testing.Short() {
		t.Skip("loads one node group of rows")
	}
	ctx := context.Background()
	db, err := openAndInit(256, 0, 0)
	require.NoError(t, err)
	defer db.close()
	wc, err := db.newWriteConn()
	require.NoError(t, err)
	defer wc.Close()

	n := LadybugNodeGroupRows - 1
	assets := make([]asset.Asset, n)
	for i := range assets {
		assets[i] = asset.Asset{ID: fmt.Sprintf("lb-%06d", i), Name: "lb", Type: "load_balancer", Provider: "aws"}
	}
	stats, err := bulkSyncCopy(ctx, wc, assets, nil, newReachOverlay(nil), nil, true, 2, nil)
	require.NoError(t, err)
	require.Equal(t, int64(n+2), stats.nodeTableRows[NodeAsset], "assets plus the internet and secret-wildcard sentinels")
	require.Contains(t, oversizedNodeTables(stats.nodeTableRows), NodeAsset)
	require.Equal(t, int64(0), stats.nodeTableRows[NodePackage])
}

// Every surface of the served graph reports the guard: GraphHealth, and a
// flag on each multi-hop answer, but not on the hop-by-hop blast-radius walk.
func TestMultiHopGuard_ReachesEveryAnswer(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	hl, err := svc.GraphHealth(ctx)
	require.NoError(t, err)
	_, known := hl.MultiHopMayBeIncomplete()
	require.False(t, known, "never built: unknown, not complete")

	assets, edges := reachFixture()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	rows, ok := svc.NodeTableRows()
	require.True(t, ok)
	require.Equal(t, int64(2), rows[NodeIamRole])
	hl, err = svc.GraphHealth(ctx)
	require.NoError(t, err)
	incomplete, known := hl.MultiHopMayBeIncomplete()
	require.True(t, known)
	require.False(t, incomplete)
	res, err := svc.RunCypher(ctx, `MATCH (a:Asset)-[:HasRole]->(r:IamRole)-[:CanAssume]->(b:IamRole) RETURN b`, 100, 100)
	require.NoError(t, err)
	require.False(t, res.MultiHopMayBeIncomplete)

	// The engine limit cannot be reached with a unit-test fixture, so the
	// recorded counts stand in for a published oversized build.
	svc.mu.Lock()
	svc.publishNodeTableRows(ctx, map[string]int64{NodeAsset: 10, NodePackage: LadybugNodeGroupRows + 7})
	svc.mu.Unlock()

	hl, err = svc.GraphHealth(ctx)
	require.NoError(t, err)
	incomplete, known = hl.MultiHopMayBeIncomplete()
	require.True(t, known)
	require.True(t, incomplete)
	require.Equal(t, map[string]int64{NodePackage: LadybugNodeGroupRows + 7}, hl.OversizedNodeTables)

	res, err = svc.RunCypher(ctx, `MATCH (a:Asset)-[:HasRole]->(r:IamRole)-[:CanAssume]->(b:IamRole) RETURN b`, 100, 100)
	require.NoError(t, err)
	require.True(t, res.MultiHopMayBeIncomplete, "raw Cypher")
	for _, name := range []string{"blast_radius_deep", "attack_path_internet_to_iam"} {
		named, nErr := svc.RunNamedQuery(ctx, name, nil)
		require.NoError(t, nErr, name)
		require.True(t, named.MultiHopMayBeIncomplete, name)
	}
	path, err := svc.RunNamedQuery(ctx, "attack_path_check", map[string]string{"src_id": "lb-a", "dst_id": "role-2"})
	require.NoError(t, err)
	require.True(t, path.MultiHopMayBeIncomplete, "attack_path_check")
	blast, err := svc.RunNamedQuery(ctx, "blast_radius", map[string]string{"id": "lb-a"})
	require.NoError(t, err)
	require.False(t, blast.MultiHopMayBeIncomplete, "the hop-by-hop walk is not affected")
}
