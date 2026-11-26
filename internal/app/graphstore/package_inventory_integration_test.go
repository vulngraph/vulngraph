//go:build integration

package graphstore

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestPackageInventory_ResidentCoreAndOnDemandQueries(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_URL must point to an isolated migrated test database")
	}
	ctx := context.Background()
	ch, err := db.NewCH(ctx, dsn, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	inv := asset.NewService(asset.NewCHRepo(ch))
	assets, edges := packageUsageFixture()
	// Real storage timestamps keep liveness/freshness gates in this test.
	for i := range assets {
		assets[i].LastSeen = time.Now()
	}
	assets[1].RiskScore = 10
	assets[2].RiskScore = 80
	edges = append(edges, asset.Edge{SrcID: "pod-1", SrcType: "k8s_pod", DstID: InternetNodeID, DstType: "internet", EdgeType: "exposed_to_internet"})
	t.Cleanup(func() {
		for _, a := range assets {
			_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id=? SETTINGS mutations_sync=1", a.ID)
			_ = ch.Exec(ctx, "ALTER TABLE graph_edges DELETE WHERE src_id=? SETTINGS mutations_sync=1", a.ID)
		}
	})
	require.NoError(t, inv.Ingest(ctx, assets, edges))
	risk, err := inv.PackageRiskByRunner(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 80, risk["image/sha256:abc"])
	require.EqualValues(t, 80, risk["example-corp/api-service"])
	versions, err := inv.FindPackageVersions(ctx, "@example-corp/db-client", 101)
	require.NoError(t, err)
	require.Len(t, versions, 1)

	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	svc.WithPackageInventory(explore.NewCHRepo(ch), inv)
	const pkg = "pkg:npm/@example-corp/db-client@1.2.0"
	require.NoError(t, svc.SyncFromSources(ctx, 0, inv, inv, stubSignals{map[string]NodeSignals{pkg: {HasKEV: true, MaxScore: 90}}}))
	core, err := svc.MatchSeed(ctx, explore.NodeMatch{IDs: []string{pkg}}, 10)
	require.NoError(t, err)
	require.Empty(t, core)
	require.NotContains(t, svc.lastNodeIDs, pkg)
	image, err := svc.MatchSeed(ctx, explore.NodeMatch{IDs: []string{"image/sha256:abc"}}, 10)
	require.NoError(t, err)
	require.Len(t, image, 1)
	require.GreaterOrEqual(t, image[0].Score, 80, "package risk must survive projection")
	for _, q := range NamedQueries {
		if !q.Inventory {
			continue
		}
		t.Run(q.Name, func(t *testing.T) {
			result, err := svc.RunNamedQuery(ctx, q.Name, map[string]string{"name": "@example-corp/db-client"})
			require.NoError(t, err)
			require.Contains(t, nodeIDs(result.Nodes), pkg)
			require.NotEmpty(t, result.Edges)
			if q.Name == "package_running_workloads" {
				require.Contains(t, nodeIDs(result.Nodes), "pod-1")
			}
		})
	}
	merged := explore.NewFallbackRepo(svc, explore.NewCHRepo(ch))
	combined, nodes, cut, err := merged.Neighbors(ctx, []string{"image/sha256:abc"}, nil, explore.DirectionBoth)
	require.NoError(t, err)
	require.False(t, cut)
	require.Contains(t, nodeIDs(nodes), pkg)
	require.Contains(t, nodeIDs(nodes), "pod-1")
	require.True(t, slices.ContainsFunc(combined, func(e explore.Edge) bool { return e.EdgeType == "runs_package" }))
	require.True(t, slices.ContainsFunc(combined, func(e explore.Edge) bool { return e.EdgeType == "RunsImage" }))
}
