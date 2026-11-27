package graphstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/benchconfig"
)

// Replay the collector's persisted output, independently through correlation
// and native graph loading. This catches fixture counts that never become
// traversable relationships. It is opt-in and runs under the benchmark lock.
func TestGitHubVisibilityFixtureReplay(t *testing.T) {
	dir := os.Getenv("GITHUB_VISIBILITY_FIXTURES")
	if dir == "" {
		t.Skip("requires persisted GitHub visibility fixtures")
	}
	for _, n := range []int{100, 1000, 10000} {
		if n > benchconfig.MaxSize(t) {
			continue
		}
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, "github-"+strconv.Itoa(n)+"-fixture.json"))
			require.NoError(t, err)
			var fixture collect.Result
			require.NoError(t, json.Unmarshal(data, &fixture))
			fixture.Assets = append(fixture.Assets, asset.Asset{ID: "arn:aws:iam::123456789012:role/deploy", Type: "iam_role", Provider: asset.ProviderAWS})
			cloud := (&correlate.CIAccess{}).Correlate(correlate.NewGraph(fixture.Assets))
			require.Len(t, cloud, 2*n)
			fixture.Edges = append(fixture.Edges, cloud...)
			assets := filterLadybugAssets(fixture.Assets, fixture.Edges)
			require.Len(t, assets, 4*n+4)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			db, err := openAndInit(512, 1, 1)
			require.NoError(t, err)
			defer db.close()
			conn, err := db.newWriteConn()
			require.NoError(t, err)
			defer conn.Close()
			_, err = bulkSyncCopy(t.Context(), conn, assets, fixture.Edges, newReachOverlay(fixture.Edges), nil, true, 4, nil)
			require.NoError(t, err)
			seconds := time.Since(start).Seconds()
			runtime.ReadMemStats(&after)
			// COPY also seeds internet + secret wildcard + six DataClass nodes;
			// applySchema adds one _SchemaMeta node. Count these explicitly rather
			// than reporting only the supplied collector/correlation node count.
			require.Equal(t, int64(n), countQuery(t, conn, "MATCH (node:Repo) RETURN count(node)"))
			require.Equal(t, int64(3*n+5), countQuery(t, conn, "MATCH (node:Asset) RETURN count(node)"))
			require.Equal(t, int64(1), countQuery(t, conn, "MATCH (node:IamRole) RETURN count(node)"))
			require.Equal(t, int64(6), countQuery(t, conn, "MATCH (node:DataClass) RETURN count(node)"))
			require.Equal(t, int64(1), countQuery(t, conn, "MATCH (node:_SchemaMeta) RETURN count(node)"))
			require.Equal(t, int64(4*n+13), countQuery(t, conn, "MATCH (node) RETURN count(node)"))
			require.Equal(t, int64(n), countQuery(t, conn, "MATCH ()-[:GitHubWorkflow]->() RETURN count(*)"))
			require.Equal(t, int64(2*n), countQuery(t, conn, "MATCH ()-[:GitHubWorkflowToken]->() RETURN count(*)"))
			require.Equal(t, int64(n), countQuery(t, conn, "MATCH ()-[:GitHubTokenGrant]->() RETURN count(*)"))
			require.Equal(t, int64(n), countQuery(t, conn, "MATCH ()-[:GitHubTokenRepository]->() RETURN count(*)"))
			require.Equal(t, int64(n), countQuery(t, conn, "MATCH ()-[:GitHubGrantRepository]->() RETURN count(*)"))
			require.Equal(t, int64(n), countQuery(t, conn, "MATCH ()-[:FederatedAccessAsset]->() RETURN count(*)"))
			require.Equal(t, int64(8*n+2), countQuery(t, conn, "MATCH ()-[e]->() RETURN count(e)"))
			report := map[string]any{"repositories": n, "supplied_nodes": len(assets), "resident_nodes": 4*n + 13, "resident_edges": 8*n + 2, "load_seconds": seconds, "allocated_bytes": after.TotalAlloc - before.TotalAlloc, "cloud_edges": len(cloud)}
			encoded, err := json.Marshal(report)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "graph-"+strconv.Itoa(n)+".json"), encoded, 0600))
			t.Log(string(encoded))
		})
	}
}
