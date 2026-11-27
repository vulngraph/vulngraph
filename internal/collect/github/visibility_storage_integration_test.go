//go:build integration

package github

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Uses the production snapshot, asset and edge write/read paths. The harness
// must supply a disposable migrated database; never fall back to port 9000.
func TestGitHubVisibilityStorageRetainsUnknownAndRetiresOldGrant(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("requires an isolated migrated ClickHouse")
	}
	ctx := t.Context()
	ch, err := db.NewCH(ctx, dsn, 4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	prefix := "github-visibility-" + uuid.NewString()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		require.NoError(t, ch.Exec(ctx, "DELETE FROM graph_edges WHERE startsWith(src_id,?) OR startsWith(dst_id,?) SETTINGS mutations_sync=1", prefix, prefix))
		require.NoError(t, ch.Exec(ctx, "DELETE FROM assets WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
	})
	repo := asset.NewCHRepo(ch)
	svc := asset.NewService(repo)
	now := time.Now()
	grantID := prefix + "-grant-v1"
	snapshotID := prefix + "-snapshot"
	targetID := prefix + "-private"
	snapshot := appSnapshot{Coverage: "complete", Installations: []appInstallation{observedInstallation(1, 123, "org", targetID)}}
	rows := []asset.Asset{
		visibilityAsset(snapshotID, "github_visibility_snapshot", "snapshot", map[string]string{"snapshot": jsonString(snapshot), "coverage": "complete"}, now),
		visibilityAsset(grantID, "github_app_grant", "grant", map[string]string{"permissions": `{"contents":"write"}`}, now),
		visibilityAsset(targetID, "github_repo", "private", map[string]string{"visibility": "private"}, now),
	}
	edge := visibilityEdge(grantID, "github_app_grant", targetID, "github_repo", "github_grant_repository", "observed_grant", "complete")
	require.NoError(t, svc.Ingest(ctx, rows, []asset.Edge{edge}))
	loaded, err := svc.ByIDs(ctx, []string{snapshotID})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	require.Equal(t, jsonString(snapshot), loaded[0].Metadata["snapshot"])
	// Failed collection retains source data and refreshes an explicitly unknown
	// observation. There is no deletion proof and no safe empty grant.
	rows[0].Metadata["coverage"] = "unknown"
	rows[1].Metadata["coverage"] = "unknown"
	edge.Properties["coverage"] = "unknown"
	for i := range rows {
		rows[i].LastSeen = time.Now()
	}
	require.NoError(t, svc.Ingest(ctx, rows, []asset.Edge{edge}))
	edges, err := repo.EdgesFrom(ctx, []string{grantID})
	require.NoError(t, err)
	require.Len(t, edges, 1)
	require.Equal(t, "unknown", edges[0].Properties["coverage"])
	// An authoritative permission/repository change creates a new grant version.
	// Existing retirement removes every old edge version, on replay as well.
	replacement := visibilityAsset(prefix+"-grant-v2", "github_app_grant", "narrowed", map[string]string{"permissions": `{"metadata":"read"}`}, time.Now())
	require.NoError(t, svc.Ingest(ctx, []asset.Asset{replacement}, nil))
	cutoff := time.Now().Add(time.Millisecond)
	for range 2 {
		_, err = repo.RetireAssets(ctx, map[string]time.Time{grantID: cutoff})
		require.NoError(t, err)
		edges, err = repo.EdgesFrom(ctx, []string{grantID})
		require.NoError(t, err)
		require.Empty(t, edges)
	}
	loaded, err = svc.ByIDs(ctx, []string{snapshotID, replacement.ID, targetID})
	require.NoError(t, err)
	require.Len(t, loaded, 3)
}
