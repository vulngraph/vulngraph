//go:build integration

package asset

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestBlastAccountProjectionMatchesFullWalk(t *testing.T) {
	if os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	prefix := "blast-accounts-" + uuid.NewString()
	defer func() {
		require.NoError(t, ch.Exec(ctx, "DELETE FROM assets WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
		require.NoError(t, ch.Exec(ctx, "DELETE FROM graph_edges WHERE startsWith(src_id,?) SETTINGS mutations_sync=1", prefix))
	}()
	var assets []Asset
	var edges []Edge
	seed := prefix + "-0"
	for i := range 120 {
		id := fmt.Sprintf("%s-%d", prefix, i)
		account := fmt.Sprint("account-", i%3)
		if i%11 == 0 {
			account = ""
		}
		assets = append(assets, Asset{ID: id, Type: "ec2_instance", AccountID: account, Name: id,
			Metadata: map[string]string{"wide": strings.Repeat("payload ", 10240)}, LastSeen: time.Now()})
		if i > 0 {
			from := seed
			if i >= 10 {
				from = fmt.Sprintf("%s-%d", prefix, i%9+1)
			}
			edges = append(edges, Edge{SrcID: from, DstID: id, EdgeType: "runs_in"})
		}
	}
	edges = append(edges, Edge{SrcID: prefix + "-1", DstID: seed, EdgeType: "runs_in"},
		Edge{SrcID: prefix + "-2", DstID: prefix + "-missing", EdgeType: "runs_in"})
	repo := NewCHRepo(ch)
	// The full detail walk can reference historical rows through fresh edges.
	// Its narrow account projection must not reinterpret their account as unknown.
	assets[2].Type, assets[2].LastSeen, assets[2].AccountID = "k8s_pod", time.Now().Add(-8*24*time.Hour), "historical-account"
	assets[3].Type = "k8s_pod"
	require.NoError(t, repo.UpsertAssets(ctx, assets))
	require.NoError(t, repo.UpsertEdges(ctx, edges))
	assets[1].AccountID = "updated-account"
	require.NoError(t, repo.UpsertAssets(ctx, assets[1:2]))
	svc := NewService(repo)
	fullCtx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": prefix + "-full", "log_queries": 1, "log_queries_probability": 1})
	full, err := svc.BlastRadius(fullCtx, seed, 2)
	require.NoError(t, err)
	require.Len(t, full.Assets, 121)
	countCtx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": prefix + "-counts", "log_queries": 1, "log_queries_probability": 1})
	counts, err := svc.BlastRadiusAccounts(countCtx, seed, 2)
	require.NoError(t, err)
	assertBlastAccounts(t, full, counts)
	require.Equal(t, 1, counts.ByAccount["updated-account"], "read current account assignments")
	require.Equal(t, 1, counts.ByAccount["historical-account"], "preserve full detail lookup semantics")
	require.NoError(t, ch.Exec(ctx, "SYSTEM FLUSH LOGS"))
	var fullBytes, countBytes, queries uint64
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing blast projection telemetry")
		}
		return rows.Scan(&fullBytes, &countBytes, &queries)
	}, `SELECT sumIf(read_bytes,log_comment=?),sumIf(read_bytes,log_comment=?),countIf(log_comment=?)
		FROM system.query_log WHERE type='QueryFinish' AND log_comment IN (?,?)`,
		prefix+"-full", prefix+"-counts", prefix+"-counts", prefix+"-full", prefix+"-counts"))
	require.Positive(t, fullBytes)
	require.Positive(t, countBytes)
	require.Less(t, countBytes, fullBytes/4, "account counting must not read full metadata")
	require.EqualValues(t, 4, queries, "seed, two edge hops and one account hydration")
	t.Logf("full_read_bytes=%d account_read_bytes=%d queries=%d", fullBytes, countBytes, queries)
}
