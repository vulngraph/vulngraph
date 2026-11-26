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
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestWideInventoryBatchesPreserveEveryRow(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx := context.Background()
	ch, err := db.NewCH(ctx, dsn, 4)
	require.NoError(t, err)
	defer ch.Close()
	prefix := fmt.Sprintf("wide-batch-%d-", time.Now().UnixNano())
	defer func() {
		require.NoError(t, ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
		require.NoError(t, ch.Exec(ctx, "ALTER TABLE graph_edges DELETE WHERE startsWith(src_id,?) SETTINGS mutations_sync=1", prefix))
	}()
	const n = 1005
	now := time.Now()
	payload := strings.Repeat("\x00\"\\", 2048) // JSON escaping, not just compressible ASCII
	var assets []Asset
	var edges []Edge
	var ids []string
	for i := range n {
		id := fmt.Sprintf("%s%d", prefix, i)
		ids = append(ids, id)
		assets = append(assets, Asset{ID: id, Type: "ec2_instance", Name: id, Provider: ProviderAWS, Metadata: map[string]string{"payload": payload}, Tags: map[string]string{"tag": payload}, DiscoveredAt: now, LastSeen: now})
		edges = append(edges, Edge{SrcID: id, SrcType: "ec2_instance", DstID: prefix + "target", DstType: "ec2_instance", EdgeType: "runs_in", Properties: map[string]string{"payload": payload}})
	}
	repo := NewCHRepo(ch)
	require.NoError(t, repo.UpsertAssets(ctx, assets))
	require.NoError(t, repo.UpsertEdges(ctx, edges))
	got, err := repo.ByIDs(ctx, ids)
	require.NoError(t, err)
	require.Len(t, got, n)
	for _, a := range got {
		require.Equal(t, payload, a.Metadata["payload"])
		require.Equal(t, payload, a.Tags["tag"])
	}
	var count, bad uint64
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		require.True(t, rows.Next())
		return rows.Scan(&count, &bad)
	}, `SELECT uniqExact(src_id),countIf(JSONExtractString(properties,'payload') != ?) FROM graph_edges WHERE startsWith(src_id,?)`, payload, prefix))
	require.EqualValues(t, n, count)
	require.Zero(t, bad)
}
