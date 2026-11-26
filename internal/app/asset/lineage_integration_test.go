//go:build integration

package asset

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestBoundedLineageFreshnessVersionsAndExposureGrade(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx := context.Background()
	ch, err := db.NewCH(ctx, dsn, 4)
	require.NoError(t, err)
	defer ch.Close()
	prefix := fmt.Sprintf("lineage-%d-", time.Now().UnixNano())
	defer func() {
		require.NoError(t, ch.Exec(ctx, "ALTER TABLE graph_edges DELETE WHERE startsWith(src_id,?) SETTINGS mutations_sync=1", prefix))
	}()
	insert := func(src, dst, typ, props string, at time.Time) {
		require.NoError(t, ch.Exec(ctx, `INSERT INTO graph_edges(src_id,src_type,dst_id,dst_type,edge_type,properties,synced_at) VALUES(?,'k8s_pod',?,'container_image',?,?,?)`, prefix+src, prefix+dst, typ, props, at))
	}
	now := time.Now().Add(-time.Minute)
	for i := range 3 {
		insert(fmt.Sprint(i), "image", "runs_image", "{}", now)
		insert(fmt.Sprint(i), "image", "runs_image", "{}", now.Add(-time.Second))
	}
	insert("expired", "image", "runs_image", "{}", now.Add(-72*time.Hour))
	repo := NewCHRepo(ch)
	rows, truncated, err := repo.LineageSources(ctx, []string{prefix + "image"}, "runs_image", 2)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.True(t, truncated)
	rows, truncated, err = repo.LineageSources(ctx, []string{prefix + "image"}, "runs_image", 3)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	require.False(t, truncated)
	for _, row := range rows {
		require.NotEqual(t, prefix+"expired", row.SrcID)
	}
	insert("vm", "internet", "exposed_to_internet", `{"public_access":"confirmed"}`, now.Add(-time.Second))
	insert("vm", "internet", "exposed_to_internet", `{"public_access":"possible"}`, now)
	exposed, err := repo.AnyConfirmedExposure(ctx, []string{prefix + "vm"})
	require.NoError(t, err)
	require.False(t, exposed, "latest possible grade overrides old confirmation")
	insert("vm", "internet", "exposed_to_internet", `{"public_access":"confirmed"}`, now.Add(time.Second))
	exposed, err = repo.AnyConfirmedExposure(ctx, []string{prefix + "vm"})
	require.NoError(t, err)
	require.True(t, exposed)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, _, err = repo.LineageSources(cancelled, []string{prefix + "image"}, "runs_image", 3)
	require.Error(t, err)
}
