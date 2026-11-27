//go:build integration

package asset

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestAttackTraversalFiltersBeforeReturningRows(t *testing.T) {
	if os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	prefix := "blast-filter-" + uuid.NewString()
	defer func() {
		require.NoError(t, ch.Exec(ctx, "DELETE FROM graph_edges WHERE startsWith(src_id,?) SETTINGS mutations_sync=1", prefix))
	}()
	repo := NewCHRepo(ch)
	hub := prefix + "-hub"
	var edges []Edge
	const fanout = 100000
	for i := range fanout {
		edges = append(edges, Edge{SrcID: fmt.Sprintf("%s-pod-%d", prefix, i), DstID: hub, EdgeType: "runs_image"})
	}
	edges = append(edges,
		Edge{SrcID: hub, DstID: prefix + "-secret", EdgeType: "accesses_secret", Properties: map[string]string{"value": "preserved"}},
		Edge{SrcID: prefix + "-sg", DstID: hub, EdgeType: "sg_allows_from"},
		Edge{SrcID: hub, DstID: prefix + "-peer", EdgeType: "connected_via_sg"},
		Edge{SrcID: hub, DstID: prefix + "-unknown", EdgeType: "fixture_unknown"},
		Edge{SrcID: hub, DstID: prefix + "-internet", EdgeType: "exposed_to_internet"},
	)
	require.NoError(t, repo.UpsertEdges(ctx, edges))
	// Independently retain the old service's direction filtering as the oracle.
	out, err := repo.EdgesFrom(ctx, []string{hub})
	require.NoError(t, err)
	in, err := repo.EdgesTo(ctx, []string{hub})
	require.NoError(t, err)
	var want []Edge
	for _, e := range out {
		if attackFollowsOut(e.EdgeType) {
			want = append(want, e)
		}
	}
	for _, e := range in {
		if attackFollowsIn(e.EdgeType) {
			want = append(want, e)
		}
	}
	require.Len(t, want, 4)
	comment := "attack-hop-" + uuid.NewString()
	readCtx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": comment, "log_queries": 1, "log_queries_probability": 1})
	start := time.Now()
	got, err := repo.EdgesForAttack(readCtx, []string{hub})
	require.NoError(t, err)
	elapsed := time.Since(start)
	require.ElementsMatch(t, want, got)
	require.NoError(t, ch.Exec(ctx, "SYSTEM FLUSH LOGS"))
	var queries, resultRows, readRows, memory uint64
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing attack query telemetry")
		}
		return rows.Scan(&queries, &resultRows, &readRows, &memory)
	}, `SELECT count(),sum(result_rows),sum(read_rows),max(memory_usage)
		FROM system.query_log WHERE type='QueryFinish' AND log_comment=?`, comment))
	require.EqualValues(t, 2, queries)
	require.EqualValues(t, len(want), resultRows, "irrelevant fan-out must be removed in storage, before transmission")
	require.LessOrEqual(t, memory, uint64(128<<20))
	t.Logf("fanout=%d returned=%d seconds=%.4f read_rows=%d max_query_memory=%d", fanout, resultRows, elapsed.Seconds(), readRows, memory)
}
