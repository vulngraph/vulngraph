//go:build integration

package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
)

// This opt-in benchmark owns its disposable store and runs no parallel tests.
// Temporarily removing the optimization retains a measured historical control
// through the same production decoder and completeness accounting.
func TestCriticalEdgeSourceBudget(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("requires disposable envelope runner")
	}
	n, err := strconv.Atoi(os.Getenv("PERF_ENVELOPE_ASSETS"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 2)
	require.NoError(t, err)
	defer admin.Close()
	app, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 2)
	require.NoError(t, err)
	defer app.Close()
	repo := NewCHRepo(app)
	for _, table := range []string{"assets", "graph_edges"} {
		require.NoError(t, admin.Exec(ctx, "TRUNCATE TABLE "+table))
		require.NoError(t, admin.Exec(ctx, "SYSTEM STOP MERGES "+table))
	}
	stamp := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, admin.Exec(ctx, `INSERT INTO assets(id,type,last_seen,synced_at) VALUES ('edge-budget-sg','security_group',?,?),('edge-budget-wrong','ec2_instance',?,?)`, stamp, stamp, stamp, stamp))
	for revision := 1; revision <= 2; revision++ {
		require.NoError(t, admin.Exec(ctx, `INSERT INTO graph_edges(src_id,src_type,dst_id,dst_type,edge_type,properties,synced_at)
   WITH ? AS revision,toDateTime64(?,9) AS stamp
   SELECT concat('edge-budget-',toString(number)),'ec2_instance','edge-budget-sg','security_group','connected_via_sg',
   toJSONString(map('revision',toString(revision),'note','quoted "text" and unicode café','ports',if(revision=2,'443','80'))),stamp+toIntervalSecond(revision)
   FROM numbers(?) SETTINGS max_block_size=512`, revision, stamp, n))
	}
	require.NoError(t, admin.Exec(ctx, `INSERT INTO graph_edges(src_id,src_type,dst_id,dst_type,edge_type,properties,synced_at) VALUES
  ('invalid','ec2_instance','edge-budget-wrong','ec2_instance','connected_via_sg','{}',?),
  ('expired','ec2_instance','edge-budget-sg','security_group','connected_via_sg','{}',?),
  ('bulk','ec2_instance','bucket','s3_bucket','contains_data',?,?)`, stamp, stamp.Add(-49*time.Hour), `{"classification":"internal"}`, stamp))
	original := criticalEdgesQ
	defer func() { criticalEdgesQ = original }()
	baseline := strings.Replace(original, ", optimize_aggregation_in_order = 1", "", 1)
	baseline = strings.Replace(baseline, ", aggregation_in_order_max_block_bytes = 4194304", "", 1)
	baseline = strings.Replace(baseline, ", max_block_size = 4096", "", 1)
	memoryBudget := uint64(64 << 20)
	if n >= 1_000_000 {
		memoryBudget = 512 << 20
	}
	report := map[string]any{"source": os.Getenv("PERF_COMMIT"), "logical_critical_edges": n, "physical_edges": 2*n + 3, "critical_memory_budget_bytes": memoryBudget,
		"scope": "actual edge reader with two unmerged versions, exact properties/types/freshness/SG filter and bulk completeness; no pipeline or whole-host claim"}
	var samples []perfassurance.QuerySample
	t.Cleanup(func() {
		report["passed"] = !t.Failed()
		report["samples"] = samples
		b, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "critical-edge-source.json"), b, 0600))
	})
	settings := map[string]string{}
	require.NoError(t, app.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var name, value string
			if err := rows.Scan(&name, &value); err != nil {
				return err
			}
			settings[name] = value
		}
		return rows.Err()
	}, `SELECT name,value FROM system.settings WHERE name IN ('max_threads','max_block_size','aggregation_in_order_max_block_bytes','read_in_order_use_buffering')`))
	report["session_settings"] = settings
	var plan []string
	require.NoError(t, app.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan = append(plan, line)
		}
		return rows.Err()
	}, "EXPLAIN PIPELINE "+original))
	report["production_pipeline"] = plan
	require.Contains(t, strings.Join(plan, "\n"), "AggregatingInOrder", "optimizer must actually use ordered aggregation")
	access := perfassurance.QueryLogAccess{Flush: func(ctx context.Context) error { return admin.Exec(ctx, "SYSTEM FLUSH LOGS") }, Select: `SELECT query,query_duration_ms,read_rows,read_bytes,memory_usage,exception,Settings['max_threads'],Settings['max_block_size'],ProfileEvents FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds,query_id`}
	for repeat := range 3 {
		order := []string{"baseline", "production"}
		if repeat%2 != 0 {
			order = []string{"production", "baseline"}
		}
		for _, variant := range order {
			criticalEdgesQ = original
			if variant == "baseline" {
				criticalEdgesQ = baseline
			}
			sample, e := perfassurance.Measure(ctx, admin, access, fmt.Sprintf("critical-edges:%s:%d", variant, repeat), func(ctx context.Context) error {
				result, err := repo.AllEdgesForSync(ctx, SyncProjection{})
				if err != nil {
					return err
				}
				if result.BulkPassFailed || len(result.TruncatedTypes) != 0 || len(result.Edges) != n+1 {
					return fmt.Errorf("incomplete edge read: %d", len(result.Edges))
				}
				seen := make([]bool, n)
				bulk := false
				for _, edge := range result.Edges {
					if edge.SrcID == "bulk" {
						if bulk || edge.EdgeType != "contains_data" || edge.Properties["classification"] != "internal" {
							return fmt.Errorf("incorrect bulk edge")
						}
						bulk = true
						continue
					}
					index, err := strconv.Atoi(strings.TrimPrefix(edge.SrcID, "edge-budget-"))
					if err != nil || index < 0 || index >= n || seen[index] {
						return fmt.Errorf("unexpected/duplicate edge %s", edge.SrcID)
					}
					seen[index] = true
					if edge.SrcType != "ec2_instance" || edge.DstID != "edge-budget-sg" || edge.DstType != "security_group" || edge.EdgeType != "connected_via_sg" || len(edge.Properties) != 3 || edge.Properties["revision"] != "2" || edge.Properties["ports"] != "443" || edge.Properties["note"] != "quoted \"text\" and unicode café" {
						return fmt.Errorf("incorrect latest edge %s", edge.SrcID)
					}
				}
				if !bulk {
					return fmt.Errorf("missing bulk edge")
				}
				return nil
			})
			if e != nil {
				sample.Error = e.Error()
			}
			samples = append(samples, sample)
			if e != nil {
				t.Errorf("%s: %v", variant, e)
				continue
			}
			require.Len(t, sample.Queries, 2, "critical and bulk terminal records both required")
			critical, bulk := 0, 0
			for _, q := range sample.Queries {
				require.Contains(t, q.SQL, "FROM graph_edges")
				if strings.Contains(q.SQL, "LIMIT") {
					bulk++
					continue
				}
				critical++
				if variant == "baseline" && n >= 100_000 {
					require.Greater(t, q.Memory, memoryBudget, "restored historical query must fail the unchanged memory guard")
					samples[len(samples)-1].ExpectedBudgetViolation = "critical edge query memory"
				}
				if variant == "production" {
					if q.Memory > memoryBudget {
						t.Errorf("critical edge memory %d exceeds %d", q.Memory, memoryBudget)
					}
					require.LessOrEqual(t, q.ReadRows, uint64(2*n+20))
					require.LessOrEqual(t, q.ReadBytes, uint64(512*n+65536))
				}
			}
			require.Equal(t, 1, critical)
			require.Equal(t, 1, bulk)
		}
	}
}
