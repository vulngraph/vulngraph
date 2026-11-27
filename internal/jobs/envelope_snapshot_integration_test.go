//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Use the deployed engine's own snapshot test hook. Publication must complete
// after the risk data snapshot but before the marker snapshot; mere wall-clock
// sleeps or a few lucky concurrent reads cannot establish that interleaving.
func TestEnvelopeDerivedSnapshotBarrier(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("isolated snapshot acquisition barrier")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	app, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer app.Close()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer admin.Close()
	svc := asset.NewService(asset.NewCHRepo(app))
	ids := []string{"snapshot-a", "snapshot-b"}
	require.NoError(t, svc.Ingest(ctx, []asset.Asset{
		{ID: ids[0], Type: "ec2_instance", Name: "first", AccountID: "snapshot-account", RiskScore: 5, LastSeen: time.Now()},
		{ID: ids[1], Type: "ec2_instance", Name: "second", AccountID: "snapshot-account", RiskScore: 5, LastSeen: time.Now()},
	}, nil))
	for _, tc := range []struct {
		name string
		read func(context.Context) ([]asset.Asset, error)
	}{
		{"by_ids", func(c context.Context) ([]asset.Asset, error) { return svc.ByIDs(c, ids) }},
		{"current", func(c context.Context) ([]asset.Asset, error) {
			return svc.List(c, asset.Filter{Limit: 25, AccountID: "snapshot-account"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version, e := svc.BeginDerivedUpdate(ctx)
			require.NoError(t, e)
			require.NoError(t, svc.PublishFindingRisk(ctx, version, map[string]uint8{ids[0]: 60, ids[1]: 80}))
			type result struct {
				rows []asset.Asset
				err  error
			}
			readCtx, stop := context.WithCancel(ctx)
			defer stop()
			readCtx = app.WithQuerySettings(readCtx, map[string]any{"merge_tree_storage_snapshot_sleep_ms": 500, "send_logs_level": "debug", "enable_shared_storage_snapshot_in_query": 0})
			var shared uint64
			require.NoError(t, app.Select(readCtx, func(rows driver.Rows) error {
				require.True(t, rows.Next())
				return rows.Scan(&shared)
			}, "SELECT toUInt64(getSetting('enable_shared_storage_snapshot_in_query'))"))
			require.Equal(t, uint64(1), shared, "application reads must override a disabled caller setting")
			queryID := fmt.Sprintf("snapshot-%s-%d", tc.name, time.Now().UnixNano())
			readCtx = clickhouse.Context(readCtx, clickhouse.WithQueryID(queryID))
			finished := make(chan result, 1)
			go func() {
				defer func() {
					if p := recover(); p != nil {
						finished <- result{err: fmt.Errorf("snapshot reader panic: %v", p)}
					}
				}()
				rows, err := tc.read(readCtx)
				finished <- result{rows, err}
			}()
			var riskStarted, riskFinished, markerStarted, markerFinished uint64
			markerTable := "asset_risk_publications"
			var markerOrdinal uint64
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				require.NoError(t, admin.Exec(ctx, "SYSTEM FLUSH LOGS text_log"))
				require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
					require.True(t, rows.Next())
					return rows.Scan(&riskStarted, &riskFinished, &markerStarted, &markerFinished)
				}, `SELECT
countIf(position(logger_name,'asset_finding_risk')>0 AND startsWith(message,'Injecting')),
countIf(position(logger_name,'asset_finding_risk')>0 AND startsWith(message,'Finished')),
countIf(position(logger_name,'asset_risk_publications')>0 AND startsWith(message,'Injecting')),
countIf(position(logger_name,'asset_risk_publications')>0 AND startsWith(message,'Finished'))
FROM system.text_log WHERE query_id=?`, queryID))
				if riskFinished > 0 && markerStarted > markerFinished {
					markerOrdinal = markerStarted
					break
				}
				if riskFinished > 0 && riskStarted > riskFinished {
					markerTable, markerOrdinal = "asset_finding_risk", riskStarted
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			require.Positive(t, markerOrdinal, "snapshot barrier was not observed")
			version, e = svc.BeginDerivedUpdate(ctx)
			require.NoError(t, e)
			require.NoError(t, svc.PublishFindingRisk(ctx, version, map[string]uint8{ids[0]: 80, ids[1]: 60}))
			published, e := svc.BeginDerivedUpdate(ctx)
			require.NoError(t, e)
			got := <-finished
			require.NoError(t, admin.Exec(ctx, "SYSTEM FLUSH LOGS text_log"))
			var captures []time.Time
			require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
				for rows.Next() {
					var at time.Time
					if err := rows.Scan(&at); err != nil {
						return err
					}
					captures = append(captures, at)
				}
				return rows.Err()
			}, `SELECT event_time_microseconds FROM system.text_log WHERE query_id=?
 AND position(logger_name,?)>0 AND startsWith(message,'Finished') ORDER BY event_time_microseconds`, queryID, markerTable))
			require.GreaterOrEqual(t, len(captures), int(markerOrdinal))
			markerCaptured := captures[markerOrdinal-1]
			scores := map[string]uint8{}
			for _, row := range got.rows {
				scores[row.ID] = row.RiskScore
			}
			valid := len(got.rows) == 2 && ((scores[ids[0]] == 60 && scores[ids[1]] == 80) || (scores[ids[0]] == 80 && scores[ids[1]] == 60))
			evidence, e := json.MarshalIndent(map[string]any{"query_id": queryID, "reader": tc.name, "risk_snapshot_finished": riskFinished,
				"marker_table": markerTable, "marker_snapshot_ordinal": markerOrdinal, "marker_snapshot_started": markerStarted, "publication_completed": published, "marker_snapshot_captured": markerCaptured,
				"scores": scores, "complete_pair": valid, "barrier_order_valid": published.Before(markerCaptured)}, "", "  ")
			require.NoError(t, e)
			require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "snapshot-barrier-"+tc.name+".json"), evidence, 0600))
			require.NoError(t, got.err)
			require.True(t, published.Before(markerCaptured), "publisher missed the snapshot window")
			require.True(t, valid, "reader saw missing or mixed contributions: %v", scores)
		})
	}
}
