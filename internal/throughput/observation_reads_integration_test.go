//go:build integration

package throughput

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
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestObservationHistoryUsesNarrowReads(t *testing.T) {
	if os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx := t.Context()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	for _, table := range []string{"assets", "findings"} {
		t.Run(table, func(t *testing.T) {
			prefix := "observation-read-" + uuid.NewString()
			defer func() {
				require.NoError(t, ch.Exec(ctx, "DELETE FROM "+table+" WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
			}()
			old := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
			ids := make([]string, 128)
			expected := map[string]time.Time{}
			for i := range ids {
				ids[i] = fmt.Sprintf("%s-%03d", prefix, i)
				expected[ids[i]] = old
			}
			comment := func(name string) context.Context {
				return ch.WithQuerySettings(ctx, map[string]any{"log_comment": prefix + name, "log_queries": 1, "log_queries_probability": 1})
			}
			column := "first_discovered_at"
			if table == "assets" {
				repo := asset.NewCHRepo(ch)
				rows := make([]asset.Asset, len(ids))
				for i, id := range ids {
					rows[i] = asset.Asset{ID: id, Type: "ec2_instance", Name: "old", DiscoveredAt: old, LastSeen: time.Now(), Metadata: map[string]string{"wide": strings.Repeat("payload ", 4096)}}
				}
				// A reappearing pod keeps its original date even while its old row
				// is excluded from live inventory.
				rows[1].Type, rows[1].LastSeen = "k8s_pod", time.Now().Add(-8*24*time.Hour)
				rows[2].Type = "k8s_pod" // establishes a current liveness high-water mark
				require.NoError(t, repo.UpsertAssets(ctx, rows))
				live, err := repo.LiveIDs(ctx, []string{rows[1].ID})
				require.NoError(t, err)
				require.Empty(t, live, "old pod must be expired before its reappearance")
				_, err = repo.ByIDs(comment("-full"), ids)
				require.NoError(t, err)
				for i := range rows {
					rows[i].Name = "changed"
					rows[i].LastSeen = time.Now()
					rows[i].DiscoveredAt = time.Now()
					if i%7 == 0 {
						rows[i].FirstDiscoveredAt = old.Add(-time.Hour)
						expected[rows[i].ID] = rows[i].FirstDiscoveredAt
					}
				}
				require.NoError(t, asset.NewService(repo).IngestAssets(comment("-history"), rows))
			} else {
				column = "first_detected_at"
				repo := finding.NewCHRepo(ch)
				rows := make([]finding.Finding, len(ids))
				for i, id := range ids {
					rows[i] = finding.Finding{ID: id, Source: "fixture", Severity: finding.SeverityHigh, Title: "old", DetectedAt: old, Description: strings.Repeat("payload ", 4096)}
				}
				require.NoError(t, repo.Upsert(ctx, rows))
				_, err = repo.ByIDs(comment("-full"), ids)
				require.NoError(t, err)
				for i := range rows {
					rows[i].Title = "changed"
					rows[i].Severity = finding.SeverityLow
					rows[i].DetectedAt = time.Now()
					if i%7 == 0 {
						rows[i].FirstDetectedAt = old.Add(-time.Hour)
						expected[rows[i].ID] = rows[i].FirstDetectedAt
					}
				}
				require.NoError(t, finding.NewService(repo).RecordObserved(comment("-history"), rows))
			}
			// Inspect the newest physical version, not a min over old versions
			// that could mask a broken carry-forward write until merges run.
			count := 0
			require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
				for rows.Next() {
					var id string
					var stamp time.Time
					if err := rows.Scan(&id, &stamp); err != nil {
						return err
					}
					require.Equal(t, expected[id].Unix(), stamp.Unix(), id)
					count++
				}
				return rows.Err()
			}, "SELECT id,argMax("+column+",synced_at) FROM "+table+" WHERE startsWith(id,?) GROUP BY id", prefix))
			require.Equal(t, len(ids), count)
			require.NoError(t, ch.Exec(ctx, "SYSTEM FLUSH LOGS"))
			var fullBytes, historyBytes, historyQueries uint64
			require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
				if !rows.Next() {
					return fmt.Errorf("missing history-read telemetry")
				}
				return rows.Scan(&fullBytes, &historyBytes, &historyQueries)
			}, `SELECT sumIf(read_bytes,log_comment=?),sumIf(read_bytes,log_comment=?),countIf(log_comment=?) FROM system.query_log WHERE type='QueryFinish' AND startsWith(query,'SELECT') AND log_comment IN (?,?)`, prefix+"-full", prefix+"-history", prefix+"-history", prefix+"-full", prefix+"-history"))
			require.Positive(t, fullBytes)
			require.Positive(t, historyBytes)
			require.EqualValues(t, 1, historyQueries)
			require.Less(t, historyBytes, fullBytes/4, "preserving observation dates must not reload full payloads or enrichment joins")
			t.Logf("full_read_bytes=%d history_read_bytes=%d queries=%d", fullBytes, historyBytes, historyQueries)
		})
	}
}
