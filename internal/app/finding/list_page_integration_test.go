//go:build integration

package finding

import (
	"context"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

func TestFindingPagesPreserveResultsWithoutUnusedJoin(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx := t.Context()
	ch, err := db.NewCH(ctx, dsn, 4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	prefix := "page-" + uuid.NewString()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		require.NoError(t, ch.Exec(cleanup, "DELETE FROM findings WHERE source=? SETTINGS mutations_sync=1", prefix))
		require.NoError(t, ch.Exec(cleanup, "DELETE FROM finding_enrichment WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
	})
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	version := time.Now().UTC()
	repo := NewCHRepo(ch, WithClock(func() time.Time { return version }))
	var findings []Finding
	var enrichments []Enrichment
	for i := 0; i < 200; i++ {
		f := Finding{ID: fmt.Sprintf("%s-%03d", prefix, i), Source: prefix, Type: "exposure", Severity: SeverityLow,
			Title: fmt.Sprintf("finding %d", i), ResourceID: fmt.Sprintf("%s-resource-%d", prefix, i%2), ResourceType: "ec2_instance",
			CheckID: "CVE-2024-0001", DetectedAt: base.Add(time.Duration(i) * time.Second), LastObservedAt: base, Metadata: map[string]string{"row": fmt.Sprint(i)}}
		findings = append(findings, f)
		if i%2 == 0 {
			enrichments = append(enrichments, Enrichment{ID: f.ID, Score: uint8(i % 100), ScoreBand: "monitor", EnrichedAt: version, OwnerTeam: "team", OwnerSource: "tag", Environment: "prod"})
		}
	}
	require.NoError(t, repo.Upsert(ctx, findings))
	// Newer versions must govern severity, lifecycle and order before paging.
	version = version.Add(time.Millisecond)
	findings[10].Severity = SeverityHigh
	findings[20].ResolvedAt = base
	findings[30].DetectedAt = base.Add(500 * time.Second)
	require.NoError(t, repo.Upsert(ctx, []Finding{findings[10], findings[20], findings[30]}))
	const noise = 20000
	for i := 0; i < noise; i++ {
		enrichments = append(enrichments, Enrichment{ID: fmt.Sprintf("%s-noise-%d", prefix, i), Score: 50, EnrichedAt: version})
	}
	require.NoError(t, repo.UpsertEnrichment(ctx, enrichments))
	tests := []struct {
		name   string
		filter Filter
		keep   func(Finding) bool
	}{
		{"ordinary", Filter{}, func(f Finding) bool { return !f.Resolved() }},
		{"severity", Filter{Severity: SeverityHigh}, func(f Finding) bool { return !f.Resolved() && f.Severity == SeverityHigh }},
		{"resource", Filter{ResourceID: prefix + "-resource-0"}, func(f Finding) bool { return !f.Resolved() && f.ResourceID == prefix+"-resource-0" }},
		{"check", Filter{CheckID: "CVE-2024-0001"}, func(f Finding) bool { return !f.Resolved() }},
		{"cve", Filter{CVEIn: []string{"cve-2024-0001"}}, func(f Finding) bool { return !f.Resolved() }},
		{"resolved", Filter{IncludeResolved: true}, func(Finding) bool { return true }},
		{"oldest", Filter{OldestFirst: true}, func(f Finding) bool { return !f.Resolved() }},
		{"time window", Filter{DetectedAfter: base.Add(50 * time.Second), DetectedBefore: base.Add(100 * time.Second)}, func(f Finding) bool {
			return !f.Resolved() && !f.DetectedAt.Before(base.Add(50*time.Second)) && !f.DetectedAt.After(base.Add(100*time.Second))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var want []Finding
			for _, f := range findings {
				if tc.keep(f) {
					want = append(want, f)
				}
			}
			slices.SortFunc(want, func(a, b Finding) int {
				if tc.filter.OldestFirst {
					return a.DetectedAt.Compare(b.DetectedAt)
				}
				return b.DetectedAt.Compare(a.DetectedAt)
			})
			f := tc.filter
			f.Source = prefix
			f.Limit = 31
			var got []Finding
			for page := 0; page < 10; page++ {
				rows, err := repo.List(ctx, f)
				require.NoError(t, err)
				got = append(got, rows...)
				if len(rows) < f.Limit {
					break
				}
				f.Cursor = EncodeCursor(rows[len(rows)-1], false)
			}
			require.Len(t, got, len(want))
			for i, row := range got {
				require.Equal(t, want[i].ID, row.ID)
				require.Equal(t, want[i].Severity, row.Severity)
				require.Equal(t, want[i].Metadata, row.Metadata)
				var n int
				_, err := fmt.Sscan(row.Metadata["row"], &n)
				require.NoError(t, err)
				if n%2 == 0 {
					require.Equal(t, uint8(n%100), row.Score)
					require.Equal(t, "team", row.OwnerTeam)
				} else {
					require.Zero(t, row.Score)
					require.Empty(t, row.OwnerTeam)
				}
			}
		})
	}
	// Compare the actual List's page-selection query against the former full
	// enrichment join on identical data. Hydration still returns enrichment.
	comment := prefix + "-current"
	currentCtx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": comment, "log_queries": 1, "log_queries_probability": 1})
	got, err := repo.List(currentCtx, Filter{Source: prefix, Limit: 50})
	require.NoError(t, err)
	legacy := "SELECT id FROM (" + fmt.Sprintf(selectFindingKeysArgMax, "LEFT", "1=1", "") + " WHERE f.source=? GROUP BY " + findingKeysGroupBy + " HAVING resolved_at < toDateTime('2000-01-01 00:00:00')) ORDER BY detected_at DESC, id DESC LIMIT ?"
	legacyCtx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": prefix + "-legacy", "log_queries": 1, "log_queries_probability": 1})
	var wantIDs []string
	require.NoError(t, ch.Select(legacyCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			wantIDs = append(wantIDs, id)
		}
		return rows.Err()
	}, legacy, prefix, 50))
	var gotIDs []string
	for _, f := range got {
		gotIDs = append(gotIDs, f.ID)
	}
	require.Equal(t, wantIDs, gotIDs)
	require.NoError(t, ch.Exec(ctx, "SYSTEM FLUSH LOGS"))
	reads := func(tag string) uint64 {
		var calls, rows uint64
		require.NoError(t, ch.Select(ctx, func(r driver.Rows) error {
			if !r.Next() {
				return fmt.Errorf("missing query telemetry")
			}
			return r.Scan(&calls, &rows)
		},
			"SELECT count(),sum(read_rows) FROM system.query_log WHERE type='QueryFinish' AND log_comment=? AND startsWith(query,'SELECT id FROM (')", tag))
		require.Equal(t, uint64(1), calls)
		return rows
	}
	oldRows, newRows := reads(prefix+"-legacy"), reads(comment)
	t.Logf("page-selection read rows: joined=%d narrow=%d", oldRows, newRows)
	require.GreaterOrEqual(t, oldRows, uint64(noise))
	require.Less(t, newRows, oldRows-uint64(noise/2), "page selection must not scan unrelated enrichments")
}
