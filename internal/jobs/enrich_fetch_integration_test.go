//go:build integration

package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestEnrichFetchPreservesStoredValuesWithFewerQueries(t *testing.T) {
	if os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	prefix := "fetch-" + uuid.NewString()
	defer func() {
		for _, table := range []string{"findings", "finding_enrichment"} {
			require.NoError(t, ch.Exec(ctx, "DELETE FROM "+table+" WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
		}
	}()
	service := finding.NewService(finding.NewCHRepo(ch))
	var input []finding.Finding
	var enriched []finding.Enrichment
	for i := range 128 {
		id := fmt.Sprintf("%s-%d", prefix, i)
		metadata := map[string]string{"ordinal": fmt.Sprint(i)}
		if i%100 == 0 {
			metadata["wide"] = strings.Repeat("payload ", 10240)
		}
		input = append(input, finding.Finding{ID: id, ResourceID: prefix, Source: "cspm", Severity: finding.SeverityHigh,
			Title: "title-" + fmt.Sprint(i), Metadata: metadata, DetectedAt: time.Now()})
		enriched = append(enriched, finding.Enrichment{ID: id, Score: uint8(i%80 + 1), ScoreBand: "monitor", EnrichedAt: time.Now(), OwnerTeam: "team-" + fmt.Sprint(i)})
	}
	require.NoError(t, service.RecordObserved(ctx, input))
	require.NoError(t, service.RecordEnrichment(ctx, enriched))
	// Compare every field with the ordinary point-read path, including wide
	// metadata, lifecycle timestamps and independently versioned enrichment.
	want := make(map[string]finding.Finding, len(input))
	for _, f := range input {
		value, err := service.Get(ctx, f.ID)
		require.NoError(t, err)
		want[f.ID] = value
	}
	comment := prefix + "-batched"
	readCtx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": comment, "log_queries": 1, "log_queries_probability": 1})
	fetcher := newEnrichFindingFetcher(service)
	var group errgroup.Group
	group.SetLimit(32)
	ids := make([]string, 0, len(input)+1)
	for _, f := range input {
		ids = append(ids, f.ID)
	}
	ids = append(ids, prefix+"-missing")
	for _, id := range ids {
		group.Go(func() (err error) {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("finding reader panic: %v", p)
				}
			}()
			got, err := fetcher.Get(readCtx, id)
			if id == prefix+"-missing" {
				if !errors.Is(err, finding.ErrNotFound) {
					return fmt.Errorf("missing finding returned %v", err)
				}
				return nil
			}
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(want[id], got) {
				return fmt.Errorf("stored finding differs for %s", id)
			}
			return nil
		})
	}
	require.NoError(t, group.Wait())
	require.NoError(t, ch.Exec(ctx, "SYSTEM FLUSH LOGS"))
	var queries, readRows, readBytes uint64
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing finding read telemetry")
		}
		return rows.Scan(&queries, &readRows, &readBytes)
	}, `SELECT count(),sum(read_rows),sum(read_bytes) FROM system.query_log WHERE type='QueryFinish' AND log_comment=?`, comment))
	require.Positive(t, queries)
	require.Less(t, queries, uint64(len(ids)))
	t.Logf("%d worker reads: %d queries, %d rows, %d bytes", len(ids), queries, readRows, readBytes)
	input[0].Title = "updated immediately"
	input[0].Metadata = map[string]string{"revision": "two"}
	require.NoError(t, service.RecordObserved(ctx, input[:1]))
	enriched[0].Score = 99
	enriched[0].EnrichedAt = time.Now()
	require.NoError(t, service.RecordEnrichment(ctx, enriched[:1]))
	fresh, err := fetcher.Get(ctx, input[0].ID)
	require.NoError(t, err)
	ordinary, err := service.Get(ctx, input[0].ID)
	require.NoError(t, err)
	require.Equal(t, ordinary, fresh)
	require.Equal(t, "updated immediately", fresh.Title)
	require.Equal(t, uint8(99), fresh.Score)
	require.Equal(t, map[string]string{"revision": "two"}, fresh.Metadata)
}
