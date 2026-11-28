//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
)

type lostEnrichmentCheckpoint struct {
	SweepProgressStore
	writes int
}

func (s *lostEnrichmentCheckpoint) AdvanceSweepProgress(ctx context.Context, revision int64, next enrichcache.SweepProgress) (bool, error) {
	s.writes++
	if s.writes == 2 {
		return false, errors.New("injected checkpoint outage after committed enqueue")
	}
	return s.SweepProgressStore.AdvanceSweepProgress(ctx, revision, next)
}

func TestEnvelopeEnrichmentCommittedQueueReplay(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("requires the disposable envelope runner")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pool, err := db.NewPool(ctx, os.Getenv("PERF_POSTGRES_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	ch, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 1)
	require.NoError(t, err)
	defer admin.Close()
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	require.NoError(t, err)
	findings := finding.NewService(finding.NewCHRepo(ch))
	cache := enrichcache.NewService(enrichcache.NewPGRepo(pool))
	initial, err := cache.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Empty(t, initial.Cursor)
	require.True(t, initial.Before.IsZero())
	prefix := fmt.Sprintf("progress-replay-%d", time.Now().UnixNano())
	rows := make([]finding.Finding, 4)
	scores := make([]finding.Enrichment, len(rows))
	old := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	for i := range rows {
		rows[i] = finding.Finding{ID: fmt.Sprintf("%s-%d", prefix, i), Source: prefix, ResourceID: prefix, Severity: finding.SeverityHigh, EnrichedAt: old}
		scores[i] = finding.EnrichmentOf(rows[i])
	}
	require.NoError(t, findings.RecordObserved(ctx, rows))
	require.NoError(t, findings.RecordEnrichment(ctx, scores))
	report := map[string]any{"expected_findings": len(rows), "scope": "real committed River batches, injected checkpoint failure, independent service restart; enumeration is not scoring completion"}
	t.Cleanup(func() {
		report["passed"] = !t.Failed()
		b, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "enrichment-progress-replay.json"), b, 0600))
	})
	access := perfassurance.QueryLogAccess{Flush: func(ctx context.Context) error { return admin.Exec(ctx, "SYSTEM FLUSH LOGS") }, Select: `SELECT query,query_duration_ms,read_rows,read_bytes,memory_usage,exception,Settings['max_threads'],Settings['max_block_size'],ProfileEvents FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds,query_id`}
	var page finding.EnrichmentPage
	sample, err := perfassurance.Measure(ctx, admin, access, prefix+"-candidate-page", func(ctx context.Context) error {
		var e error
		page, e = findings.EnrichmentCandidates(ctx, finding.Filter{Source: prefix, EnrichedBefore: time.Now().UTC().Truncate(time.Millisecond), Limit: len(rows)})
		return e
	})
	report["candidate_page"] = sample
	require.NoError(t, err)
	require.Len(t, sample.Queries, 1, "candidate selection and its seek key must come from one snapshot without ByIDs hydration")
	require.Len(t, page.IDs, len(rows))
	require.Equal(t, finding.EncodeStaleCursor(rows[len(rows)-1]), page.Cursor)
	queued := func() int {
		t.Helper()
		var n int
		require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE kind='enrich' AND state='available' AND starts_with(args->>'finding_id',$1)", prefix).Scan(&n))
		return n
	}
	first := &EnrichSweepWorker{findings: scopedBackfillFindings{findings, prefix}, progress: &lostEnrichmentCheckpoint{SweepProgressStore: cache}}
	n, err := first.drainDriftWith(ctx, client, len(rows))
	require.ErrorContains(t, err, "injected checkpoint outage")
	require.Equal(t, len(rows), n)
	require.Equal(t, len(rows), queued(), "queue transaction committed before checkpoint failure")
	lost, err := cache.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Empty(t, lost.Cursor)
	require.False(t, lost.Before.IsZero())
	report["committed_before_checkpoint_failure"] = queued()
	second := &EnrichSweepWorker{findings: scopedBackfillFindings{findings, prefix}, progress: enrichcache.NewService(enrichcache.NewPGRepo(pool))}
	n, err = second.drainDriftWith(ctx, client, len(rows))
	require.NoError(t, err)
	require.Equal(t, len(rows), n)
	require.Equal(t, len(rows), queued(), "retry must reuse durable pending jobs via args-level uniqueness")
	persisted, err := cache.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, page.Cursor, persisted.Cursor)
	require.True(t, lost.Before.Equal(persisted.Before))
	report["pending_after_replay"] = queued()
	n, err = second.drainDriftWith(ctx, client, len(rows))
	require.NoError(t, err)
	require.Zero(t, n, "exactly full final page is followed by explicit EOF")
	reset, err := cache.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Empty(t, reset.Cursor)
	require.True(t, reset.Before.IsZero())
}
