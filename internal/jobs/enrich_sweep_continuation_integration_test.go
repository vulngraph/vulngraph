//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertest"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

type continuationEnricher struct {
	service *enrich.Service
	calls   atomic.Int64
}

func (e *continuationEnricher) Enrich(ctx context.Context, f finding.Finding) (enrich.Score, error) {
	e.calls.Add(1)
	return e.service.Enrich(ctx, f)
}

type continuationFindings struct {
	scopedBackfillFindings
	backfillReads  atomic.Int64
	candidateReads atomic.Int64
}

func (f *continuationFindings) List(ctx context.Context, filter finding.Filter) ([]finding.Finding, error) {
	f.backfillReads.Add(1)
	return f.scopedBackfillFindings.List(ctx, filter)
}

func (f *continuationFindings) EnrichmentCandidates(ctx context.Context, filter finding.Filter) (finding.EnrichmentPage, error) {
	f.candidateReads.Add(1)
	return f.scopedBackfillFindings.EnrichmentCandidates(ctx, filter)
}

// Real stores, cache and River snoozes; a manually admitted first tick avoids
// waiting for the ordinary fifteen-minute cadence. No synthetic faster cadence.
func TestEnrichmentContinuationRecoversAndEndsAtPassBoundary(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("requires disposable benchmark databases")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	pool, err := db.NewPool(ctx, os.Getenv("PERF_POSTGRES_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	ch, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	_, err = pool.Exec(ctx, "TRUNCATE river_job")
	require.NoError(t, err)
	findings := finding.NewService(finding.NewCHRepo(ch))
	cache := enrichcache.NewService(enrichcache.NewPGRepo(pool))
	observed := &continuationEnricher{service: enrich.NewService(findings, enrich.NewSignalCHRepo(ch), []enrich.Source{enrich.BaseSeverity{}})}
	prefix := fmt.Sprintf("continuation-%d", time.Now().UnixNano())
	report := map[string]any{"findings": 2*enrichSweepMax + 1, "per_execution_ceiling": enrichSweepMax, "scope": "real queue/cache continuation and restart; manually admitted first/next ordinary ticks, not elapsed periodic freshness"}
	t.Cleanup(func() {
		report["passed"] = !t.Failed()
		report["actual_scoring_calls"] = observed.calls.Load()
		data, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "enrichment-continuation.json"), data, 0600))
	})
	rows := make([]finding.Finding, 2*enrichSweepMax+1)
	for i := range rows {
		rows[i] = finding.Finding{ID: fmt.Sprintf("%s-%05d", prefix, i), Source: prefix, ResourceID: prefix, Severity: finding.SeverityHigh}
	}
	require.NoError(t, findings.RecordObserved(ctx, rows))
	direct := &EnrichWorker{enrich: observed, findings: newEnrichFindingFetcher(findings), cache: cache}
	plain, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	require.NoError(t, err)
	workCtx := rivertest.WorkContext(ctx, plain)
	for _, row := range []finding.Finding{rows[0], rows[len(rows)-1]} {
		require.NoError(t, direct.Work(workCtx, &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: row.ID}}))
	}
	stored, err := findings.Get(ctx, rows[len(rows)-1].ID)
	require.NoError(t, err)
	old := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Millisecond)
	scores := make([]finding.Enrichment, len(rows))
	for i, row := range rows {
		scores[i] = finding.EnrichmentOf(stored)
		scores[i].ID = row.ID
		scores[i].EnrichedAt = old
		in := fingerprintInput(row)
		require.NoError(t, cache.Put(ctx, enrichcache.Entry{FindingID: row.ID, InputFP: enrichcache.Fingerprint(in), ContextFP: enrichcache.ContextFingerprint(in), ScoreBand: stored.ScoreBand, EnrichedAt: old}))
	}
	require.NoError(t, findings.RecordEnrichment(ctx, scores))
	tail := rows[len(rows)-1]
	tail.Severity = finding.SeverityCritical
	require.NoError(t, findings.RecordObserved(ctx, []finding.Finding{tail}))
	source := &continuationFindings{scopedBackfillFindings: scopedBackfillFindings{findings, prefix}}
	first := newEnrichSweepWorker(source, cache)
	err = first.Work(workCtx, &river.Job[EnrichSweepArgs]{})
	var snooze *river.JobSnoozeError
	require.ErrorAs(t, err, &snooze, "a full bounded page must retain its own durable continuation")
	require.Positive(t, snooze.Duration)
	checkpoint, err := cache.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.False(t, checkpoint.Before.IsZero())
	// Drain the first page before changing a prefix row: finishing this pass must
	// not pretend that a later update to an already-enumerated row was scored.
	ids, err := pool.Query(ctx, "SELECT args->>'finding_id' FROM river_job WHERE kind='enrich' ORDER BY id")
	require.NoError(t, err)
	var firstIDs []string
	for ids.Next() {
		var id string
		require.NoError(t, ids.Scan(&id))
		firstIDs = append(firstIDs, id)
	}
	require.NoError(t, ids.Err())
	ids.Close()
	require.Len(t, firstIDs, enrichSweepMax)
	for _, id := range firstIDs {
		require.NoError(t, direct.Work(workCtx, &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: id}}))
	}
	_, err = pool.Exec(ctx, "UPDATE river_job SET state='completed',finalized_at=now() WHERE kind='enrich'")
	require.NoError(t, err)
	changedPrefix, err := findings.Get(ctx, firstIDs[0])
	require.NoError(t, err)
	require.Equal(t, uint8(30), changedPrefix.Score)
	report["late_prefix_id"] = changedPrefix.ID
	changedPrefix.Severity = finding.SeverityCritical
	require.NoError(t, findings.RecordObserved(ctx, []finding.Finding{changedPrefix}))
	blockers := make([]finding.Finding, enrichQueueMax)
	for i := range blockers {
		blockers[i].ID = fmt.Sprintf("%s-block-%d", prefix, i)
	}
	enqueueEnrich(workCtx, blockers)
	backfillReads, candidateReads := source.backfillReads.Load(), source.candidateReads.Load()
	err = first.Work(workCtx, &river.Job[EnrichSweepArgs]{})
	require.ErrorAs(t, err, &snooze, "queue pressure must postpone, not complete, an unfinished pass")
	afterPressure, err := cache.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, checkpoint, afterPressure)
	require.Equal(t, backfillReads, source.backfillReads.Load(), "pressure waits must not rerun backfill scans")
	require.Equal(t, candidateReads, source.candidateReads.Load(), "pressure waits must not read candidate pages")
	_, err = pool.Exec(ctx, "DELETE FROM river_job WHERE starts_with(args->>'finding_id',$1)", prefix+"-block-")
	require.NoError(t, err)
	newClient := func() *river.Client[pgx.Tx] {
		workers := river.NewWorkers()
		river.AddWorker(workers, &EnrichWorker{enrich: observed, findings: newEnrichFindingFetcher(findings), cache: cache})
		river.AddWorker(workers, newEnrichSweepWorker(source, enrichcache.NewService(enrichcache.NewPGRepo(pool))))
		addRescueOnlyWorkers(workers)
		client, e := river.NewClient(riverpgxv5.New(pool), &river.Config{Workers: workers, Queues: map[string]river.QueueConfig{queueEnrich: queueConfig(queueEnrich)}})
		require.NoError(t, e)
		return client
	}
	client := newClient()
	inserted, err := client.Insert(ctx, EnrichSweepArgs{}, nil)
	require.NoError(t, err)
	runCtx, stopRun := soakRiverContext(ctx)
	defer stopRun()
	require.NoError(t, client.Start(runCtx))
	defer func() {
		stop, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		require.NoError(t, client.StopAndCancel(stop))
	}()
	require.Eventually(t, func() bool {
		var paused bool
		e := pool.QueryRow(ctx, "SELECT state IN ('scheduled','available') AND scheduled_at>now() AND COALESCE((metadata->>'snoozes')::int,0)>0 FROM river_job WHERE id=$1", inserted.Job.ID).Scan(&paused)
		return e == nil && paused
	}, 30*time.Second, 25*time.Millisecond, "River must persist the continuation on the same job")
	duplicate, err := client.Insert(ctx, EnrichSweepArgs{}, nil)
	require.NoError(t, err)
	require.Equal(t, inserted.Job.ID, duplicate.Job.ID, "an overlapping periodic tick must leave the existing continuation intact")
	require.NoError(t, client.Stop(ctx))
	persisted, err := cache.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, checkpoint.Before, persisted.Before, "restart preserves the fixed pass cutoff")
	client = newClient()
	require.NoError(t, client.Start(runCtx))
	peak := map[string]int{}
	require.Positive(t, waitSoakQueues(t, ctx, pool, []string{queueEnrich}, peak))
	var state string
	var snoozes, attempt int
	require.NoError(t, pool.QueryRow(ctx, "SELECT state,COALESCE((metadata->>'snoozes')::int,0),attempt FROM river_job WHERE id=$1", inserted.Job.ID).Scan(&state, &snoozes, &attempt))
	require.Equal(t, "completed", state)
	require.Positive(t, snoozes)
	require.LessOrEqual(t, attempt, enrichSweepMaxAttempts)
	require.LessOrEqual(t, peak[queueEnrich], enrichQueueMax+enrichSweepMax+1)
	complete, err := cache.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.True(t, complete.Before.IsZero())
	require.Empty(t, complete.Cursor)
	points := func(id string) int64 {
		var value int64
		e := ch.Select(ctx, func(result driver.Rows) error {
			require.True(t, result.Next())
			require.NoError(t, result.Scan(&value))
			require.False(t, result.Next())
			return result.Err()
		}, "SELECT JSONExtractInt(arrayFirst(x -> JSONExtractString(x,'source')='base_severity',JSONExtractArrayRaw(argMax(factors,synced_at))),'points') FROM signals WHERE id=?", id)
		require.NoError(t, e)
		return value
	}
	require.Equal(t, int64(40), points(tail.ID))
	prefixAfterPass, err := findings.Get(ctx, changedPrefix.ID)
	require.NoError(t, err)
	require.Equal(t, uint8(30), prefixAfterPass.Score, "enumeration completion is not a promise about updates behind the cursor")
	require.Equal(t, int64(len(backfillSeverities)), source.backfillReads.Load(), "continuations must not repeat initial maintenance")
	report["first_pass_backfill_queries"] = source.backfillReads.Load()
	report["first_pass_candidate_queries"] = source.candidateReads.Load()
	report["first_pass_tail_points"] = 40
	report["late_prefix_score_after_first_pass"] = 30
	next, err := client.Insert(ctx, EnrichSweepArgs{}, nil)
	require.NoError(t, err)
	require.NotEqual(t, inserted.Job.ID, next.Job.ID)
	require.Positive(t, waitSoakQueues(t, ctx, pool, []string{queueEnrich}, peak))
	require.Equal(t, int64(40), points(changedPrefix.ID), "the next ordinary pass must repair the late prefix update")
	report["late_prefix_points_after_next_pass"] = 40
	require.Equal(t, int64(2*len(backfillSeverities)), source.backfillReads.Load())
	report["two_pass_backfill_queries"] = source.backfillReads.Load()
	report["two_pass_candidate_queries"] = source.candidateReads.Load()
	report["continuation_snoozes"] = snoozes
	report["peak_queue_depth"] = peak[queueEnrich]
}
