//go:build integration

package jobs

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertest"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestDeferredEnrichmentRecoversWithoutPeriodicTicks(t *testing.T) {
	if os.Getenv("PERF_ISOLATED") != "1" || os.Getenv("TEST_DATABASE_URL") == "" || os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires benchmark-owned disposable databases")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pool, err := db.NewPool(ctx, os.Getenv("TEST_DATABASE_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	// No application databases are permitted by this test's opt-in contract.
	// The benchmark has no consumers running during its storage regressions.
	_, err = pool.Exec(ctx, "TRUNCATE river_job")
	require.NoError(t, err)
	prefix := "auto-backfill-" + uuid.NewString()
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		_, err := pool.Exec(cleanup, "DELETE FROM river_job WHERE args::text LIKE $1", "%"+prefix+"%")
		require.NoError(t, err)
		for _, table := range []string{"findings", "finding_enrichment", "signals"} {
			require.NoError(t, ch.Exec(cleanup, "DELETE FROM "+table+" WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
		}
	}()
	defer trackNewBackfillJobs(t, ctx, pool)()
	findings := finding.NewService(finding.NewCHRepo(ch))
	rows := make([]finding.Finding, 2*enrichSweepMax+11)
	for i := range rows {
		rows[i] = finding.Finding{ID: fmt.Sprintf("%s-%06d", prefix, i), Source: prefix, ResourceID: prefix, Severity: backfillSeverities[i%len(backfillSeverities)]}
	}
	require.NoError(t, findings.RecordObserved(ctx, rows))
	observed := &soakEnricher{service: enrich.NewService(findings, enrich.NewSignalCHRepo(ch), []enrich.Source{enrich.BaseSeverity{}}), values: map[string]soakEnrichmentValue{}}
	newClient := func() *river.Client[pgx.Tx] {
		workers := river.NewWorkers()
		river.AddWorker(workers, &EnrichWorker{findings: newEnrichFindingFetcher(findings), enrich: observed})
		river.AddWorker(workers, &EnrichSweepWorker{findings: scopedBackfillFindings{findings, prefix}})
		addRescueOnlyWorkers(workers)
		client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Workers: workers, Queues: map[string]river.QueueConfig{queueEnrich: queueConfig(queueEnrich)}})
		require.NoError(t, err)
		return client
	}
	client := newClient()
	producer := rivertest.WorkContext(ctx, client)
	blockers := make([]finding.Finding, enrichQueueMax)
	for i := range blockers {
		blockers[i].ID = fmt.Sprintf("%s-block-%d", prefix, i)
	}
	enqueueEnrich(producer, blockers)
	enqueueEnrichIfCapacity(producer, rows)
	enqueueEnrichIfCapacity(producer, rows) // duplicate wake-ups remain one row
	var backfillID int64
	var count int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*),min(id) FROM river_job WHERE kind='enrich_sweep' AND args->>'backfill_only'='true'").Scan(&count, &backfillID))
	require.Equal(t, 1, count)
	_, err = pool.Exec(ctx, "DELETE FROM river_job WHERE starts_with(args->>'finding_id',$1)", prefix+"-block-")
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
		var scheduled bool
		err := pool.QueryRow(ctx, "SELECT state IN ('scheduled','available') AND scheduled_at>now() AND COALESCE((metadata->>'snoozes')::int,0)>0 FROM river_job WHERE id=$1", backfillID).Scan(&scheduled)
		return err == nil && scheduled
	}, 30*time.Second, 25*time.Millisecond, "backfill must durably reschedule itself after a bounded batch")
	require.NoError(t, client.StopAndCancel(ctx))
	client = newClient()
	require.NoError(t, client.Start(runCtx))
	peak := map[string]int{}
	waitSoakQueues(t, ctx, pool, []string{queueEnrich}, peak)
	var state string
	var snoozes, attempt int
	require.NoError(t, pool.QueryRow(ctx, "SELECT state,COALESCE((metadata->>'snoozes')::int,0),attempt FROM river_job WHERE id=$1", backfillID).Scan(&state, &snoozes, &attempt))
	require.Equal(t, "completed", state)
	require.GreaterOrEqual(t, snoozes, 3, "more than two batches must recover without periodic ticks")
	require.LessOrEqual(t, attempt, enrichSweepMaxAttempts, "snoozes must not consume the retry budget")
	require.LessOrEqual(t, peak[queueEnrich], backfillQueueCeiling+enrichSweepMax+1, "automatic refill retains queue backpressure")
	report := &soakReport{}
	verifySoakEnrichment(t, ctx, pool, ch, findings, observed, report)
	require.Equal(t, len(rows), report.VerifiedScores)
}
