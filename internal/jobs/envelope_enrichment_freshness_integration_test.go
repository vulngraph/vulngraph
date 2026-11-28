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

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertest"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

type envelopeCountingEnricher struct {
	service *enrich.Service
	calls   int
}

func (e *envelopeCountingEnricher) Enrich(ctx context.Context, f finding.Finding) (enrich.Score, error) {
	e.calls++
	return e.service.Enrich(ctx, f)
}

// Exercise the ordinary sweep worker directly: no accelerated scheduler or
// sleeping is needed to distinguish backfill from changed-input convergence.
func TestEnvelopeAlreadyEnrichedDriftRecovery(t *testing.T) {
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
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	require.NoError(t, err)
	ctx = rivertest.WorkContext(ctx, client)
	findings := finding.NewService(finding.NewCHRepo(ch))
	cache := enrichcache.NewService(enrichcache.NewPGRepo(pool))
	measured := &envelopeCountingEnricher{service: enrich.NewService(findings, enrich.NewSignalCHRepo(ch), []enrich.Source{enrich.BaseSeverity{}})}
	worker := &EnrichWorker{enrich: measured, findings: newEnrichFindingFetcher(findings), cache: cache}
	prefix := fmt.Sprintf("drift-replay-%d", time.Now().UnixNano())
	rows := make([]finding.Finding, 4)
	for i := range rows {
		rows[i] = finding.Finding{ID: fmt.Sprintf("%s-%d", prefix, i), Source: prefix, ResourceID: prefix, Severity: finding.SeverityHigh}
	}
	report := map[string]any{"expected_findings": len(rows), "queue_ceiling": enrichQueueMax, "sweep_budget": enrichSweepMax,
		"scope": "manual ordinary production workers with real stores/cache; fifteen-minute schedule and eight-minute constructor offset are not elapsed-time measurements"}
	t.Cleanup(func() {
		report["passed"] = !t.Failed()
		b, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "enrichment-drift.json"), b, 0600))
	})
	require.NoError(t, findings.RecordObserved(ctx, rows))
	initial := map[string]string{}
	for _, row := range rows {
		require.NoError(t, worker.Work(ctx, &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: row.ID}}))
		entry, e := cache.Get(ctx, row.ID)
		require.NoError(t, e)
		initial[row.ID] = entry.InputFP
	}
	verify := func(points int64) {
		t.Helper()
		seen := map[string]bool{}
		require.NoError(t, ch.Select(ctx, func(result driver.Rows) error {
			for result.Next() {
				var id string
				var got int64
				if e := result.Scan(&id, &got); e != nil {
					return e
				}
				require.Contains(t, initial, id)
				require.False(t, seen[id])
				seen[id] = true
				require.Equal(t, points, got, id)
			}
			return result.Err()
		}, `SELECT id,JSONExtractInt(arrayFirst(x -> JSONExtractString(x,'source')='base_severity',JSONExtractArrayRaw(argMax(factors,synced_at))),'points')
		FROM signals WHERE startsWith(id,?) GROUP BY id`, prefix))
		require.Len(t, seen, len(rows), "every expected finding, independent of queued jobs")
	}
	verify(30)
	blockers := make([]finding.Finding, enrichQueueMax)
	for i := range blockers {
		blockers[i].ID = fmt.Sprintf("%s-blocker-%d", prefix, i)
	}
	enqueueEnrich(ctx, blockers)
	for i := range rows {
		rows[i].Severity = finding.SeverityCritical
	}
	require.NoError(t, findings.RecordObserved(ctx, rows))
	enqueueEnrichIfCapacity(ctx, rows)
	var queued int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE kind='enrich_sweep' AND args->>'backfill_only'='true'").Scan(&queued))
	require.Equal(t, 1, queued)
	_, err = pool.Exec(ctx, "DELETE FROM river_job WHERE starts_with(args->>'finding_id',$1)", prefix+"-blocker-")
	require.NoError(t, err)
	sweep := &EnrichSweepWorker{findings: scopedBackfillFindings{findings, prefix}, progress: cache}
	require.NoError(t, sweep.Work(ctx, &river.Job[EnrichSweepArgs]{Args: EnrichSweepArgs{BackfillOnly: true}}))
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE kind='enrich' AND starts_with(args->>'finding_id',$1)", prefix).Scan(&queued))
	require.Zero(t, queued, "backfill does not refresh already-enriched inputs")
	verify(30)
	report["stale_after_backfill"] = len(rows)
	start := time.Now()
	require.NoError(t, sweep.Work(ctx, &river.Job[EnrichSweepArgs]{}))
	jobs, err := pool.Query(ctx, "SELECT args->>'finding_id' FROM river_job WHERE kind='enrich' AND starts_with(args->>'finding_id',$1)", prefix)
	require.NoError(t, err)
	var ids []string
	for jobs.Next() {
		var id string
		require.NoError(t, jobs.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, jobs.Err())
	jobs.Close()
	require.Len(t, ids, len(rows))
	for _, id := range ids {
		require.Contains(t, initial, id)
		require.NoError(t, worker.Work(ctx, &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: id}}))
		entry, e := cache.Get(ctx, id)
		require.NoError(t, e)
		require.NotEqual(t, initial[id], entry.InputFP, "severity change must bypass recent cache")
	}
	verify(40)
	report["ordinary_sweep_repaired"] = len(ids)
	report["manual_repair_seconds"] = time.Since(start).Seconds()
	require.Equal(t, 2*len(rows), measured.calls)
	for _, id := range ids {
		require.NoError(t, worker.Work(ctx, &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: id}}))
	}
	require.Equal(t, 2*len(rows), measured.calls, "unchanged cached inputs still skip rescoring")
}
