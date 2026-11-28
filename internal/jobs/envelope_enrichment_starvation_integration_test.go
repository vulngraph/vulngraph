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

func TestEnvelopeCachedPrefixDoesNotStarveChangedFinding(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("requires disposable stores")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
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
	prefix := fmt.Sprintf("cached-prefix-%d", time.Now().UnixNano())
	rows := make([]finding.Finding, enrichSweepMax+1)
	for i := range rows {
		rows[i] = finding.Finding{ID: fmt.Sprintf("%s-%05d", prefix, i), Source: prefix, ResourceID: prefix, Severity: finding.SeverityHigh}
	}
	tail := rows[len(rows)-1]
	report := map[string]any{"prefix_findings": enrichSweepMax, "changed_tail": tail.ID, "default_interval_seconds": defaultEnrichInterval.Seconds(), "scope": "two manual ordinary production sweeps with real stores/cache; bulk-seeded unchanged prefix scores/cache, tail actually enriched; no elapsed scheduler guarantee"}
	var sweeps []map[string]any
	t.Cleanup(func() {
		report["passed"] = !t.Failed()
		report["sweeps"] = sweeps
		b, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "enrichment-prefix-starvation.json"), b, 0600))
	})
	require.NoError(t, findings.RecordObserved(ctx, rows))
	require.NoError(t, worker.Work(ctx, &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: tail.ID}}))
	stored, err := findings.Get(ctx, tail.ID)
	require.NoError(t, err)
	old := time.Now().Add(-2 * time.Hour).UTC()
	scores := make([]finding.Enrichment, enrichSweepMax)
	for i := range scores {
		scores[i] = finding.EnrichmentOf(stored)
		scores[i].ID = rows[i].ID
		scores[i].EnrichedAt = old
		in := fingerprintInput(rows[i])
		require.NoError(t, cache.Put(ctx, enrichcache.Entry{FindingID: rows[i].ID, InputFP: enrichcache.Fingerprint(in), ContextFP: enrichcache.ContextFingerprint(in), ScoreBand: stored.ScoreBand, EnrichedAt: old}))
	}
	require.NoError(t, findings.RecordEnrichment(ctx, scores))
	tail.Severity = finding.SeverityCritical
	require.NoError(t, findings.RecordObserved(ctx, []finding.Finding{tail}))
	previous := map[string]bool{}
	for pass := range 2 {
		// A new service/worker instance must resume the persisted checkpoint.
		sweep := &EnrichSweepWorker{findings: scopedBackfillFindings{findings, prefix}, progress: enrichcache.NewService(enrichcache.NewPGRepo(pool))}
		require.NoError(t, sweep.Work(ctx, &river.Job[EnrichSweepArgs]{}))
		selected, err := pool.Query(ctx, "SELECT args->>'finding_id' FROM river_job WHERE kind='enrich' AND state='available' AND starts_with(args->>'finding_id',$1) ORDER BY id", prefix)
		require.NoError(t, err)
		var ids []string
		for selected.Next() {
			var id string
			require.NoError(t, selected.Scan(&id))
			ids = append(ids, id)
		}
		require.NoError(t, selected.Err())
		selected.Close()
		require.NotEmpty(t, ids)
		require.LessOrEqual(t, len(ids), enrichSweepMax)
		admitted, repeated := false, 0
		before := measured.calls
		for _, id := range ids {
			if id == tail.ID {
				admitted = true
			}
			if previous[id] {
				repeated++
			}
			previous[id] = true
			require.NoError(t, worker.Work(ctx, &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: id}}))
		}
		_, err = pool.Exec(ctx, "UPDATE river_job SET state='completed',finalized_at=now() WHERE kind='enrich' AND state='available' AND starts_with(args->>'finding_id',$1)", prefix)
		require.NoError(t, err)
		sweeps = append(sweeps, map[string]any{"pass": pass, "selected": len(ids), "tail_admitted": admitted, "repeated_ids": repeated, "actual_rescores": measured.calls - before})
		if pass == 0 {
			require.Len(t, ids, enrichSweepMax)
			require.False(t, admitted)
		} else {
			require.True(t, admitted, "a new worker must advance past the cached prefix")
		}
	}
	var points int64
	require.NoError(t, ch.Select(ctx, func(result driver.Rows) error {
		require.True(t, result.Next())
		require.NoError(t, result.Scan(&points))
		require.False(t, result.Next())
		return result.Err()
	}, `SELECT JSONExtractInt(arrayFirst(x -> JSONExtractString(x,'source')='base_severity',JSONExtractArrayRaw(argMax(factors,synced_at))),'points') FROM signals WHERE id=?`, tail.ID))
	report["tail_base_severity_points"] = points
	latest, err := findings.Get(ctx, tail.ID)
	require.NoError(t, err)
	require.Equal(t, finding.SeverityCritical, latest.Severity)
	require.Equal(t, int64(40), points, "unchanged cached prefix must not starve a changed already-enriched tail")
}
