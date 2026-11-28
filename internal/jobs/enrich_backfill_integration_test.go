//go:build integration

package jobs

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertest"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

type scopedBackfillFindings struct {
	service *finding.Service
	source  string
}

func (s scopedBackfillFindings) List(ctx context.Context, filter finding.Filter) ([]finding.Finding, error) {
	filter.Source = s.source
	return s.service.List(ctx, filter)
}

func (s scopedBackfillFindings) EnrichmentCandidates(ctx context.Context, filter finding.Filter) (finding.EnrichmentPage, error) {
	filter.Source = s.source
	return s.service.EnrichmentCandidates(ctx, filter)
}

func TestEnrichBackfillIncludesDeferredInformation(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" || os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires isolated migrated databases")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool, err := db.NewPool(ctx, os.Getenv("TEST_DATABASE_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	defer trackNewBackfillJobs(t, ctx, pool)()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	require.NoError(t, err)
	ctx = rivertest.WorkContext(ctx, client)
	prefix := "backfill-" + uuid.NewString()
	defer func() {
		_, err := pool.Exec(ctx, "DELETE FROM river_job WHERE starts_with(args->>'finding_id',$1)", prefix)
		require.NoError(t, err)
		for _, table := range []string{"findings", "finding_enrichment", "signals"} {
			require.NoError(t, ch.Exec(ctx, "DELETE FROM "+table+" WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
		}
	}()
	findings := finding.NewService(finding.NewCHRepo(ch))
	var observed, blockers []finding.Finding
	for _, severity := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo} {
		observed = append(observed, finding.Finding{ID: prefix + "-" + string(severity), Source: prefix, ResourceID: prefix, Severity: severity})
	}
	require.NoError(t, findings.RecordObserved(ctx, observed))
	for i := range enrichQueueMax {
		blockers = append(blockers, finding.Finding{ID: fmt.Sprintf("%s-block-%d", prefix, i)})
	}
	enqueueEnrichPriority(ctx, blockers, enrichSweepPriority)
	enqueueEnrichIfCapacity(ctx, observed)
	var automatic int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE kind='enrich_sweep' AND args->>'backfill_only'='true' AND state IN ('available','scheduled','running','retryable','pending')").Scan(&automatic))
	require.Equal(t, 1, automatic, "deferred findings must durably wake backfill without a periodic tick")
	var queued int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE starts_with(args->>'finding_id',$1) AND NOT starts_with(args->>'finding_id',$2)", prefix, prefix+"-block-").Scan(&queued))
	require.Zero(t, queued, "a full ingest queue must defer all five severities")
	_, err = pool.Exec(ctx, "DELETE FROM river_job WHERE starts_with(args->>'finding_id',$1)", prefix+"-block-")
	require.NoError(t, err)
	sweep := &EnrichSweepWorker{findings: scopedBackfillFindings{findings, prefix}}
	require.NoError(t, sweep.Work(ctx, &river.Job[EnrichSweepArgs]{}))
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE starts_with(args->>'finding_id',$1)", prefix).Scan(&queued))
	require.Equal(t, len(observed), queued, "the backstop must not strand informational findings")
	worker := &EnrichWorker{findings: newEnrichFindingFetcher(findings), enrich: enrich.NewService(findings, enrich.NewSignalCHRepo(ch), []enrich.Source{enrich.BaseSeverity{}})}
	for _, f := range observed {
		var count int
		require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE args->>'finding_id'=$1 AND state='available'", f.ID).Scan(&count))
		require.Equal(t, 1, count, f.Severity)
		require.NoError(t, worker.Work(ctx, &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}}))
		stored, err := findings.Get(ctx, f.ID)
		require.NoError(t, err)
		require.True(t, stored.EnrichedAt.After(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)), f.Severity)
	}
	remaining, err := findings.List(ctx, finding.Filter{Source: prefix, Unenriched: true})
	require.NoError(t, err)
	require.Empty(t, remaining)
}
