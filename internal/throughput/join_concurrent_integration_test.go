//go:build integration

package throughput

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type joinOperation struct {
	OldestObservation *time.Time `json:"oldest_observation_at,omitempty"`
	Kind              string     `json:"kind"`
	Scheduled         time.Time  `json:"scheduled_at"`
	Started           time.Time  `json:"started_at"`
	Finished          time.Time  `json:"finished_at"`
	Error             string     `json:"error,omitempty"`
	Verified          bool       `json:"verified"`
}

type concurrentJoinReport struct {
	Experiment         string                    `json:"experiment"`
	FixtureVersion     int                       `json:"fixture_version"`
	Phase              string                    `json:"merge_phase"`
	IngestMode         string                    `json:"ingest_mode"`
	ChunkRows          int                       `json:"repository_write_chunk_rows"`
	InputRowsPerSecond int                       `json:"input_observations_per_second"`
	FlushWindowSeconds float64                   `json:"collection_window_seconds"`
	SettleSeconds      float64                   `json:"merge_settle_seconds"`
	PartsBefore        map[string]joinPartCount  `json:"parts_before_merges"`
	PartsAtStart       map[string]joinPartCount  `json:"parts_at_measurement_start"`
	Variant            string                    `json:"variant"`
	Source             string                    `json:"source"`
	Duration           int                       `json:"arrival_seconds"`
	ReadRate           int                       `json:"read_arrivals_per_second"`
	WriteRate          float64                   `json:"write_batches_per_second"`
	BatchRows          int                       `json:"finding_rows_per_write_batch"`
	Workers            int                       `json:"read_workers"`
	Concurrency        int                       `json:"shared_ch_concurrency"`
	WaitScope          string                    `json:"wait_scope"`
	MutationScope      string                    `json:"mutation_scope"`
	Started            time.Time                 `json:"started_at"`
	Finished           time.Time                 `json:"finished_at"`
	ServerDrainedAt    time.Time                 `json:"server_drained_at"`
	TerminalDrain      float64                   `json:"terminal_drain_seconds"`
	Operations         []joinOperation           `json:"operations"`
	QueryCosts         []perfassurance.QueryCost `json:"query_costs"`
	ReadP95MS          float64                   `json:"read_end_to_end_p95_ms"`
	ReadP99MS          float64                   `json:"read_end_to_end_p99_ms"`
	BudgetFailures     []string                  `json:"budget_failures"`
	Passed             bool                      `json:"passed"`
}

func joinTask(g *errgroup.Group, ctx context.Context, fn func() error) {
	g.Go(func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("join workload panic: %v", p)
				log.FromContext(ctx).Error().Err(err).Msg("join probe failed")
			}
		}()
		return fn()
	})
}

func joinArrival(ctx context.Context, at time.Time) error {
	timer := time.NewTimer(max(time.Until(at), 0))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Re-observe existing rows and update enrichment provenance without changing any
// summary/cluster fields. Every read has one exact answer during these writes.
// Lifecycle changes and cross-table snapshot coherence are separate scenarios.
func joinWriteBatch(wave int, stamp int64) ([]finding.Finding, []finding.Enrichment) {
	var findings []finding.Finding
	var enrichments []finding.Enrichment
	marker := fmt.Sprintf("join-wave-%d", wave)
	for i := 0; i < 100; i++ {
		f := finding.Finding{ID: fmt.Sprintf("large-f-%d", i), Source: "noise", Type: "vulnerability", Severity: finding.SeverityHigh,
			Title: "Large finding", Description: marker + strings.Repeat("x", 256), ResourceID: fmt.Sprintf("resource-%d", i),
			CheckID: fmt.Sprintf("large-check-%d", i), Remediation: "fix", DetectedAt: time.Unix(stamp-int64(i), 0).UTC(), LastObservedAt: time.Now().UTC()}
		if i == 0 {
			f.Description = marker + strings.Repeat("x", 16384)
		}
		if i == 1 {
			f.Source = "sample"
		}
		if i%13 == 0 {
			f.Severity = finding.SeverityCritical
		}
		if i%17 == 0 {
			f.ResolvedAt = time.Unix(stamp+2, 0).UTC()
		}
		findings = append(findings, f)
		if i%19 != 0 {
			enrichments = append(enrichments, finding.Enrichment{ID: f.ID, Score: uint8(90 + i%10), ScoreBand: "high", KnownExploited: i%7 == 0,
				OwnerTeam: fmt.Sprintf("team-%d", (i+2)%23), OwnerSource: "tag", Environment: "prod", EnrichedAt: time.Now().UTC(), MustFixReason: marker})
		}
	}
	return findings, enrichments
}

func runConcurrentJoins(t *testing.T, ctx context.Context, admin, app *db.CH, p profile, n uint64, stamp int64, settings map[string]any, experiment string) {
	t.Helper()
	seconds, err := strconv.Atoi(os.Getenv("PERF_JOIN_MIXED_SECONDS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, seconds, 5)
	require.LessOrEqual(t, seconds, 60)
	rate, err := strconv.Atoi(os.Getenv("PERF_JOIN_READ_RATE"))
	require.NoError(t, err)
	require.Contains(t, []int{1, 2, 4}, rate)
	variant := os.Getenv("PERF_JOIN_VARIANT")
	require.Contains(t, []string{"baseline", "candidate"}, variant)
	report := concurrentJoinReport{Variant: variant, Source: os.Getenv("PERF_COMMIT"), Duration: seconds, ReadRate: rate, WriteRate: 2, BatchRows: 100, Workers: 8, Concurrency: 8,
		WaitScope:     "scheduled arrival to worker start; operation includes unseparated CH semaphore, pool and transport wait; write completion includes exact readback",
		MutationScope: "100 existing findings and 94 matching enrichments per wave; latest descriptions/provenance change, summary/cluster values stay invariant; merges enabled"}
	report.FixtureVersion = 2
	report.Experiment = experiment
	report.Phase = os.Getenv("PERF_JOIN_PHASE")
	if report.Phase == "" {
		report.Phase = "catchup"
	}
	require.Contains(t, []string{"catchup", "settled"}, report.Phase)
	report.IngestMode = os.Getenv("PERF_JOIN_INGEST")
	if report.IngestMode == "" {
		report.IngestMode = "hot"
	}
	require.Contains(t, []string{"hot", "common_flush"}, report.IngestMode)
	report.ChunkRows = 100
	report.InputRowsPerSecond = 200
	report.FlushWindowSeconds = 0.5
	waves, interval, queriesPerWave := seconds*2, 500*time.Millisecond, 3
	if report.IngestMode == "common_flush" {
		report.ChunkRows, err = strconv.Atoi(os.Getenv("PERF_JOIN_WRITE_CHUNK"))
		require.NoError(t, err)
		require.Contains(t, []int{100, 1000}, report.ChunkRows)
		require.Zero(t, seconds%5)
		require.LessOrEqual(t, uint64(seconds*200), n)
		report.BatchRows = 1000
		report.WriteRate = 0.2
		report.FlushWindowSeconds = 5
		waves = seconds / 5
		interval = 5 * time.Second
		// Public ByIDs chunks these short IDs into two bounded 500-ID reads.
		queriesPerWave = 2*(1000/report.ChunkRows) + 2
		if report.ChunkRows == 1000 {
			queriesPerWave++ // UpsertEnrichment bounds native batches to 500 rows.
		}
		report.MutationScope = "same distinct observations at 200 rows/s and same five-second collection window; compare 100/1000-row repository calls (native enrichment batches capped at 500), then verify the whole window; exact source times at schema precision (findings seconds, enrichment milliseconds); no cross-table atomicity claim"
	}
	defer func() {
		report.Passed = !t.Failed()
		data, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_QUERY_DIR"), "concurrent-joins.json"), append(data, '\n'), 0o600))
	}()
	repo := finding.NewCHRepo(app)
	assets := asset.NewCHRepo(app)
	wantSummary, wantClusters := largeJoinOracle(n, stamp, "")
	report.PartsBefore, err = joinParts(ctx, admin)
	require.NoError(t, err)
	for _, table := range []string{"assets", "graph_edges", "findings", "finding_enrichment"} {
		require.NoError(t, admin.Exec(ctx, "SYSTEM START MERGES "+table))
	}
	settleStart := time.Now()
	if report.Phase == "settled" {
		report.PartsAtStart, err = settleJoinParts(ctx, admin)
	} else {
		report.PartsAtStart, err = joinParts(ctx, admin)
	}
	report.SettleSeconds = time.Since(settleStart).Seconds()
	require.NoError(t, err)
	workCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second+2*time.Minute)
	defer cancel()
	group, groupCtx := errgroup.WithContext(workCtx)
	arrivals := make(chan joinOperation, 16)
	var mu sync.Mutex
	report.Started = time.Now().UTC().Truncate(time.Millisecond)
	start := report.Started
	prefix := "join-mixed-" + variant + "-"
	record := func(op joinOperation, e error) {
		op.Finished = time.Now().UTC()
		op.Verified = e == nil
		if e != nil {
			op.Error = e.Error()
		}
		mu.Lock()
		report.Operations = append(report.Operations, op)
		mu.Unlock()
	}
	tag := func(ctx context.Context, kind string) context.Context {
		return app.WithQuerySettings(ctx, map[string]any{"log_comment": prefix + kind, "log_queries": 1, "log_queries_probability": 1, "log_query_settings": 1})
	}
	joinTask(group, groupCtx, func() error {
		defer close(arrivals)
		for i := 0; i < seconds*rate; i++ {
			at := start.Add(time.Duration(i) * time.Second / time.Duration(rate))
			if e := joinArrival(groupCtx, at); e != nil {
				return e
			}
			kind := "summary"
			if i%2 != 0 {
				kind = "clusters"
			}
			select {
			case arrivals <- joinOperation{Kind: kind, Scheduled: at}:
			case <-groupCtx.Done():
				return groupCtx.Err()
			}
		}
		return nil
	})
	for worker := 0; worker < report.Workers; worker++ {
		joinTask(group, groupCtx, func() error {
			for op := range arrivals {
				op.Started = time.Now().UTC()
				callCtx, callCancel := context.WithTimeout(tag(groupCtx, op.Kind), 10*time.Second)
				if variant == "candidate" && len(settings) > 0 {
					callCtx = app.WithQuerySettings(callCtx, settings)
				}
				var e error
				if op.Kind == "summary" {
					var got finding.Summary
					if variant == "candidate" && experiment == "latest_rows" {
						got, e = readJoinSummaryCandidate(callCtx, app, "", experiment)
					} else {
						got, e = readJoinSummaryCandidate(callCtx, app, "", "baseline_rows")
					}
					if e == nil && !reflect.DeepEqual(got, wantSummary) {
						e = fmt.Errorf("summary output mismatch")
					}
				} else {
					var got []finding.Cluster
					var total int
					if variant == "candidate" && experiment == "latest_rows" {
						got, total, e = readJoinClustersCandidate(callCtx, app, "", experiment)
					} else {
						got, total, e = readJoinClustersCandidate(callCtx, app, "", "baseline_rows")
					}
					sort.Slice(got, func(i, j int) bool { return got[i].CheckID < got[j].CheckID })
					for i := range got {
						got[i].LastDetected = got[i].LastDetected.UTC()
					}
					if e == nil && (total != len(wantClusters) || !reflect.DeepEqual(got, wantClusters)) {
						e = fmt.Errorf("cluster output mismatch")
					}
				}
				callCancel()
				record(op, e)
			}
			return nil
		})
	}
	joinTask(group, groupCtx, func() error {
		for wave := 0; wave < waves; wave++ {
			at := start.Add(time.Duration(wave) * interval)
			if report.IngestMode == "common_flush" {
				at = at.Add(interval)
			}
			if e := joinArrival(groupCtx, at); e != nil {
				return e
			}
			op := joinOperation{Kind: "ingest", Scheduled: at, Started: time.Now().UTC()}
			findings, enrichments := joinWriteBatch(wave, stamp)
			if report.IngestMode == "common_flush" {
				findings, enrichments = joinObservationWindow(wave, stamp, start)
				oldest := findings[0].LastObservedAt
				op.OldestObservation = &oldest
			}
			callCtx := tag(groupCtx, "ingest")
			e := writeJoinChunks(callCtx, repo, findings, enrichments, report.ChunkRows)
			if e == nil {
				ids := make([]string, len(findings))
				for i, f := range findings {
					ids[i] = f.ID
				}
				var got []finding.Finding
				got, e = repo.ByIDs(callCtx, ids)
				if e == nil {
					byID := map[string]finding.Finding{}
					for _, f := range got {
						byID[f.ID] = f
					}
					if len(byID) != len(findings) {
						e = fmt.Errorf("ingest readback count %d", len(byID))
					}
					for _, f := range findings {
						if byID[f.ID].Description != f.Description {
							e = fmt.Errorf("finding readback mismatch %s", f.ID)
						}
						if report.IngestMode == "common_flush" && !byID[f.ID].LastObservedAt.Equal(f.LastObservedAt) {
							e = fmt.Errorf("finding source time mismatch %s", f.ID)
						}
					}
					for _, en := range enrichments {
						if byID[en.ID].MustFixReason != en.MustFixReason {
							e = fmt.Errorf("enrichment readback mismatch %s", en.ID)
						}
						if report.IngestMode == "common_flush" && !byID[en.ID].EnrichedAt.Equal(en.EnrichedAt) {
							e = fmt.Errorf("enrichment source time mismatch %s", en.ID)
						}
					}
				}
			}
			record(op, e)
		}
		return nil
	})
	joinTask(group, groupCtx, func() error {
		for i := 0; i < seconds; i += 5 {
			at := start.Add(time.Duration(i) * time.Second)
			if e := joinArrival(groupCtx, at); e != nil {
				return e
			}
			op := joinOperation{Kind: "package-risk", Scheduled: at, Started: time.Now().UTC()}
			got, e := assets.PackageRiskByRunner(tag(groupCtx, "package-risk"))
			if e == nil {
				if uint64(len(got)) != p.Images {
					e = fmt.Errorf("runner count mismatch")
				}
				for j := uint64(0); j < p.Images; j++ {
					if got[fmt.Sprintf("image-%d", j)] != 80 {
						e = fmt.Errorf("runner risk mismatch")
					}
				}
			}
			record(op, e)
		}
		return nil
	})
	err = group.Wait()
	report.Finished = time.Now().UTC()
	require.NoError(t, err)
	sort.Slice(report.Operations, func(i, j int) bool { return report.Operations[i].Scheduled.Before(report.Operations[j].Scheduled) })
	drainStart := time.Now()
	drainCtx, drainCancel := context.WithTimeout(ctx, 10*time.Second)
	err = stopJoinRequests(drainCtx, admin, prefix, true)
	drainCancel()
	report.TerminalDrain = time.Since(drainStart).Seconds()
	report.ServerDrainedAt = time.Now().UTC()
	require.NoError(t, err)
	require.NoError(t, admin.Exec(ctx, "SYSTEM FLUSH LOGS"))
	require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var q perfassurance.QueryCost
			if e := rows.Scan(&q.SQL, &q.Milliseconds, &q.ReadRows, &q.ReadBytes, &q.Memory, &q.Exception, &q.MaxThreads, &q.MaxBlockSize, &q.ProfileEvents); e != nil {
				return e
			}
			report.QueryCosts = append(report.QueryCosts, q)
		}
		return rows.Err()
	}, strings.Replace(largeJoinCosts, "log_comment=?", "startsWith(log_comment,?)", 1), prefix))
	var latencies []float64
	for _, op := range report.Operations {
		if op.Error != "" {
			t.Errorf("%s: %s", op.Kind, op.Error)
		}
		if op.Kind == "summary" || op.Kind == "clusters" {
			latencies = append(latencies, float64(op.Finished.Sub(op.Scheduled))/float64(time.Millisecond))
		}
	}
	require.Len(t, latencies, seconds*rate)
	sort.Float64s(latencies)
	report.ReadP95MS = latencies[(95*len(latencies)+99)/100-1]
	report.ReadP99MS = latencies[(99*len(latencies)+99)/100-1]
	for _, q := range report.QueryCosts {
		if q.Memory > 512<<20 {
			report.BudgetFailures = append(report.BudgetFailures, "query memory exceeds 512 MiB")
		}
		if q.Exception != "" {
			report.BudgetFailures = append(report.BudgetFailures, q.Exception)
		}
	}
	if report.ReadP95MS > 1500 || report.ReadP99MS > 3000 {
		report.BudgetFailures = append(report.BudgetFailures, "target interactive latency exceeded (1500 ms p95 / 3000 ms p99)")
	}
	require.Len(t, report.Operations, seconds*rate+waves+(seconds+4)/5)
	if len(report.BudgetFailures) == 0 {
		require.Len(t, report.QueryCosts, seconds*rate+queriesPerWave*waves+(seconds+4)/5, "all reads, native chunks and exact write readback must be measured")
	}
	require.Empty(t, report.BudgetFailures)
}
