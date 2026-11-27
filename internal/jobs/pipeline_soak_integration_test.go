//go:build integration

package jobs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/testutil/benchconfig"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

func TestPipelineSoak(t *testing.T) {
	if os.Getenv("PERF_ISOLATED") != "1" || os.Getenv("PERF_SOAK_SECONDS") == "" {
		t.Skip("set PERF_SOAK_SECONDS with scripts/benchmark-connectors.sh")
	}
	seconds, err := strconv.Atoi(os.Getenv("PERF_SOAK_SECONDS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, seconds, 1)
	require.LessOrEqual(t, seconds, 600)
	require.NotEmpty(t, os.Getenv("PERF_CONNECTOR_DIR"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	pool, err := db.NewPool(ctx, os.Getenv("PERF_POSTGRES_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	chConcurrency := benchconfig.SoakCHConcurrency(t)
	ch, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), chConcurrency)
	require.NoError(t, err)
	defer ch.Close()
	// Earlier insert-only measurements intentionally leave jobs unconsumed.
	// Reset only before this run; no backlog is removed during the soak.
	_, err = pool.Exec(ctx, "DELETE FROM river_job")
	require.NoError(t, err)
	r := &soakReport{Version: 1, FixtureVersion: 4, Commit: os.Getenv("PERF_COMMIT"), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		GoVersion: runtime.Version(), GoMaxProcs: runtime.GOMAXPROCS(0), MinimumSeconds: seconds,
		CHConcurrency: chConcurrency,
		MaxPending:    map[string]int{}, Deferred: map[string]int{}}
	t.Cleanup(func() { writeSoakReport(t, r) })
	cipher, err := connector.NewCipher(testKey(t))
	require.NoError(t, err)
	conns := connector.NewService(connector.NewPGRepo(pool), cipher)
	inv := asset.NewService(asset.NewCHRepo(ch))
	cache := enrichcache.NewService(enrichcache.NewPGRepo(pool))
	findings := finding.NewService(finding.NewCHRepo(ch)).WithResolveObserver(cache)
	signals := soakSignals{findings}
	graph, err := graphstore.Open("", 256, 2, 2, "")
	require.NoError(t, err)
	defer graph.Close()
	graph.SetLoadThreads(2)
	require.NoError(t, graph.SyncFromSources(ctx, 0, inv, inv, signals))
	require.NoError(t, soakGraphRead(ctx, graph))
	registry := collect.NewRegistry()
	producers := map[string]*soakCollector{}
	var connectorIDs []string
	for _, kind := range []string{"aws", "gcp", "azure", "kubernetes", "github", "okta", "google_workspace", "demo"} {
		pattern := fmt.Sprintf("%s-%d-fixture.json", kind, benchconfig.MaxSize(t))
		if kind == "demo" {
			pattern = "demo-*-fixture.json"
		}
		files, err := filepath.Glob(filepath.Join(os.Getenv("PERF_CONNECTOR_DIR"), pattern))
		require.NoError(t, err)
		require.Len(t, files, 1)
		data, err := os.ReadFile(files[0])
		require.NoError(t, err)
		p := &soakCollector{data: data, entered: make(chan struct{})}
		producers[kind] = p
		registry.Register(connector.Type(kind), p)
		id := uuid.NewString()
		enc, err := cipher.EncryptWithAAD([]byte(`{}`), []byte("connector:"+id))
		require.NoError(t, err)
		_, err = pool.Exec(ctx, "INSERT INTO connectors(id,type,name,config_enc) VALUES($1,$2,$3,$4)", id, kind, "soak-"+kind, enc)
		require.NoError(t, err)
		connectorIDs = append(connectorIDs, id)
	}
	producers["aws"].failOnce.Store(true)
	correlation := correlate.NewService(correlate.NewCHRepo(ch), inv, []correlate.Rule{
		correlate.DNSPointsTo{}, correlate.IAMCanAssume{}, correlate.GCPImpersonation{}, correlate.EC2InstanceProfile{},
		correlate.ExecutesAs{}, correlate.DeploysTo{}, correlate.K8sManifestOwnership{}, correlate.TFOwnership{},
		correlate.DeclaredIdentityOwnership{}, correlate.ImageOwnership{}, correlate.SecurityGroupAllows{},
		correlate.SharedSecurityGroup{}, correlate.GCPFirewallApplies{}, correlate.GCPFirewallReachability{},
		correlate.K8sServiceTargets{}, correlate.InternetReachability{}, correlate.FederationTrust{},
		correlate.GCPWorkloadIdentity{}, correlate.IRSATrust{}, correlate.K8sPodServiceAccount{},
		correlate.IAMEffectivePermissions{}, correlate.SecretAccess{}, correlate.DataClassification{}, correlate.HumanIdentityFederation{},
	})
	// Local deterministic sources still perform real graph traversals and writes.
	// External feeds, LLM decisions, registry pulls and disk scans are not consumed.
	blast := &soakBlast{assets: inv, graph: graph}
	enrichment := enrich.NewService(findings, enrich.NewSignalCHRepo(ch), []enrich.Source{
		enrich.BaseSeverity{}, enrich.KEV{}, enrich.ExposureType{}, enrich.BlastRadius{Counter: blast, Provider: blast},
	})
	observed := &soakEnricher{service: enrichment, values: map[string]soakEnrichmentValue{}}
	syncGraph := LadybugSyncFn(func(ctx context.Context) error { return graph.SyncFromSources(ctx, 0, inv, inv, signals) })
	newClient := func() *river.Client[pgx.Tx] {
		workers := river.NewWorkers()
		river.AddWorker(workers, &SyncWorker{connectors: conns, registry: registry, assets: inv, findings: findings, checks: checks.Default()})
		river.AddWorker(workers, &EnrichWorker{enrich: observed, findings: newEnrichFindingFetcher(findings), cache: cache})
		river.AddWorker(workers, &EnrichSweepWorker{findings: findings})
		river.AddWorker(workers, &CorrelateWorker{correlate: correlation, ladybug: syncGraph})
		river.AddWorker(workers, &LadybugRebuildWorker{ladybug: syncGraph})
		addRescueOnlyWorkers(workers)
		queues := map[string]river.QueueConfig{}
		for _, name := range soakQueues {
			queues[name] = queueConfig(name)
		}
		client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Queues: queues, Workers: workers})
		require.NoError(t, err)
		return client
	}
	client := newClient()
	plainCtx := ctx
	comment := "pipeline-soak-" + uuid.NewString()
	ctx = ch.WithQuerySettings(ctx, map[string]any{"log_comment": comment, "log_queries": 1, "log_queries_probability": 1})
	riverCtx, cancelRiver := soakRiverContext(ctx)
	defer cancelRiver()
	require.NoError(t, client.Start(riverCtx))
	defer func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		require.NoError(t, client.StopAndCancel(stopCtx))
	}()
	reads := &soakReadSamples{times: map[string][]float64{}, errors: map[string]int{}}
	readCtx, stopReads := context.WithCancel(ctx)
	var readers errgroup.Group
	for _, kind := range []string{"inventory", "findings", "graph"} {
		readers.Go(func() (err error) {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("%s read panic: %v", kind, p)
				}
			}()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-readCtx.Done():
					return nil
				case <-ticker.C:
				}
				start := time.Now()
				qctx, done := context.WithTimeout(readCtx, 10*time.Second)
				var readErr error
				switch kind {
				case "inventory":
					var rows []asset.Asset
					rows, readErr = inv.ByIDs(qctx, []string{"pod-0"})
					if readErr == nil && len(rows) != 1 {
						readErr = fmt.Errorf("stable inventory row disappeared")
					}
				case "findings":
					_, readErr = findings.List(qctx, finding.Filter{Limit: 25})
				case "graph":
					readErr = soakGraphRead(qctx, graph)
				}
				done()
				if readCtx.Err() != nil {
					return nil
				}
				reads.add(kind, start, readErr)
			}
		})
	}
	defer func() {
		stopReads()
		require.NoError(t, readers.Wait())
		r.Reads = reads.report()
		r.ReadError = reads.firstError
	}()
	start := time.Now()
	for revision := 0; revision < 3 || time.Since(start) < time.Duration(seconds)*time.Second; revision++ {
		waveStart := time.Now()
		for _, producer := range producers {
			producer.revision.Store(int64(revision))
		}
		restarting := revision == 1
		if restarting {
			producers["azure"].blockOnce.Store(true)
		}
		for _, id := range connectorIDs {
			_, err = client.Insert(ctx, SyncConnectorArgs{ConnectorID: id}, nil)
			require.NoError(t, err)
		}
		if restarting {
			select {
			case <-producers["azure"].entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			stopCtx, stop := context.WithTimeout(ctx, 30*time.Second)
			err = client.StopAndCancel(stopCtx)
			stop()
			require.NoError(t, err)
			var pending int
			require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE kind='sync_connector' AND state!='completed'").Scan(&pending))
			require.Positive(t, pending, "cancelled in-flight work must remain durable")
			client = newClient()
			require.NoError(t, client.Start(riverCtx))
		}
		waitSoakQueues(t, ctx, pool, []string{queueSync}, r.MaxPending)
		// Exercise the real coalescer after the writes, then the full sweep that
		// covers batches above its targeted-correlation limit.
		partialCorrelateCoalescer.flush(ctx, client, client)
		_, err = client.Insert(ctx, CorrelateArgs{}, fullCorrelateOpts())
		require.NoError(t, err)
		completed := waitSoakQueues(t, ctx, pool, soakQueues, r.MaxPending)
		// The production admission path must schedule and drain deferred work.
		// Never inject extra sweeps here: that would hide a slow production
		// scheduling cadence behind a fast worker-throughput measurement.
		counts, err := findings.UnenrichedCounts(ctx)
		require.NoError(t, err)
		for _, count := range counts {
			require.Zero(t, count.N, "production backfill left unmeasured findings: %s", count.Severity)
		}

		wave := soakWave{Revision: revision, Seconds: time.Since(waveStart).Seconds(), CompletedJobs: completed, Restarted: restarting}
		wave.HeapBytes, wave.PeakRSSBytes = soakMemory()
		// Query persisted output, never substitute queue completion for enrichment.
		require.NoError(t, pool.QueryRow(ctx, "SELECT count(DISTINCT args->>'finding_id') FROM river_job WHERE kind='enrich' AND state='completed'").Scan(&wave.EnrichedFindings))
		require.Positive(t, wave.EnrichedFindings)
		r.Waves = append(r.Waves, wave)
		t.Logf("soak revision=%d elapsed=%.3fs completed=%d enriched=%d heap=%d peak_rss=%d restart=%v", revision, wave.Seconds, completed, wave.EnrichedFindings, wave.HeapBytes, wave.PeakRSSBytes, restarting)
	}
	r.Seconds = time.Since(start).Seconds()
	require.NoError(t, pool.QueryRow(ctx, `SELECT COALESCE(sum(attempt+COALESCE((metadata->>'snoozes')::int,0)),0) FROM river_job WHERE kind='enrich_sweep' AND args->>'backfill_only'='true'`).Scan(&r.BackfillTicks))
	stopReads()
	require.NoError(t, readers.Wait())
	r.BlastFailures = blast.failures.Load()
	require.Zero(t, r.BlastFailures, "a faster fallback after failed blast queries is not a throughput improvement")
	require.NoError(t, ch.Exec(plainCtx, "SYSTEM FLUSH LOGS"))
	require.NoError(t, ch.Select(plainCtx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing soak query telemetry")
		}
		return rows.Scan(&r.Queries, &r.ReadRows, &r.ReadBytes, &r.MaxQueryMemory)
	}, `SELECT count(),sum(read_rows),sum(read_bytes),max(memory_usage) FROM system.query_log WHERE type='QueryFinish' AND log_comment=?`, comment))
	require.Positive(t, r.Queries)
	require.NoError(t, ch.Select(plainCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var cost soakQueryCost
			if err := rows.Scan(&cost.Query, &cost.Calls, &cost.Milliseconds, &cost.ReadRows, &cost.ReadBytes, &cost.MaxMemory); err != nil {
				return err
			}
			r.QueryCosts = append(r.QueryCosts, cost)
		}
		return rows.Err()
	}, `SELECT any(normalizeQuery(query)),count(),sum(query_duration_ms),sum(read_rows),sum(read_bytes),max(memory_usage)
		FROM system.query_log WHERE type='QueryFinish' AND log_comment=?
		GROUP BY normalized_query_hash ORDER BY sum(query_duration_ms) DESC LIMIT 25`, comment))
	r.Reads = reads.report()
	for name, latency := range r.Reads {
		require.Positive(t, latency.Count, name)
		require.Zero(t, latency.Errors, "%s: %s", name, reads.firstError)
	}
	require.Len(t, r.Reads, 3)
	assets, edges := soakExpected(t, producers)
	verifySyncReadback(t, ctx, inv, assets, edges)
	r.VerifiedAssets, r.VerifiedEdges = len(assets), len(edges)
	verifySoakEnrichment(t, ctx, pool, ch, findings, observed, r)
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE attempt>1 AND state='completed'").Scan(&r.Retried))
	require.GreaterOrEqual(t, r.Retried, 2, "transient failure and interrupted work must both recover")
	rows, err := pool.Query(ctx, "SELECT kind,count(*) FROM river_job WHERE state!='completed' GROUP BY kind")
	require.NoError(t, err)
	for rows.Next() {
		var kind string
		var count int
		require.NoError(t, rows.Scan(&kind, &count))
		r.Deferred[kind] = count
	}
	require.NoError(t, rows.Err())
	rows.Close()
	// A new native engine rebuilds from the persisted stores, without a snapshot.
	fresh, err := graphstore.Open("", 256, 2, 2, "")
	require.NoError(t, err)
	defer fresh.Close()
	fresh.SetLoadThreads(2)
	require.NoError(t, fresh.SyncFromSources(ctx, 0, inv, inv, signals))
	require.NoError(t, soakGraphRead(ctx, fresh))
	require.Equal(t, graph.NodeCount(), fresh.NodeCount())
	r.GraphEdges, r.UnloadedEdges, r.MissingEdges = fresh.EdgeLoadStats()
	r.GraphRebuilt, r.Passed = true, true
}

func verifySoakEnrichment(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ch *db.CH, findings *finding.Service, observed *soakEnricher, report *soakReport) {
	t.Helper()
	observed.mu.Lock()
	defer observed.mu.Unlock()
	for _, value := range observed.values {
		if value.unmeasured > 0 {
			report.Unmeasured++
		}
	}
	require.Zero(t, report.Unmeasured, "completed runs must not hide degraded enrichment sources")
	rows, err := pool.Query(ctx, "SELECT DISTINCT args->>'finding_id' FROM river_job WHERE kind='enrich' AND state='completed'")
	require.NoError(t, err)
	var ids []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.NotEmpty(t, ids)
	for start := 0; start < len(ids); start += 500 {
		chunk := ids[start:min(start+500, len(ids))]
		got, err := findings.ByIDs(ctx, chunk)
		require.NoError(t, err)
		require.Len(t, got, len(chunk))
		for _, f := range got {
			require.True(t, f.Resolved() || (f.Score > 0 && !f.EnrichedAt.IsZero()), "completed job lacks persisted enrichment: %s", f.ID)
			if expected, ok := observed.values[f.ID]; ok {
				require.Equal(t, expected.score, f.Score, f.ID)
				require.Equal(t, expected.band, f.ScoreBand, f.ID)
			}
		}
		keys, args := dbutil.CHIn(chunk)
		require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
			for rows.Next() {
				var id, factors string
				if err := rows.Scan(&id, &factors); err != nil {
					return err
				}
				if expected, ok := observed.values[id]; ok {
					require.Equal(t, expected.factors, sha256.Sum256([]byte(factors)), id)
					report.VerifiedScores++
				}
			}
			return rows.Err()
		}, fmt.Sprintf(`SELECT id,argMax(factors,synced_at) FROM signals WHERE id IN (%s) GROUP BY id`, keys), args...))
	}
	require.Equal(t, len(observed.values), report.VerifiedScores, "every observed enrichment must be stored with its factors")
}
