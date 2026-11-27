//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
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
	"github.com/vulngraph/vulngraph/internal/httpsrv"
	"github.com/vulngraph/vulngraph/internal/memlimit"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

var envelopeQueues = []string{queueSync, queueEnrich, queueCorrelate, queueGraph, queueDangling}

type envelopeReport struct {
	Version           int                    `json:"version"`
	Source            string                 `json:"source"`
	Platform          string                 `json:"platform"`
	Connectors        int                    `json:"configured_connectors"`
	Resources         int                    `json:"fixture_assets_excluding_stable_sentinel"`
	CollectHoldMillis int                    `json:"modeled_whole_result_hold_milliseconds"`
	Sizes             []int                  `json:"connector_asset_counts"`
	Scopes            []envelopeScope        `json:"connector_scopes"`
	Queues            map[string]int         `json:"queue_worker_limits"`
	Peak              map[string]int         `json:"observed_active_peaks"`
	Memory            memlimit.Budget        `json:"go_memory_budget"`
	Waves             []map[string]any       `json:"waves"`
	Reads             map[string]soakLatency `json:"reads"`
	Failures          []string               `json:"failures"`
	Passed            bool                   `json:"passed"`
	Scope             []string               `json:"scope_and_gaps"`
}

func TestConnectorMemoryEnvelope(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("use scripts/benchmark-connector-envelope.sh")
	}
	require.Equal(t, "linux", runtime.GOOS, "measure worker cgroup and native RSS together")
	n, err := strconv.Atoi(os.Getenv("PERF_ENVELOPE_CONNECTORS"))
	require.NoError(t, err)
	resources, err := strconv.Atoi(os.Getenv("PERF_ENVELOPE_ASSETS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 2)
	scopes, err := envelopeScopes(os.Getenv("PERF_ENVELOPE_SCOPE_COUNTS"), n)
	require.NoError(t, err)
	require.Len(t, scopes, n)
	require.GreaterOrEqual(t, resources, n*20)
	dir := os.Getenv("PERF_ENVELOPE_DIR")
	require.NotEmpty(t, dir)
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Minute)
	defer cancel()
	traceFile, err := os.Create(filepath.Join(dir, "worker-timeline.jsonl"))
	require.NoError(t, err)
	trace := &envelopeTrace{file: traceFile, active: map[string]int{}, peak: map[string]int{}}
	defer traceFile.Close()
	r := &envelopeReport{Version: 7, Source: os.Getenv("PERF_COMMIT"), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Connectors: n, Resources: resources, Scopes: scopes, Sizes: envelopeScopeSizes(scopes, resources), Queues: map[string]int{},
		Scope: []string{"one worker replica; production queue concurrency", "provider round-robin admission; version4 grouped providers sequentially", "production five-second coalescer; prior version5 flushed only after sync drain", "explicit wave controller and final reconciliation; not production periodic scheduling latency", "synthetic per-provider Collect Result allocation; no SDK/API cost or quota proof",
			"24 correlation rules; default CSPM checks; four local enrichment sources; native graph",
			"HTTP domain handlers over loopback; no authentication middleware or browser",
			"250ms worker samples include benchmark observer; no forced GC; native allocator bytes not separately available",
			"atomic graph pointer swap does not prove a committed cross-table ClickHouse generation",
			"proof-aware fallback deletion behavior has a separate adversarial replay; raw delayed correlation rows are counted explicitly",
			"no external feeds, scans, LLM, additional replicas or 24-hour soak"}}
	t.Cleanup(func() {
		r.Passed = r.Passed && !t.Failed()
		trace.mu.Lock()
		r.Peak = trace.peak
		traceErr := trace.err
		trace.mu.Unlock()
		require.NoError(t, traceErr)
		b, e := json.MarshalIndent(r, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "envelope.json"), b, 0600))
	})
	sampleCtx, stopSamples := context.WithCancel(ctx)
	var samples errgroup.Group
	samples.Go(func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("sample panic: %v", p)
			}
		}()
		return trace.sample(sampleCtx)
	})
	defer func() { stopSamples(); require.NoError(t, samples.Wait()) }()
	r.Memory = memlimit.Apply(os.Getenv, 1280)
	pool, err := db.NewPool(ctx, os.Getenv("PERF_POSTGRES_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	ch, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 8)
	require.NoError(t, err)
	defer ch.Close()
	cipher, err := connector.NewCipher(testKey(t))
	require.NoError(t, err)
	conns := connector.NewService(connector.NewPGRepo(pool), cipher)
	inv := asset.NewService(asset.NewCHRepo(ch)).WithDeletionProofs(conns)
	cache := enrichcache.NewService(enrichcache.NewPGRepo(pool))
	findings := finding.NewService(finding.NewCHRepo(ch)).WithResolveObserver(cache)
	stable := asset.Asset{ID: "envelope-stable", Name: "stable", Type: "container_image", Provider: asset.ProviderAWS, LastSeen: time.Now()}
	require.NoError(t, inv.Ingest(ctx, []asset.Asset{stable}, nil))
	graph, err := graphstore.Open("", 1280, 2, 2, "")
	require.NoError(t, err)
	defer graph.Close()
	graph.SetLoadThreads(2)
	graph.WithSyncMetrics(trace)
	signals := soakSignals{findings}
	syncGraph := LadybugSyncFn(func(ctx context.Context) error {
		finish := trace.begin("graph", "")
		err := graph.SyncFromSources(ctx, 0, inv, inv, signals)
		finish(err)
		return err
	})
	require.NoError(t, syncGraph.Sync(ctx))
	nativeBaseline := envelopeNativeCount(t, ctx, graph, "MATCH (n) RETURN count(n) AS n")
	hold, err := strconv.Atoi(os.Getenv("PERF_ENVELOPE_COLLECT_HOLD_MS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, hold, 0)
	require.LessOrEqual(t, hold, 5000, "modeled collection hold is bounded")
	r.CollectHoldMillis = hold
	producer := &envelopeCollector{trace: trace, hold: time.Duration(hold) * time.Millisecond, scopes: scopes}
	registry := collect.NewRegistry()
	for _, kind := range []connector.Type{connector.TypeAWS, connector.TypeGCP, connector.TypeKubernetes, connector.TypeGitHub} {
		registry.Register(kind, producer)
	}
	ids := make([]string, n)
	for i, size := range r.Sizes {
		ids[i] = uuid.NewString()
		cfg, e := json.Marshal(map[string]string{"index": strconv.Itoa(i), "resources": strconv.Itoa(size)})
		require.NoError(t, e)
		enc, e := cipher.EncryptWithAAD(cfg, []byte("connector:"+ids[i]))
		require.NoError(t, e)
		_, e = pool.Exec(ctx, "INSERT INTO connectors(id,type,name,config_enc) VALUES($1,$2,$3,$4)", ids[i], scopes[i].Kind, fmt.Sprintf("envelope-%d", i), enc)
		require.NoError(t, e)
	}
	correlation := &envelopeCorrelator{Service: correlate.NewService(correlate.NewCHRepo(ch), inv, []correlate.Rule{
		correlate.DNSPointsTo{}, correlate.IAMCanAssume{}, correlate.GCPImpersonation{}, correlate.EC2InstanceProfile{}, correlate.ExecutesAs{}, correlate.DeploysTo{},
		correlate.K8sManifestOwnership{}, correlate.TFOwnership{}, correlate.DeclaredIdentityOwnership{}, correlate.ImageOwnership{}, correlate.SecurityGroupAllows{},
		correlate.SharedSecurityGroup{}, correlate.GCPFirewallApplies{}, correlate.GCPFirewallReachability{}, correlate.K8sServiceTargets{}, correlate.InternetReachability{},
		correlate.FederationTrust{}, correlate.GCPWorkloadIdentity{}, correlate.IRSATrust{}, correlate.K8sPodServiceAccount{}, correlate.IAMEffectivePermissions{},
		correlate.SecretAccess{}, correlate.DataClassification{}, correlate.HumanIdentityFederation{}}).WithViewMetrics(trace), trace: trace}
	blast := &soakBlast{assets: inv, graph: graph}
	observed := &soakEnricher{service: enrich.NewService(findings, enrich.NewSignalCHRepo(ch), []enrich.Source{
		enrich.BaseSeverity{}, enrich.KEV{}, enrich.ExposureType{}, enrich.BlastRadius{Counter: blast, Provider: blast}}), values: map[string]soakEnrichmentValue{}}
	workers := river.NewWorkers()
	river.AddWorker(workers, &envelopeSyncWorker{SyncWorker: &SyncWorker{connectors: conns, registry: registry, assets: inv, findings: findings, checks: checks.Default()}, trace: trace})
	river.AddWorker(workers, &EnrichWorker{enrich: &envelopeEnricher{soakEnricher: observed, trace: trace}, findings: newEnrichFindingFetcher(findings), cache: cache})
	river.AddWorker(workers, &EnrichSweepWorker{findings: findings})
	river.AddWorker(workers, &CorrelateWorker{correlate: correlation, assets: inv, findings: findings, enrichCache: cache, ladybug: syncGraph, findingsList: findings, derivedAssets: inv})
	river.AddWorker(workers, &LadybugRebuildWorker{ladybug: syncGraph})
	river.AddWorker(workers, &InventoryRetirementWorker{proofs: conns, assets: inv, findings: findings})
	river.AddWorker(workers, &DanglingSweepWorker{findings: findings, assets: inv})
	addRescueOnlyWorkers(workers)
	queues := map[string]river.QueueConfig{}
	for _, name := range envelopeQueues {
		queues[name] = queueConfig(name)
		r.Queues[name] = queues[name].MaxWorkers
	}
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Queues: queues, Workers: workers})
	require.NoError(t, err)
	riverCtx, stopRiver := soakRiverContext(ctx)
	defer stopRiver()
	require.NoError(t, client.Start(riverCtx))
	coalesceStop := make(chan struct{})
	var coalescers errgroup.Group
	coalescers.Go(func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("coalescer panic: %v", p)
			}
		}()
		RunCorrelateCoalescer(ctx, coalesceStop, client)
		return nil
	})
	defer func() {
		stopCtx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		require.NoError(t, client.StopAndCancel(stopCtx))
		close(coalesceStop)
		require.NoError(t, coalescers.Wait())
	}()
	stopReads := envelopeReads(t, ctx, inv, findings, graph, trace, r)
	defer stopReads()
	for wave, name := range []string{"initial", "unchanged", "changed_one_percent", "partial_omission", "confirmed_deletion", "reappearance"} {
		if wave == 2 {
			producer.revision.Store(1)
		}
		if wave == 3 {
			producer.mode.Store(1)
		}
		if wave == 4 {
			producer.mode.Store(2)
		}
		if wave == 5 {
			producer.mode.Store(0)
		}
		start := time.Now()
		trace.write(map[string]any{"event": "wave_start", "wave": name})
		for _, i := range envelopeSchedule(scopes) {
			_, err = client.Insert(ctx, SyncConnectorArgs{ConnectorID: ids[i]}, nil)
			require.NoError(t, err)
		}
		// Start broad work after a quarter of scopes committed, so it reads a
		// populated inventory while other syncs remain active. On changed waves
		// wait for actual enrichment, not an artificial enrichment allocation.
		envelopeWaitOverlap(t, ctx, pool, trace, start, n, wave == 0 || wave == 2)
		_, err = client.Insert(ctx, CorrelateArgs{}, fullCorrelateOpts())
		require.NoError(t, err)
		_, err = client.Insert(ctx, LadybugRebuildArgs{}, nil)
		require.NoError(t, err)
		failed := envelopeDrain(t, ctx, pool, ch, trace, r)
		partialCorrelateCoalescer.flush(ctx, client, client)
		failed += envelopeDrain(t, ctx, pool, ch, trace, r)
		if wave == 4 {
			_, err = client.Insert(ctx, InventoryRetirementArgs{}, nil)
			require.NoError(t, err)
			failed += envelopeDrain(t, ctx, pool, ch, trace, r)
		}
		_, err = client.Insert(ctx, CorrelateArgs{}, fullCorrelateOpts())
		require.NoError(t, err)
		failed += envelopeDrain(t, ctx, pool, ch, trace, r)

		if failed > 0 {
			r.Failures = append(r.Failures, fmt.Sprintf("%s: %d terminal failed jobs", name, failed))
		}
		// Final publication after concurrent writes verifies recovery/freshness;
		// its cost is retained separately from overlapping graph attempts.
		graphErr := syncGraph.Sync(ctx)
		if graphErr != nil {
			r.Failures = append(r.Failures, graphErr.Error())
		}
		r.Waves = append(r.Waves, map[string]any{"name": name, "started_at": start.UTC(), "seconds_to_drained_publication": time.Since(start).Seconds(),
			"graph_loaded_asset_count": graph.NodeCount(), "graph_path": graph.LastSyncPath(), "failed_jobs": failed})
		trace.write(map[string]any{"event": "wave_end", "wave": name})
		func() {
			finish := trace.begin("oracle", name)
			defer finish(nil)
			verifyCtx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": "envelope-output-oracle"})
			r.Waves[len(r.Waves)-1]["retained_raw_correlation_edges_to_deleted_assets"] = envelopeVerifyStream(t, verifyCtx, ch, r.Sizes, scopes, wave)
			native := envelopeVerifyNative(t, verifyCtx, graph, r.Sizes, scopes, wave, nativeBaseline)
			r.Waves[len(r.Waves)-1]["native_node_count"] = native
			envelopeVerifyFindings(t, verifyCtx, findings, r.Sizes, scopes, wave)
			var enrichment soakReport
			verifySoakEnrichment(t, verifyCtx, pool, ch, findings, observed, &enrichment)
			r.Waves[len(r.Waves)-1]["verified_enrichment_scores"] = enrichment.VerifiedScores
		}()
	}
	stopReads()
	require.Zero(t, blast.failures.Load(), "failed blast queries must not become fast unknown fallbacks")
	require.Empty(t, r.Failures)
	for kind, values := range r.Reads {
		require.Positive(t, values.Count, kind)
		require.Zero(t, values.Errors, kind)
	}
	r.Passed = true
}

func envelopeWaitOverlap(t *testing.T, ctx context.Context, pool *pgxpool.Pool, trace *envelopeTrace, after time.Time, scopes int, needEnrichment bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		var count int
		require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE kind='sync_connector' AND state='completed' AND finalized_at >= $1", after).Scan(&count))
		trace.mu.Lock()
		enriching := trace.active["enrich"]
		trace.mu.Unlock()
		if count >= max(1, scopes/4) && (!needEnrichment || enriching > 0 || count >= scopes) {
			trace.write(map[string]any{"event": "overlap_trigger", "completed_scopes": count, "configured_scopes": scopes, "active_enrich": enriching, "missed_enrichment_overlap": needEnrichment && enriching == 0})
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}

func envelopeDrain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ch *db.CH, trace *envelopeTrace, report *envelopeReport) int {
	t.Helper()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		rows, err := pool.Query(ctx, "SELECT queue,state,count(*) FROM river_job WHERE queue=ANY($1) GROUP BY queue,state", envelopeQueues)
		require.NoError(t, err)
		pending, failed := 0, 0
		counts := map[string]int{}
		for rows.Next() {
			var queue, state string
			var count int
			require.NoError(t, rows.Scan(&queue, &state, &count))
			counts[queue+"/"+state] = count
			switch state {
			case "completed":
			case "cancelled", "discarded":
				failed += count
			default:
				pending += count
			}
		}
		require.NoError(t, rows.Err())
		rows.Close()
		buffered, full, age := partialCorrelateCoalescer.buf.state()
		flushing := partialCorrelateCoalescer.flushing.Load()
		trace.write(map[string]any{"event": "queues", "counts": counts, "buffered_changed_ids": buffered, "buffered_full": full, "buffer_age_seconds": age.Seconds(), "coalescer_flushing": flushing})
		envelopeCheckCorrelationLimit(t, ctx, pool, ch, trace, report)
		if pending == 0 && buffered == 0 && !full && flushing == 0 {
			return failed
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}

func envelopeReads(t *testing.T, ctx context.Context, inv *asset.Service, findings *finding.Service, graph *graphstore.Service, trace *envelopeTrace, r *envelopeReport) func() {
	t.Helper()
	mux := http.NewServeMux()
	ah := asset.NewHandler(inv, httpsrv.AssetRiskProvider(findings))
	fh := finding.NewHandler(findings, nil)
	mux.HandleFunc("GET /api/assets", ah.List)
	mux.HandleFunc("GET /api/findings", fh.List)
	mux.HandleFunc("GET /api/findings/summary", fh.Summary)
	server := httptest.NewServer(mux)
	client := safenet.NewInternal(10 * time.Second)
	readCtx, cancel := context.WithCancel(ctx)
	reads := &soakReadSamples{times: map[string][]float64{}, errors: map[string]int{}}
	var group errgroup.Group
	for _, route := range []string{"/api/assets?limit=25", "/api/findings?limit=25", "/api/findings/summary", "graph"} {
		group.Go(func() (err error) {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("read panic: %v", p)
				}
			}()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-readCtx.Done():
					return nil
				case <-ticker.C:
				}
				start := time.Now()
				var readErr error
				if route == "graph" {
					result, e := graph.RunCypher(readCtx, "MATCH (a:Asset {id:'envelope-stable'}) RETURN a", 10, 10)
					readErr = e
					if e == nil && len(result.Nodes) != 1 {
						readErr = fmt.Errorf("stable graph node disappeared")
					}
				} else {
					req, e := http.NewRequestWithContext(readCtx, http.MethodGet, server.URL+route, nil)
					if e != nil {
						return e
					}
					response, e := client.Do(req)
					readErr = e
					if e == nil {
						_, readErr = io.Copy(io.Discard, response.Body)
						_ = response.Body.Close()
						if response.StatusCode != http.StatusOK {
							readErr = fmt.Errorf("HTTP %d", response.StatusCode)
						}
					}
				}
				if readCtx.Err() != nil {
					return nil
				}
				reads.add(route, start, readErr)
				message := ""
				if readErr != nil {
					message = readErr.Error()
				}
				trace.write(map[string]any{"event": "read", "route": route, "seconds": time.Since(start).Seconds(), "error": message})
			}
		})
	}
	return func() { cancel(); require.NoError(t, group.Wait()); server.Close(); r.Reads = reads.report() }
}
