//go:build integration

package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// Only the upstream API is substituted. The River workers, database adapters,
// scorer, correlation rules and native graph execute their production code.
type soakCollector struct {
	data      []byte
	revision  atomic.Int64
	failOnce  atomic.Bool
	blockOnce atomic.Bool
	entered   chan struct{}
}

func (c *soakCollector) Collect(ctx context.Context, _ map[string]string) (collect.Result, error) {
	if c.failOnce.Swap(false) {
		return collect.Result{}, fmt.Errorf("injected transient collection failure")
	}
	if c.blockOnce.Swap(false) {
		close(c.entered)
		<-ctx.Done()
		return collect.Result{}, ctx.Err()
	}
	var out collect.Result
	if err := json.Unmarshal(c.data, &out); err != nil {
		return out, err
	}
	revision := c.revision.Load()
	for i := 0; i < len(out.Assets); i += 100 {
		a := &out.Assets[i]
		a.Name += fmt.Sprintf("-soak-%d", revision)
		if a.Metadata == nil {
			a.Metadata = map[string]string{}
		}
		a.Metadata["soak_revision"] = fmt.Sprint(revision)
	}
	for i := 0; i < len(out.Edges); i += 100 {
		e := &out.Edges[i]
		if e.Properties == nil {
			e.Properties = map[string]string{}
		}
		e.Properties["soak_revision"] = fmt.Sprint(revision)
	}
	return out, nil
}

type soakSignals struct{ findings *finding.Service }

// River v0.39.0's notifier exits on context.Canceled, but retries indefinitely
// on context.DeadlineExceeded. Retain values and propagate the parent's end as
// cancellation so a failed benchmark can still shut down its client cleanly.
func soakRiverContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	stop := context.AfterFunc(parent, cancel)
	return ctx, func() { stop(); cancel() }
}

type soakBlast struct {
	assets   *asset.Service
	graph    *graphstore.Service
	failures atomic.Uint64
}

func (s *soakBlast) observe(ctx context.Context, err error) {
	// Forced worker cancellation is expected; timeouts and storage failures
	// must not turn into a fast run through the scorer's fallback path.
	if err != nil && ctx.Err() != context.Canceled {
		s.failures.Add(1)
	}
}

func (s *soakBlast) BlastRadius(ctx context.Context, seed string, depth int) (asset.BlastRadius, error) {
	value, err := s.assets.BlastRadius(ctx, seed, depth)
	s.observe(ctx, err)
	return value, err
}

func (s *soakBlast) BlastRadiusAccounts(ctx context.Context, seed string, depth int) (asset.BlastAccountCounts, error) {
	value, err := s.assets.BlastRadiusAccounts(ctx, seed, depth)
	s.observe(ctx, err)
	return value, err
}

func (s *soakBlast) BlastRadiusCount(ctx context.Context, seed string, depth int) (int, error) {
	value, err := s.graph.BlastRadiusCount(ctx, seed, depth)
	s.observe(ctx, err)
	return value, err
}

type soakEnrichmentValue struct {
	score      uint8
	band       string
	factors    [32]byte
	unmeasured int
}

// Observe production outputs so storage verification compares values, not just
// nonzero scores. No output is substituted or recomputed by this adapter.
type soakEnricher struct {
	service *enrich.Service
	mu      sync.Mutex
	values  map[string]soakEnrichmentValue
}

func (s *soakEnricher) Enrich(ctx context.Context, f finding.Finding) (enrich.Score, error) {
	score, err := s.service.Enrich(ctx, f)
	if err != nil {
		return score, err
	}
	factors, err := json.Marshal(score.Factors)
	if err != nil {
		return score, err
	}
	s.mu.Lock()
	s.values[f.ID] = soakEnrichmentValue{score.Value, string(score.Band), sha256.Sum256(factors), len(score.Unmeasured)}
	s.mu.Unlock()
	return score, nil
}

func (s soakSignals) SignalsByResource(ctx context.Context) (map[string]graphstore.NodeSignals, error) {
	raw, err := s.findings.SignalsByResource(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]graphstore.NodeSignals, len(raw))
	for id, r := range raw {
		n := graphstore.NewNodeSignals()
		n.HasKEV, n.Exploitable, n.MaxScore, n.PrivescCount, n.CveID = r.HasKEV, r.Exploitable, int(r.MaxScore), r.PrivescCount, r.CveID
		out[id] = n
	}
	return out, nil
}

type soakLatency struct {
	Count  int     `json:"count"`
	Errors int     `json:"errors"`
	P50    float64 `json:"p50_seconds"`
	P95    float64 `json:"p95_seconds"`
	P99    float64 `json:"p99_seconds"`
	Max    float64 `json:"max_seconds"`
}
type soakReadSamples struct {
	mu         sync.Mutex
	times      map[string][]float64
	errors     map[string]int
	firstError string
}

func (s *soakReadSamples) add(kind string, start time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.times[kind] = append(s.times[kind], time.Since(start).Seconds())
	if err != nil {
		s.errors[kind]++
		if s.firstError == "" {
			s.firstError = err.Error()
		}
	}
}
func (s *soakReadSamples) report() map[string]soakLatency {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]soakLatency{}
	for name, values := range s.times {
		v := slices.Clone(values)
		slices.Sort(v)
		if len(v) == 0 {
			continue
		}
		at := func(percent int) float64 { return v[min(len(v)-1, (len(v)*percent+99)/100-1)] }
		out[name] = soakLatency{len(v), s.errors[name], at(50), at(95), at(99), v[len(v)-1]}
	}
	return out
}

type soakWave struct {
	Revision         int     `json:"revision"`
	Seconds          float64 `json:"seconds"`
	HeapBytes        uint64  `json:"heap_bytes_after_gc"`
	PeakRSSBytes     int64   `json:"process_peak_rss_bytes"`
	CompletedJobs    int     `json:"completed_jobs"`
	EnrichedFindings int     `json:"enriched_findings"`
	Restarted        bool    `json:"restarted"`
}
type soakQueryCost struct {
	Query        string `json:"normalized_query"`
	Calls        uint64 `json:"calls"`
	Milliseconds uint64 `json:"total_milliseconds"`
	ReadRows     uint64 `json:"read_rows"`
	ReadBytes    uint64 `json:"read_bytes"`
	MaxMemory    uint64 `json:"max_memory_bytes"`
}

type soakReport struct {
	Version        int                    `json:"format_version"`
	FixtureVersion int                    `json:"fixture_version"`
	Commit         string                 `json:"commit"`
	Platform       string                 `json:"platform"`
	GoVersion      string                 `json:"go_version"`
	GoMaxProcs     int                    `json:"gomaxprocs"`
	CHConcurrency  int                    `json:"clickhouse_concurrency"`
	BlastFailures  uint64                 `json:"blast_query_failures"`
	Passed         bool                   `json:"passed"`
	Seconds        float64                `json:"seconds"`
	MinimumSeconds int                    `json:"minimum_seconds"`
	Waves          []soakWave             `json:"waves"`
	Reads          map[string]soakLatency `json:"reads"`
	MaxPending     map[string]int         `json:"max_pending_jobs"`
	Deferred       map[string]int         `json:"unconsumed_external_jobs"`
	Retried        int                    `json:"retried_jobs"`
	VerifiedAssets int                    `json:"verified_assets"`
	VerifiedEdges  int                    `json:"verified_edges"`
	VerifiedScores int                    `json:"verified_enrichments"`
	Unmeasured     int                    `json:"final_unmeasured_findings"`
	GraphRebuilt   bool                   `json:"graph_rebuilt_after_restart"`
	GraphEdges     int64                  `json:"graph_loaded_edges"`
	UnloadedEdges  int64                  `json:"graph_unloaded_edge_types"`
	MissingEdges   int64                  `json:"graph_dropped_endpoints"`
	BackfillTicks  int                    `json:"backfill_ticks"`
	Queries        uint64                 `json:"queries"`
	ReadRows       uint64                 `json:"read_rows"`
	ReadBytes      uint64                 `json:"read_bytes"`
	MaxQueryMemory uint64                 `json:"max_query_memory_bytes"`
	QueryCosts     []soakQueryCost        `json:"top_query_costs"`
	ReadError      string                 `json:"first_read_error,omitempty"`
}

var soakQueues = []string{queueSync, queueEnrich, queueCorrelate, queueGraph}

func soakQueueCounts(ctx context.Context, pool *pgxpool.Pool) (map[string]int, int, error) {
	rows, err := pool.Query(ctx, `SELECT queue,state,count(*) FROM river_job GROUP BY queue,state`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	pending, completed := map[string]int{}, 0
	for rows.Next() {
		var queue, state string
		var n int
		if err := rows.Scan(&queue, &state, &n); err != nil {
			return nil, 0, err
		}
		if !slices.Contains(soakQueues, queue) {
			continue
		}
		switch state {
		case "completed":
			completed += n
		case "cancelled", "discarded":
			return nil, 0, fmt.Errorf("%d %s jobs in %s", n, state, queue)
		default:
			pending[queue] += n
		}
	}
	return pending, completed, rows.Err()
}

func waitSoakQueues(t *testing.T, ctx context.Context, pool *pgxpool.Pool, queues []string, peak map[string]int) int {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		pending, completed, err := soakQueueCounts(ctx, pool)
		require.NoError(t, err)
		remaining := 0
		for q, n := range pending {
			peak[q] = max(peak[q], n)
			if slices.Contains(queues, q) {
				remaining += n
			}
		}
		if remaining == 0 {
			return completed
		}
		select {
		case <-ctx.Done():
			t.Fatal("queues did not drain: ", pending, ctx.Err())
		case <-ticker.C:
		}
	}
}

func soakMemory() (uint64, int64) {
	runtime.GC()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	rss := usage.Maxrss
	if runtime.GOOS == "linux" {
		rss *= 1024
	}
	return mem.HeapAlloc, rss
}

func writeSoakReport(t *testing.T, r *soakReport) {
	t.Helper()
	r.Passed = r.Passed && !t.Failed()
	b, err := json.MarshalIndent(r, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_CONNECTOR_DIR"), "soak.json"), b, 0600))
}

func soakGraphRead(ctx context.Context, graph *graphstore.Service) error {
	result, err := graph.RunCypher(ctx, "MATCH (p:K8sWorkload {id:'pod-0'})-[r:RunsImage]->(i:Asset) RETURN p,r,i", 10, 10)
	if err != nil {
		return err
	}
	if len(result.Nodes) != 2 || len(result.Edges) != 1 {
		return fmt.Errorf("graph read lost the stable workload/image relationship")
	}
	return nil
}

func soakExpected(t *testing.T, producers map[string]*soakCollector) (map[string]asset.Asset, map[scaleEdgeKey]asset.Edge) {
	t.Helper()
	assets, edges := map[string]asset.Asset{}, map[scaleEdgeKey]asset.Edge{}
	for _, c := range producers {
		r, err := c.Collect(t.Context(), nil)
		require.NoError(t, err)
		for _, a := range r.Assets {
			assets[a.ID] = a
		}
		for _, e := range r.Edges {
			edges[scaleEdgeKey{e.SrcID, e.EdgeType, e.DstID}] = e
		}
	}
	return assets, edges
}
