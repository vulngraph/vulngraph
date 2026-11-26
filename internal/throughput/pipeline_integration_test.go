//go:build integration

package throughput

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/migrate"
)

type measurement struct {
	Scenario       string             `json:"scenario"`
	Path           string             `json:"sync_path"`
	Seconds        float64            `json:"seconds"`
	Phases         map[string]float64 `json:"phase_seconds"`
	Nodes          int64              `json:"resident_nodes"`
	Edges          int64              `json:"resident_edges"`
	EdgesPerSecond float64            `json:"resident_edges_per_second"`
	HeapBytes      uint64             `json:"go_heap_bytes_after"`
	AllocatedBytes uint64             `json:"go_allocated_bytes"`
	PeakRSSBytes   int64              `json:"process_peak_rss_bytes"`
	Queries        []queryCost        `json:"queries"`
	ReadRows       uint64             `json:"read_rows"`
	ReadBytes      uint64             `json:"read_bytes"`
	MaxQueryMemory uint64             `json:"max_query_memory_bytes"`
	Error          string             `json:"error,omitempty"`
}

func (*measurement) ObserveLadybugSync(_ string, _ float64)              {}
func (m *measurement) ObserveLadybugPhase(phase string, seconds float64) { m.Phases[phase] += seconds }

type report struct {
	Passed          bool           `json:"passed"`
	Version         int            `json:"format_version"`
	FixtureVersion  int            `json:"fixture_version"`
	Commit          string         `json:"commit"`
	GoVersion       string         `json:"go_version"`
	Platform        string         `json:"platform"`
	GoMaxProcs      int            `json:"gomaxprocs"`
	LadybugBufferMB int            `json:"ladybug_buffer_mb"`
	Started         time.Time      `json:"started_at"`
	Profile         profile        `json:"profile"`
	SeedSeconds     float64        `json:"seed_seconds"`
	Rows            rowCounts      `json:"rows"`
	Measurements    []*measurement `json:"measurements"`
}

// This adapter changes only the result shape. The expensive rollup is the real
// finding service query, including its production timeout and joins.
type signalSource struct{ findings *finding.Service }

func (s signalSource) SignalsByResource(ctx context.Context) (map[string]graphstore.NodeSignals, error) {
	raw, err := s.findings.SignalsByResource(ctx)
	if err != nil {
		return nil, fmt.Errorf("finding rollup: %w", err)
	}
	out := make(map[string]graphstore.NodeSignals, len(raw))
	for id, r := range raw {
		n := graphstore.NewNodeSignals()
		n.HasKEV, n.Exploitable, n.MaxScore, n.PrivescCount, n.CveID = r.HasKEV, r.Exploitable, int(r.MaxScore), r.PrivescCount, r.CveID
		out[id] = n
	}
	return out, nil
}

const changeSignals = `INSERT INTO finding_enrichment (id,score,score_band,known_exploited,enriched_at)
 VALUES ('bench-finding-cspm0',95,'critical',1,toDateTime64(?,3))`

func isolatedURL(raw, scheme string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == scheme && u.Hostname() == "127.0.0.1" && u.Port() != "" && u.Path == "/vg_perf"
}

func TestPipelineThroughput(t *testing.T) {
	if os.Getenv("PERF_ISOLATED") != "1" {
		t.Skip("run scripts/benchmark-pipeline.sh to create disposable databases")
	}
	p, err := dataset(os.Getenv("PERF_PROFILE"))
	require.NoError(t, err)
	bufferMB := 256
	if p.Workloads >= 600000 {
		bufferMB = 1280
	}
	if v := os.Getenv("PERF_LADYBUG_MB"); v != "" {
		bufferMB, err = strconv.Atoi(v)
		require.NoError(t, err)
	}
	require.GreaterOrEqual(t, bufferMB, 64)
	require.LessOrEqual(t, bufferMB, 16384)
	pgDSN, chDSN := os.Getenv("PERF_POSTGRES_URL"), os.Getenv("PERF_CLICKHOUSE_URL")
	require.True(t, isolatedURL(pgDSN, "postgres") && isolatedURL(chDSN, "clickhouse"), "benchmark requires loopback URLs to the vg_perf database")
	require.NotEmpty(t, os.Getenv("PERF_REPORT"))
	r := report{Version: 1, FixtureVersion: 1, Commit: os.Getenv("PERF_COMMIT"), GoVersion: runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH, GoMaxProcs: runtime.GOMAXPROCS(0), LadybugBufferMB: bufferMB, Started: time.Now().UTC(), Profile: p}
	t.Cleanup(func() {
		b, e := json.MarshalIndent(r, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(os.Getenv("PERF_REPORT"), append(b, '\n'), 0600))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	require.NoError(t, migrate.Run(ctx, pgDSN, chDSN))
	ch, err := db.NewCH(ctx, chDSN, 4)
	require.NoError(t, err)
	defer func() { _ = ch.Close() }()
	before, err := counts(ctx, ch)
	require.NoError(t, err)
	require.Zero(t, before.Assets, "refusing to seed an occupied database")
	require.Zero(t, before.Edges, "refusing to seed an occupied database")
	stamp := time.Now().Add(-5 * time.Minute).Unix()
	start := time.Now()
	require.NoError(t, seed(ctx, ch, p, stamp))
	r.SeedSeconds = time.Since(start).Seconds()
	r.Rows, err = counts(ctx, ch)
	require.NoError(t, err)
	require.Equal(t, p.coreNodes()+p.Packages, r.Rows.Assets)
	require.Equal(t, p.coreEdges()+p.Memberships, r.Rows.Edges, "duplicate or missing fixture edges")
	inv := asset.NewService(asset.NewCHRepo(ch))
	signals := signalSource{finding.NewService(finding.NewCHRepo(ch))}
	svc, err := graphstore.Open("", bufferMB, 2, 2, "")
	require.NoError(t, err)
	defer svc.Close()
	svc.SetLoadThreads(2)
	for _, scenario := range []struct{ name, path string }{
		{"initial_build", "full"}, {"unchanged_1", "noop"}, {"unchanged_2", "noop"},
		{"finding_update", "signals"}, {"topology_update_1pct", "full"}, {"unchanged_after_update", "noop"},
	} {
		if scenario.name == "finding_update" {
			require.NoError(t, ch.Exec(ctx, changeSignals, stamp+2))
		}
		if scenario.name == "topology_update_1pct" {
			require.NoError(t, ch.Exec(ctx, changeTopology, stamp+2))
		}
		m := &measurement{Scenario: scenario.name, Phases: map[string]float64{}}
		r.Measurements = append(r.Measurements, m)
		svc.WithSyncMetrics(m)
		comment := fmt.Sprintf("vg-perf-%d-%s", r.Started.UnixNano(), scenario.name)
		qctx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": comment, "log_queries": 1, "log_queries_probability": 1})
		var memBefore, memAfter runtime.MemStats
		runtime.ReadMemStats(&memBefore)
		start = time.Now()
		syncErr := svc.SyncFromSources(qctx, 0, inv, inv, signals)
		m.Seconds = time.Since(start).Seconds()
		runtime.ReadMemStats(&memAfter)
		m.HeapBytes, m.AllocatedBytes = memAfter.HeapAlloc, memAfter.TotalAlloc-memBefore.TotalAlloc
		var usage syscall.Rusage
		require.NoError(t, syscall.Getrusage(syscall.RUSAGE_SELF, &usage))
		m.PeakRSSBytes = usage.Maxrss
		if runtime.GOOS == "linux" {
			m.PeakRSSBytes *= 1024
		}
		m.Path, m.Nodes = svc.LastSyncPath(), svc.NodeCount()
		var dropped, missing int64
		m.Edges, dropped, missing = svc.EdgeLoadStats()
		if m.Path == "full" && syncErr == nil {
			m.EdgesPerSecond = float64(m.Edges) / m.Seconds
		}
		if syncErr != nil {
			m.Error = syncErr.Error()
		}
		m.Queries, err = costs(ctx, ch, comment)
		require.NoError(t, err)
		for _, q := range m.Queries {
			m.ReadRows += q.ReadRows
			m.ReadBytes += q.ReadBytes
			m.MaxQueryMemory = max(m.MaxQueryMemory, q.Memory)
		}
		t.Logf("%s: path=%s seconds=%.3f nodes=%d edges=%d queries=%d read_rows=%d max_query_memory=%d peak_rss=%d",
			scenario.name, m.Path, m.Seconds, m.Nodes, m.Edges, len(m.Queries), m.ReadRows, m.MaxQueryMemory, m.PeakRSSBytes)
		require.NoError(t, syncErr)
		require.NotEmpty(t, m.Queries, "query logging is required; empty telemetry is not success")
		// One asset read, critical/bulk edge reads, package risk, and findings.
		// A new read must be reviewed explicitly rather than hiding N+1 growth.
		require.Len(t, m.Queries, 5, "graph refresh query count changed")
		// Current profiles read roughly four rows for each stored row across the
		// five queries. Leave room for merge/index granularity without accepting
		// a second broad scan in every branch. This is a work budget, not a timer.
		require.LessOrEqual(t, m.ReadRows, 6*(r.Rows.AssetVersions+r.Rows.EdgeVersions), "read amplification exceeded fixture budget")
		require.Equal(t, scenario.path, m.Path)
		require.EqualValues(t, p.coreNodes(), m.Nodes, "packages must stay outside the resident graph")
		require.EqualValues(t, p.coreEdges(), m.Edges, "every core edge must survive the load")
		require.Zero(t, dropped)
		require.Zero(t, missing)
		public, err := svc.TryNodeSignals(ctx, "pod-0")
		require.NoError(t, err)
		require.Equal(t, 2, public.InternetHops)
		private, err := svc.TryNodeSignals(ctx, "pod-10")
		require.NoError(t, err)
		require.Equal(t, graphstore.ReachNone, private.InternetHops)
		if scenario.name == "finding_update" {
			require.True(t, public.HasKEV)
		}
	}
	r.Passed = true
}
