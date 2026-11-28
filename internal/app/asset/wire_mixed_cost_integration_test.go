//go:build integration

package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
	"github.com/vulngraph/vulngraph/pkg/log"
	"golang.org/x/sync/errgroup"
)

type wireOperation struct {
	Scheduled time.Time `json:"scheduled"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
	Error     string    `json:"error,omitempty"`
}

func wireTask(g *errgroup.Group, ctx context.Context, fn func() error) {
	g.Go(func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("wire mixed panic: %v", p)
				log.FromContext(ctx).Error().Err(err).Msg("wire mixed probe failed")
			}
		}()
		return fn()
	})
}

func waitWireArrival(ctx context.Context, at time.Time) error {
	if time.Until(at) <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func runWireMixed(t *testing.T, ctx context.Context, app, admin *db.CH, repo *CHRepo, n int, stamp time.Time, baseline, candidate func(context.Context) (AssetSyncResult, error), verify func(AssetSyncResult) string) {
	t.Helper()
	variant := os.Getenv("PERF_GRAPH_WIRE_VARIANT")
	require.Contains(t, []string{"baseline", "projected"}, variant)
	seconds, err := strconv.Atoi(os.Getenv("PERF_GRAPH_WIRE_SECONDS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, seconds, 5)
	require.LessOrEqual(t, seconds, 60)
	dir := os.Getenv("PERF_ENVELOPE_DIR")
	sg := Asset{ID: "wire-sg", Name: "edge-sentinel", Type: "security_group", Provider: "aws", AccountID: "synthetic", DiscoveredAt: stamp, FirstDiscoveredAt: stamp, LastSeen: stamp}
	require.NoError(t, repo.UpsertAssets(ctx, []Asset{sg}))
	require.NoError(t, admin.Exec(ctx, "SYSTEM STOP MERGES graph_edges"))
	for version := range 2 {
		for start := 0; start < n; start += 100000 {
			require.NoError(t, admin.Exec(ctx, `INSERT INTO graph_edges
 SELECT concat('wire-',leftPad(toString(number),9,'0')),'ec2_instance','wire-sg','security_group','connected_via_sg',
 toJSONString(map('ports','443','revision',?)),fromUnixTimestamp64Nano(toInt64(?)) FROM numbers(?,?) SETTINGS max_block_size=8192,max_threads=2`, strconv.Itoa(version), stamp.UnixNano()+int64(version)*int64(time.Millisecond), start, min(100000, n-start)))
		}
	}
	want, err := repo.List(ctx, Filter{Type: "ec2_instance"})
	require.NoError(t, err)
	require.Len(t, want, 100)
	for i, a := range want {
		require.Equal(t, fmt.Sprintf("wire-%09d", n-1-i), a.ID)
		require.Equal(t, "revision-1", a.Name)
		require.Equal(t, uint8((n-1-i)%101), a.RiskScore)
	}
	traceFile, err := os.Create(filepath.Join(dir, "wire-worker-timeline.jsonl"))
	require.NoError(t, err)
	defer traceFile.Close()
	trace := &wireTrace{file: traceFile, active: map[string]int{}, peak: map[string]int{}}
	report := map[string]any{"variant": variant, "logical_graph_assets": n + 1, "physical_graph_asset_rows": 2*n + 1, "physical_edge_rows": 2 * n, "seconds_offered": seconds, "reads_per_second": 4, "read_workers": 2, "write_batches_per_second": 2, "write_batch_rows": 100, "ch_concurrency": 4,
		"scope":                   "one concurrent asset/edge source pair plus paced repository inventory reads and real ingestion; source result slices retained until cohort drains; no native COPY/BFS, River queues or SDK collection",
		"wait_scope":              "scheduled arrival to harness worker start; call latency also contains unseparated CH semaphore/pool/transport wait",
		"source_allocation_scope": "Measure allocation deltas include concurrent background work; use cohort timeline for whole-worker allocation/RSS/CPU/swap"}
	var sourceSample perfassurance.QuerySample
	var sourceAssets AssetSyncResult
	var sourceEdges EdgeSyncResult
	var readOps, writeOps []wireOperation
	t.Cleanup(func() {
		report["passed"] = !t.Failed()
		report["source_sample"] = sourceSample
		report["reads"] = readOps
		report["writes"] = writeOps
		b, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "graph-source-wire-mixed.json"), b, 0600))
	})
	runtime.GC() // one matched pre-cohort collection; none during the workload
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	sampleCtx, stopSampling := context.WithCancel(ctx)
	var sampler errgroup.Group
	wireTask(&sampler, sampleCtx, func() error { return trace.sample(sampleCtx) })
	defer func() { stopSampling(); require.NoError(t, sampler.Wait()) }()
	start := time.Now().UTC()
	report["started"] = start
	var tasks errgroup.Group
	access := perfassurance.QueryLogAccess{Flush: func(ctx context.Context) error { return admin.Exec(ctx, "SYSTEM FLUSH LOGS") }, Select: `SELECT query,query_duration_ms,read_rows,read_bytes,memory_usage,exception,Settings['max_threads'],Settings['max_block_size'],ProfileEvents FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds,query_id`}
	wireTask(&tasks, ctx, func() error {
		var measureErr error
		sourceSample, measureErr = perfassurance.Measure(ctx, admin, access, "wire-mixed-source-"+variant, func(ctx context.Context) error {
			var pair errgroup.Group
			wireTask(&pair, ctx, func() (err error) {
				done := trace.begin("asset_source", variant)
				defer func() { done(err) }()
				bounded, cancel := context.WithTimeout(ctx, 120*time.Second)
				defer cancel()
				if variant == "baseline" {
					sourceAssets, err = baseline(bounded)
				} else {
					sourceAssets, err = candidate(bounded)
				}
				return err
			})
			wireTask(&pair, ctx, func() (err error) {
				done := trace.begin("edge_source", variant)
				defer func() { done(err) }()
				sourceEdges, err = repo.AllEdgesForSync(ctx, SyncProjection{})
				return err
			})
			return pair.Wait()
		})
		if measureErr != nil {
			sourceSample.Error = measureErr.Error()
		}
		return measureErr
	})
	arrivals := make(chan time.Time, 8)
	completed := make(chan wireOperation, seconds*4)
	wireTask(&tasks, ctx, func() error {
		defer close(arrivals)
		for i := range seconds * 4 {
			at := start.Add(time.Duration(i) * time.Second / 4)
			if err := waitWireArrival(ctx, at); err != nil {
				return err
			}
			select {
			case arrivals <- at:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	for range 2 {
		wireTask(&tasks, ctx, func() error {
			for at := range arrivals {
				op := wireOperation{Scheduled: at, Started: time.Now().UTC()}
				done := trace.begin("inventory", "")
				got, e := repo.List(app.WithQuerySettings(ctx, map[string]any{"log_comment": "wire-mixed-inventory"}), Filter{Type: "ec2_instance"})
				if e == nil && !reflect.DeepEqual(want, got) {
					e = fmt.Errorf("inventory page differs from independently checked stable page")
				}
				done(e)
				if e != nil {
					op.Error = e.Error()
				}
				op.Finished = time.Now().UTC()
				completed <- op
			}
			return nil
		})
	}
	wireTask(&tasks, ctx, func() error {
		service := NewService(repo)
		writes := make([]Asset, 100)
		for i := range writes {
			writes[i] = Asset{ID: fmt.Sprintf("wire-ingest-%03d", i), Name: "ingest", Type: "package", Provider: "aws", DiscoveredAt: stamp, FirstDiscoveredAt: stamp, Metadata: map[string]string{}}
		}
		for wave := range seconds * 2 {
			at := start.Add(time.Duration(wave) * time.Second / 2)
			if err := waitWireArrival(ctx, at); err != nil {
				return err
			}
			op := wireOperation{Scheduled: at, Started: time.Now().UTC()}
			for i := range writes {
				writes[i].Metadata["mixed_wave"] = strconv.Itoa(wave)
				writes[i].LastSeen = stamp.Add(time.Duration(wave) * time.Second)
			}
			done := trace.begin("ingest", "")
			e := service.IngestAssets(app.WithQuerySettings(ctx, map[string]any{"log_comment": "wire-mixed-ingest"}), writes)
			done(e)
			if e != nil {
				op.Error = e.Error()
			}
			op.Finished = time.Now().UTC()
			writeOps = append(writeOps, op)
		}
		return nil
	})
	workErr := tasks.Wait()
	report["finished"] = time.Now().UTC()
	runtime.ReadMemStats(&after)
	report["allocated_bytes"] = after.TotalAlloc - before.TotalAlloc
	report["gc_count"] = after.NumGC - before.NumGC
	stopSampling()
	require.NoError(t, sampler.Wait())
	require.NoError(t, trace.err)
	close(completed)
	for op := range completed {
		readOps = append(readOps, op)
	}
	require.NoError(t, workErr)
	require.Len(t, readOps, seconds*4)
	require.Len(t, writeOps, seconds*2)
	for _, op := range append(append([]wireOperation{}, readOps...), writeOps...) {
		require.Empty(t, op.Error)
	}
	require.Len(t, sourceSample.Queries, 3, "one asset, one critical-edge and one bulk-edge terminal record")
	queryKinds := map[string]int{}
	for _, q := range sourceSample.Queries {
		switch {
		case strings.Contains(q.SQL, "FROM graph_edges") && strings.Contains(q.SQL, "LIMIT"):
			queryKinds["bulk"]++
		case strings.Contains(q.SQL, "FROM graph_edges"):
			queryKinds["critical"]++
		case strings.Contains(q.SQL, "FROM assets") && strings.Contains(q.SQL, "LIMIT 5000000"):
			queryKinds["assets"]++
		default:
			t.Errorf("unexpected source terminal query: %s", q.SQL)
		}
		if variant == "projected" {
			require.LessOrEqual(t, q.Memory, uint64(512<<20), "fixed source query budget")
		}
	}
	require.Equal(t, map[string]int{"assets": 1, "critical": 1, "bulk": 1}, queryKinds)
	require.Len(t, sourceAssets.Assets, n+1)
	require.False(t, sourceAssets.Truncated)
	report["asset_output_sha256"] = verify(AssetSyncResult{Assets: sourceAssets.Assets[:n]})
	gotSG := sourceAssets.Assets[n]
	gotSG.DiscoveredAt, gotSG.FirstDiscoveredAt, gotSG.LastSeen = gotSG.DiscoveredAt.UTC(), gotSG.FirstDiscoveredAt.UTC(), gotSG.LastSeen.UTC()
	require.Equal(t, sg, gotSG)
	require.False(t, sourceEdges.BulkPassFailed)
	require.Empty(t, sourceEdges.TruncatedTypes)
	require.Len(t, sourceEdges.Edges, n)
	seen := make([]bool, n)
	for _, e := range sourceEdges.Edges {
		i, err := strconv.Atoi(strings.TrimPrefix(e.SrcID, "wire-"))
		require.NoError(t, err)
		require.GreaterOrEqual(t, i, 0)
		require.Less(t, i, n)
		require.False(t, seen[i])
		seen[i] = true
		require.Equal(t, Edge{SrcID: e.SrcID, SrcType: "ec2_instance", DstID: "wire-sg", DstType: "security_group", EdgeType: "connected_via_sg", Properties: map[string]string{"ports": "443", "revision": "1"}}, e)
	}
	ids := make([]string, 100)
	for i := range ids {
		ids[i] = fmt.Sprintf("wire-ingest-%03d", i)
	}
	persisted, err := repo.ByIDs(ctx, ids)
	require.NoError(t, err)
	require.Len(t, persisted, 100)
	for _, a := range persisted {
		require.Equal(t, strconv.Itoa(seconds*2-1), a.Metadata["mixed_wave"])
		require.True(t, stamp.Equal(a.FirstDiscoveredAt))
		require.True(t, stamp.Add(time.Duration(seconds*2-1)*time.Second).Equal(a.LastSeen))
	}
	report["exact_outputs"] = true
}
