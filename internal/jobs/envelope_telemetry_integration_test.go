//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/riverqueue/river"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type envelopeTrace struct {
	mu     sync.Mutex
	file   *os.File
	active map[string]int
	peak   map[string]int
	err    error
}

func (r *envelopeTrace) write(v map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v["at"] = time.Now().UTC()
	if err := json.NewEncoder(r.file).Encode(v); err != nil && r.err == nil {
		r.err = err
	}
}

func (r *envelopeTrace) begin(kind, id string) func(error) {
	start := time.Now()
	r.mu.Lock()
	r.active[kind]++
	r.peak[kind] = max(r.peak[kind], r.active[kind])
	r.mu.Unlock()
	r.write(map[string]any{"event": "start", "kind": kind, "id": id})
	return func(err error) {
		r.mu.Lock()
		r.active[kind]--
		r.mu.Unlock()
		message := ""
		if err != nil {
			message = err.Error()
		}
		r.write(map[string]any{"event": "end", "kind": kind, "id": id, "seconds": time.Since(start).Seconds(), "error": message})
	}
}

func (r *envelopeTrace) sample(ctx context.Context) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m) // no forced collection: preserve live workload pressure
		files := map[string]string{}
		for _, name := range []string{"/proc/self/status", "/proc/self/io", "/proc/meminfo", "/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/memory.swap.current", "/sys/fs/cgroup/memory.swap.max", "/sys/fs/cgroup/memory.swap.peak", "/sys/fs/cgroup/memory.swap.events", "/sys/fs/cgroup/memory.events", "/sys/fs/cgroup/memory.stat", "/sys/fs/cgroup/cpu.stat", "/sys/fs/cgroup/io.stat"} {
			b, err := os.ReadFile(name)
			if err != nil {
				return fmt.Errorf("sample %s: %w", name, err)
			}
			files[name] = string(b)
		}
		temp, err := envelopeTempUsage(os.TempDir())
		if err != nil {
			return err
		}
		r.mu.Lock()
		active := map[string]int{}
		for k, v := range r.active {
			active[k] = v
		}
		r.mu.Unlock()
		r.write(map[string]any{"event": "sample", "active": active, "go_heap_alloc_bytes": m.HeapAlloc,
			"go_heap_inuse_bytes": m.HeapInuse, "go_sys_bytes": m.Sys, "go_gc_count": m.NumGC, "go_total_alloc_bytes": m.TotalAlloc, "files": files,
			"temporary_files": temp})
	}
}

func (r *envelopeTrace) ObserveCorrelateView(rows, limit int) {
	r.write(map[string]any{"event": "correlation_view", "relevant_rows_loaded": rows, "row_limit_zero_means_byte_budgets": limit})
}

func (r *envelopeTrace) ObserveStagedView(stats correlate.StagedViewStats) {
	r.write(map[string]any{"event": "correlation_staged_cost", "stats": stats})
}

func (r *envelopeTrace) ObserveLadybugSync(path string, seconds float64) {
	r.write(map[string]any{"event": "graph_path", "path": path, "seconds": seconds})
}
func (r *envelopeTrace) ObserveLadybugPhase(phase string, seconds float64) {
	r.write(map[string]any{"event": "graph_phase_end", "phase": phase, "seconds": seconds})
}

type envelopeSyncWorker struct {
	*SyncWorker
	trace *envelopeTrace
}

func (w *envelopeSyncWorker) Work(ctx context.Context, job *river.Job[SyncConnectorArgs]) error {
	finish := w.trace.begin("sync", job.Args.ConnectorID)
	err := w.SyncWorker.Work(ctx, job)
	finish(err)
	return err
}

type envelopeCorrelator struct {
	*correlate.Service
	trace *envelopeTrace
}

func (c *envelopeCorrelator) Correlate(ctx context.Context) (int, error) {
	finish := c.trace.begin("correlation_full", "")
	n, err := c.Service.Correlate(ctx)
	finish(err)
	return n, err
}
func (c *envelopeCorrelator) PartialCorrelate(ctx context.Context, ids []string) (int, error) {
	finish := c.trace.begin("correlation_partial", "")
	n, err := c.Service.PartialCorrelate(ctx, ids)
	finish(err)
	return n, err
}

type envelopeEnricher struct {
	*soakEnricher
	trace *envelopeTrace
}

func (e *envelopeEnricher) Enrich(ctx context.Context, f finding.Finding) (enrich.Score, error) {
	finish := e.trace.begin("enrich", f.ID)
	score, err := e.soakEnricher.Enrich(ctx, f)
	finish(err)
	return score, err
}
