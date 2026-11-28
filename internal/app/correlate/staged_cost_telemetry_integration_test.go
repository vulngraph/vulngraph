//go:build integration

package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/pkg/log"
	"golang.org/x/sync/errgroup"
)

type stagedCostTrace struct{ phase atomic.Value }

func startStagedCostTrace(t *testing.T, ctx context.Context) (*stagedCostTrace, func()) {
	t.Helper()
	file, err := os.Create(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "worker-resources.jsonl"))
	require.NoError(t, err)
	trace := &stagedCostTrace{}
	trace.phase.Store("seed")
	ctx, cancel := context.WithCancel(ctx)
	var group errgroup.Group
	group.Go(func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("correlation sampler panic: %v", p)
				log.FromContext(ctx).Error().Err(err).Msg("correlation sampler failed")
			}
		}()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			files := map[string]string{}
			for _, name := range []string{"/proc/self/status", "/proc/self/io", "/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.swap.current", "/sys/fs/cgroup/memory.events", "/sys/fs/cgroup/cpu.stat", "/sys/fs/cgroup/io.stat"} {
				b, e := os.ReadFile(name)
				if e != nil {
					return fmt.Errorf("sample %s: %w", name, e)
				}
				files[name] = string(b)
			}
			if e := json.NewEncoder(file).Encode(map[string]any{"at": time.Now().UTC(), "phase": trace.phase.Load(), "heap_alloc_bytes": m.HeapAlloc,
				"heap_inuse_bytes": m.HeapInuse, "go_total_alloc_bytes": m.TotalAlloc, "go_gc_count": m.NumGC, "files": files}); e != nil {
				return e
			}
		}
	})
	return trace, func() {
		cancel()
		require.NoError(t, group.Wait())
		require.NoError(t, file.Close())
	}
}
