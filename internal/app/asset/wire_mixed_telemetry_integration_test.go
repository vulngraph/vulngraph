//go:build integration

package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

type wireTrace struct {
	mu     sync.Mutex
	file   *os.File
	active map[string]int
	peak   map[string]int
	err    error
}

func (r *wireTrace) write(v map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v["at"] = time.Now().UTC()
	if err := json.NewEncoder(r.file).Encode(v); err != nil && r.err == nil {
		r.err = err
	}
}

func (r *wireTrace) begin(kind, id string) func(error) {
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

func (r *wireTrace) sample(ctx context.Context) error {
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
		r.mu.Lock()
		active := map[string]int{}
		for k, v := range r.active {
			active[k] = v
		}
		r.mu.Unlock()
		r.write(map[string]any{"event": "sample", "active": active, "go_heap_alloc_bytes": m.HeapAlloc,
			"go_heap_inuse_bytes": m.HeapInuse, "go_sys_bytes": m.Sys, "go_gc_count": m.NumGC, "go_total_alloc_bytes": m.TotalAlloc, "files": files})
	}
}
