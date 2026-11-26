// Package collectbench measures real collector code against deterministic API
// fixtures. It is used only by tests; cloud latency and quotas are not inferred.
package collectbench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/benchconfig"
)

type Measurement struct {
	Connector       string  `json:"connector"`
	Scope           string  `json:"scope"`
	Size            int     `json:"size"`
	Run             int     `json:"run"`
	Seconds         float64 `json:"seconds"`
	AllocatedBytes  uint64  `json:"allocated_bytes"`
	Assets          int     `json:"assets"`
	Edges           int     `json:"edges"`
	Requests        int     `json:"requests"`
	Partial         bool    `json:"partial"`
	DuplicateAssets int     `json:"duplicate_asset_rows"`
}

func Sizes(t *testing.T) []int {
	t.Helper()
	if os.Getenv("PERF_CONNECTORS") != "1" {
		t.Skip("run scripts/benchmark-connectors.sh")
	}
	maxSize := benchconfig.MaxSize(t)
	var sizes []int
	for _, n := range []int{100, 1000, 10000} {
		if n <= maxSize {
			sizes = append(sizes, n)
		}
	}
	return sizes
}

// Run validates cardinality and stable asset identity independently of timing.
// prepare resets fake API state outside measurements; collect executes the real
// collector. Request counts let CI detect N+1 growth without flaky time gates.
func Run(t *testing.T, name, scope, typ string, n int, prepare func(), collectFn func() (collect.Result, int, error)) {
	t.Helper()
	var measurements []Measurement
	var last collect.Result
	for run := range 3 {
		prepare()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		res, requests, err := collectFn()
		seconds := time.Since(start).Seconds()
		runtime.ReadMemStats(&after)
		require.NoError(t, err)
		seen := map[string]bool{}
		count := 0
		duplicates := 0
		for _, a := range res.Assets {
			require.NotEmpty(t, a.ID)
			if seen[a.ID] {
				duplicates++
				continue
			}
			seen[a.ID] = true
			if a.Type == typ {
				count++
			}
		}
		require.Equal(t, n, count, "collector lost or duplicated resources")
		m := Measurement{name, scope, n, run, seconds, after.TotalAlloc - before.TotalAlloc, len(res.Assets), len(res.Edges), requests, res.Partial, duplicates}
		measurements = append(measurements, m)
		t.Logf("%s/%d run=%d seconds=%.4f assets=%d edges=%d requests=%d partial=%v allocated=%d", name, n, run, seconds, m.Assets, m.Edges, requests, res.Partial, m.AllocatedBytes)
		last = res
	}
	if dir := os.Getenv("PERF_CONNECTOR_DIR"); dir != "" {
		write := func(name string, v any) {
			b, err := json.Marshal(v)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), b, 0600))
		}
		write(fmt.Sprintf("%s-%d.json", name, n), measurements)
		write(fmt.Sprintf("%s-%d-fixture.json", name, n), last)
	}
}
