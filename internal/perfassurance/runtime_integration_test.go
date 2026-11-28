//go:build integration

package perfassurance

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/memlimit"
)

func TestWorkerBootstrapRejectsUnappliedRuntimeControls(t *testing.T) {
	good := WorkerRuntime{Policy: memlimit.Budget{Applied: true, GoLimit: 1792 << 20, GCPercent: 60}, GoMemoryLimit: 1792 << 20, GOGC: 60, GOMAXPROCS: 1}
	require.NoError(t, verifyWorkerRuntime(good, "1"))
	for _, tc := range []struct {
		name   string
		mutate func(*WorkerRuntime)
	}{
		{"policy omitted", func(v *WorkerRuntime) { v.Policy.Applied = false }},
		{"default memory limit", func(v *WorkerRuntime) { v.GoMemoryLimit = 1<<63 - 1 }},
		{"default GC", func(v *WorkerRuntime) { v.GOGC = 100 }},
		{"wrong parallelism", func(v *WorkerRuntime) { v.GOMAXPROCS = 4 }},
	} {
		t.Run(tc.name, func(t *testing.T) { bad := good; tc.mutate(&bad); require.Error(t, verifyWorkerRuntime(bad, "1")) })
	}
	require.Error(t, verifyWorkerRuntime(good, ""))
}
