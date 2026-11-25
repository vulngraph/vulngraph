package jobs

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// closeMargin is left for what runs after Stop and the flush: closing Ladybug
// (its WAL checkpoint), the ClickHouse and Postgres pools, tracing.
const closeMargin = 5 * time.Second

var gracePeriodRE = regexp.MustCompile(`(?m)^\s*terminationGracePeriodSeconds:\s*(\d+)\s*$`)

// TestShutdownFitsTerminationGracePeriod: Kubernetes SIGKILLs a pod at its
// grace period, so a shutdown that does not fit loses whatever runs last — on
// the worker, the correlate coalescer's final flush (Stop 30s + flush 10s ran
// against a 30s grace period).
func TestShutdownFitsTerminationGracePeriod(t *testing.T) {
	for _, tc := range []struct {
		file   string
		budget time.Duration
	}{
		{"deployment-worker.yaml", workerShutdownBudget},
		{"deployment-scanner.yaml", scannerShutdownBudget},
	} {
		t.Run(tc.file, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(moduleRoot(t), "deploy", "helm-chart", "graph", "templates", tc.file))
			require.NoError(t, err)
			m := gracePeriodRE.FindSubmatch(src)
			require.NotNil(t, m, "%s must set terminationGracePeriodSeconds", tc.file)
			secs, err := strconv.Atoi(string(m[1]))
			require.NoError(t, err)
			require.GreaterOrEqual(t, time.Duration(secs)*time.Second, tc.budget+closeMargin,
				"%s's grace period must cover the shutdown budget plus closing pools", tc.file)
		})
	}
}
