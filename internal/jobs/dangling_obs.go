package jobs

import (
	"time"

	"github.com/vulngraph/vulngraph/internal/obs"
)

// Sweep phase labels for obs.Metrics.ObserveSweep — one per
// dangling-sweep phase (see dangling.go's Work()). Kept as named constants (not
// inline strings at each call site) so the phase label used to RECORD a
// metric can never silently drift from the phase label a dashboard/alert
// queries against.
const (
	sweepPhaseDangling     = "dangling"
	sweepPhaseStaleState   = "stale_state"
	sweepPhaseK8sLifecycle = "k8s_lifecycle"
	// sweepPhaseGCELifecycle is a SEPARATE label from k8s_lifecycle rather than a
	// shared "lifecycle" one: k8s_lifecycle is already queried by dashboards/alerts,
	// and folding a second resource family into it would change what those are
	// measuring without anyone editing them.
	sweepPhaseGCELifecycle = "gce_lifecycle"
)

// recordSweepPhase reports one dangling-sweep phase's tick outcome to the obs
// sweep-effectiveness counters, so a sweep reporting "resolved: 0" against a
// large backlog has a metric to catch it. scanned is recorded even when resolved is zero — that combination
// is precisely the failure this exists to surface. The last-resolved gauge is
// only stamped when resolved > 0, so a phase stuck at scanned-high/resolved-
// zero shows a stale (non-advancing) timestamp rather than a fresh one.
func recordSweepPhase(m *obs.Metrics, phase string, scanned, resolved int) {
	m.ObserveSweep(phase, "scanned", scanned)
	m.ObserveSweep(phase, "resolved", resolved)
	if resolved > 0 {
		m.ObserveSweepResolved(phase, float64(time.Now().Unix()))
	}
}
