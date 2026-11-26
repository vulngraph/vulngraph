package graphstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// RefreshSignals updates finding-derived signal columns in the live Ladybug graph and
// refreshes the in-memory caches without a full topology rebuild. Called when the
// topology_version in ClickHouse sync_state is unchanged since the last full
// sync. The correlate worker bumps it after every full sweep, so an unchanged
// version means no sweep has completed since then, or the sweep's bump failed;
// in the second case that sweep's topology changes are not loaded.
//
// Signal refresh is safe to call concurrently with read queries: the write lock is
// held only for the Ladybug SET operations, not for the ClickHouse read. The
// hold is unmeasured and grows with the loaded node count; a hold over 200ms is
// logged with lock_held.
func (s *Service) RefreshSignals(ctx context.Context, signals SignalSource) error {
	if signals == nil || !s.synced.Load() {
		return nil
	}
	sigByResource, err := signals.SignalsByResource(ctx)
	if err != nil {
		return fmt.Errorf("RefreshSignals: %w", err)
	}
	if sigByResource == nil {
		sigByResource = map[string]NodeSignals{}
	}
	return s.applySignals(ctx, sigByResource)
}

// applySignals is RefreshSignals over an already-loaded rollup. Separate so the
// load-digest gate in SyncFromSources — which has just read the rollup itself — can
// take the cheap path without a second ClickHouse read.
//
// Any label write that fails fails the whole refresh and drops the latched load
// digest: the graph may now hold a mix of old and new signals, so the next sweep
// must not compare against a digest that claims either set.
func (s *Service) applySignals(ctx context.Context, sigByResource map[string]NodeSignals) error {
	logger := log.FromContext(ctx)
	start := time.Now()

	ov, _, nodeIDs := s.lastReach()
	rows := signalRows(sigByResource, ov, nodeIDs)

	// Apply signal column updates on the live DB under the write lock so readers
	// never observe a partially-updated node. The lock is held across one UNWIND SET
	// per label — blocking all withRead callers for their duration. lockElapsed in
	// the log below measures the actual cost. If it exceeds 500ms at scale, consider
	// moving to the off-side-DB pattern used by SyncFromSources (rebuild a new DB
	// with refreshed signals, swap atomically) at the cost of more memory during the
	// rebuild window.
	lockStart := time.Now()
	s.mu.Lock()
	if s.db == nil {
		s.mu.Unlock()
		return ErrLadybugUnavailable
	}
	wc, err := s.db.newWriteConn()
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("RefreshSignals: write conn: %w", err)
	}
	// One UNWIND per label that carries signal columns, derived from the label set
	// rather than hardcoded: a label missing here (e.g. :K8sWorkload or :Package)
	// would keep serving whatever the last full rebuild wrote instead of the
	// refreshed values — the same class of omission bfsScoreLabels guards against.
	var writeErrs []error
	for _, label := range signalRefreshLabels() {
		if _, uErr := unwindInsert(wc, signalRefreshQuery(label), rows); uErr != nil {
			writeErrs = append(writeErrs, fmt.Errorf("%s: %w", label, uErr))
		}
	}
	wc.Close()
	lockElapsed := time.Since(lockStart)
	s.mu.Unlock()
	if lockElapsed > 200*time.Millisecond {
		logger.Warn().Dur("lock_held", lockElapsed).Msg("graphstore: RefreshSignals write lock held longer than expected")
	}
	if len(writeErrs) > 0 {
		s.rebaseSignalsDigest(0, false)
		return fmt.Errorf("RefreshSignals: label write: %w", errors.Join(writeErrs...))
	}
	s.rebaseSignalsDigest(signalsDigest(sigByResource), true)

	// Refresh caches outside the write lock — new entries from the updated graph.
	// Topology (and thus reach) is unchanged here, so prewarmSignalCache overlays
	// the reach map stashed by the last topology build rather than the poisoned
	// zero-value InternetHops from the signal rollup.
	s.prewarmSignalCache(sigByResource)

	logger.Info().
		Dur("elapsed", time.Since(start)).
		Int("signals", len(sigByResource)).
		Int("rows", len(rows)).
		Msg("graphstore: signals refreshed (no topology rebuild)")
	return nil
}

// signalRows builds the UNWIND rows for a signal refresh: one per rollup entry,
// plus a zero row for every loaded node the rollup no longer names.
//
// The zero rows are what clears a resource whose findings all resolved. The rollup
// only carries resources with open findings, so without them an UNWIND ... MATCH
// ... SET never touches that node and it keeps has_kev/exploitable/max_score from
// its last finding — while prewarmSignalCache, which zeroes every absent node,
// tells enrich the opposite. A full rebuild loads the same node with NodeSignals{},
// so this is also what keeps the cheap path equal to a rebuild.
//
// exposed and internet_hops are topology-derived and are NOT written here — a
// signal refresh has no edges, so the rollup carries their zero values and
// writing them would assert "not exposed / not reachable" for everything.
// toxic_combo is ALSO topology-derived (exposed && privesc_count > 0); it is
// recomputed from the exposure set stashed by the last topology build.
func signalRows(sigByResource map[string]NodeSignals, ov reachOverlay, nodeIDs []string) []map[string]any {
	rows := make([]map[string]any, 0, len(sigByResource)+len(nodeIDs))
	for id, sig := range sigByResource {
		rows = append(rows, signalRow(id, sig, ov.exposed[id]))
	}
	for _, id := range nodeIDs {
		if _, ok := sigByResource[id]; ok {
			continue
		}
		rows = append(rows, signalRow(id, NodeSignals{}, ov.exposed[id]))
	}
	return rows
}

func signalRow(id string, sig NodeSignals, exposed bool) map[string]any {
	// epss_score is only meaningful alongside a CVE — appendNodeValues zeroes it
	// the same way on a full load, and signalsDigest hashes it the same way.
	epss := float64(0)
	if sig.CveID != "" {
		epss = sig.EPSSScore
	}
	return map[string]any{
		"id":            id,
		"has_kev":       boolToInt32(sig.HasKEV),
		"exploitable":   boolToInt32(sig.Exploitable),
		"toxic_combo":   boolToInt32(exposed && sig.PrivescCount > 0),
		"max_score":     int32(sig.MaxScore),     //nolint:gosec
		"privesc_count": int32(sig.PrivescCount), //nolint:gosec
		// Package's `score` column holds sig.MaxScore, NOT asset.RiskScore — see
		// signalRefreshCols. cve_id/epss_score are Package-only.
		"score":      int32(sig.MaxScore), //nolint:gosec
		"cve_id":     sig.CveID,
		"epss_score": epss,
	}
}

// rebaseSignalsDigest keeps the latched load digest truthful after a signal write.
// RefreshSignals writes signals outside SyncFromSources, so without this the
// latched Signals half would still describe the PREVIOUS rollup: a later sweep
// whose rollup reverted to it would match, take the no-op path, and keep serving
// the refreshed values. On success only the Signals half moves — Topo and Scores
// are copied from *prev, whose latch already carried the scoresApplied proof.
// On failure nothing is latched, so the next sweep rebuilds.
func (s *Service) rebaseSignalsDigest(signals uint64, applied bool) {
	prev := s.lastDigest.Load()
	if prev == nil {
		return
	}
	if !applied {
		s.lastDigest.Store(nil)
		return
	}
	next := *prev
	next.Signals = signals
	s.lastDigest.Store(&next)
}

func boolToInt32(b bool) int32 {
	if b {
		return 1
	}
	return 0
}
