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
	s.writerMu.Lock()
	defer s.writerMu.Unlock()
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

	ov, _, _ := s.lastReach()
	rows, count, err := s.changedSignalRows(sigByResource, ov)
	if err != nil {
		s.signalsDirty = true
		s.rebaseSignalsDigest(0, false)
		return fmt.Errorf("RefreshSignals: %w", err)
	}
	s.lastSignalRows.Store(int64(count))
	s.lastSignalLockNS.Store(0)

	// Prepare deltas before taking the read-blocking lock, then write only the
	// changed nodes to their actual labels. writerMu keeps this baseline stable.
	s.mu.Lock()
	lockStart := time.Now()
	if s.db == nil {
		s.mu.Unlock()
		return ErrLadybugUnavailable
	}
	var writeErrs []error
	if count > 0 {
		wc, err := s.db.newWriteConn()
		if err != nil {
			writeErrs = append(writeErrs, err)
		} else {
			for _, label := range signalRefreshLabels() {
				if len(rows[label]) == 0 {
					continue
				}
				if err := ctx.Err(); err != nil {
					writeErrs = append(writeErrs, err)
					break
				}
				if _, uErr := unwindInsert(wc, signalRefreshQuery(label), rows[label]); uErr != nil {
					writeErrs = append(writeErrs, fmt.Errorf("%s: %w", label, uErr))
				}
			}
			wc.Close()
		}
	}
	lockElapsed := time.Since(lockStart)
	s.mu.Unlock()
	s.lastSignalLockNS.Store(int64(lockElapsed))
	if lockElapsed > 200*time.Millisecond {
		logger.Warn().Dur("lock_held", lockElapsed).Msg("graphstore: RefreshSignals write lock held longer than expected")
	}
	if len(writeErrs) > 0 {
		s.signalsDirty = true
		s.rebaseSignalsDigest(0, false)
		return fmt.Errorf("RefreshSignals: label write: %w", errors.Join(writeErrs...))
	}
	s.rebaseSignalsDigest(signalsDigest(sigByResource), true)

	// Refresh caches outside the write lock — new entries from the updated graph.
	// Topology (and thus reach) is unchanged here, so prewarmSignalCache overlays
	// the reach map stashed by the last topology build rather than the poisoned
	// zero-value InternetHops from the signal rollup.
	if s.signalsDirty {
		s.prewarmSignalCache(sigByResource)
	} else {
		s.refreshSignalCache(sigByResource)
	}
	s.resetSignalBaseline(sigByResource)

	logger.Info().
		Dur("elapsed", time.Since(start)).
		Int("signals", len(sigByResource)).
		Int("rows", count).
		Msg("graphstore: signals refreshed (no topology rebuild)")
	return nil
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
