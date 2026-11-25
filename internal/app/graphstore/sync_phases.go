package graphstore

// sync_phases.go — per-phase attribution of a full Ladybug rebuild.
//
// graph_ladybug_rebuild_duration_seconds times the whole of SyncFromSources,
// which cannot answer the question that matters when deciding what to optimize:
// WHICH phase costs the time. Log lines aren't a substitute either: at high log
// volume, retention may not span many sweeps, so a phase visible only in a log
// line can't be compared across sweeps. Each phase needs its own durable metric.

import (
	"time"

	"github.com/rs/zerolog"
)

// Rebuild phase names. Every phase of the full path is named and every name is
// marked: TestEveryDeclaredPhaseIsMarked pins that a declared phase is actually
// recorded, and warnIfUnattributed catches the other direction — work on the path
// that no phase claims.
const (
	phaseLoad     = "load"     // concurrent ClickHouse read: assets, edges, signal rollup
	phaseFilter   = "filter"   // filterLadybugAssets
	phaseReach    = "reach"    // newReachOverlay: exposure set + attacker-movement BFS
	phaseDigest   = "digest"   // computeLoadDigest (the load-digest gate's pre-pass)
	phaseCopy     = "copy"     // openAndInit + bulkSyncCopy (CSV generation + COPY)
	phaseBFS      = "bfs"      // propagateRisk: in-memory boost + the per-label writes
	phaseSwap     = "swap"     // graph swap, cache prewarm, score stash
	phaseSnapshot = "snapshot" // WriteSnapshot (gob+gzip to the PVC)
)

// syncPhases accumulates the wall time of each rebuild phase, reports each to the
// SyncRecorder and folds them all into one log event.
type syncPhases struct {
	rec   SyncRecorder
	clock func() time.Time // time.Now; a test injects a fake
	last  time.Time
	// order preserves the sequence phases were marked in, so the log line reads as
	// the timeline it is rather than a randomised map.
	order []string
	dur   map[string]time.Duration
}

func newSyncPhases(rec SyncRecorder, start time.Time) *syncPhases {
	return &syncPhases{rec: rec, clock: time.Now, last: start, dur: map[string]time.Duration{}}
}

// mark closes the phase named by name, attributing to it everything since the
// previous mark. Marking the same name twice accumulates rather than overwriting —
// a phase entered on two branches must not report only its last visit.
func (p *syncPhases) mark(name string) {
	if p == nil {
		return
	}
	now := p.clock()
	d := now.Sub(p.last)
	p.last = now
	if _, seen := p.dur[name]; !seen {
		p.order = append(p.order, name)
	}
	p.dur[name] += d
	if p.rec != nil {
		p.rec.ObserveLadybugPhase(name, d.Seconds())
	}
}

// logTo attaches every phase as its own duration field, in timeline order.
func (p *syncPhases) logTo(e *zerolog.Event) *zerolog.Event {
	if p == nil {
		return e
	}
	for _, name := range p.order {
		e = e.Dur("phase_"+name, p.dur[name])
	}
	return e
}

// total is the sum of the attributed phases. It is deliberately NOT the caller's
// time.Since(start): the difference between the two is unattributed time, which
// warnIfUnattributed reports.
func (p *syncPhases) total() time.Duration {
	var t time.Duration
	if p == nil {
		return t
	}
	for _, d := range p.dur {
		t += d
	}
	return t
}

// warnIfUnattributed logs when a meaningful slice of the rebuild landed in no phase.
// A silent gap is how a newly-added step becomes invisible, which is the whole
// failure mode this file exists to prevent.
func (p *syncPhases) warnIfUnattributed(logger *zerolog.Logger, elapsed time.Duration) {
	if p == nil || logger == nil {
		return
	}
	gap := elapsed - p.total()
	if gap > elapsed/10 && gap > time.Second {
		logger.Warn().Dur("unattributed", gap).Dur("elapsed", elapsed).
			Msg("graphstore: rebuild time is not fully attributed to phases — a step is unmeasured")
	}
}
