package graphstore

import (
	"fmt"
	"maps"
	"strings"
	"time"
)

// SignalRefreshStats reports the most recent refresh's native row writes and
// time holding the graph write lock. Full builds do not change these counters.
func (s *Service) SignalRefreshStats() (rows int64, lockHeld time.Duration) {
	return s.lastSignalRows.Load(), time.Duration(s.lastSignalLockNS.Load())
}

func (s *Service) resetSignalBaseline(signals map[string]NodeSignals) {
	s.lastSignals = maps.Clone(signals)
	s.signalsDirty = false
}

// canonicalSignal compares only finding-owned columns. Topology fields are
// overlaid by the loader and EPSS is meaningful only alongside a CVE.
func canonicalSignal(sig NodeSignals, label string) NodeSignals {
	sig.Exposed, sig.ToxicCombo, sig.InternetHops = false, false, 0
	if label != NodePackage {
		sig.CveID = ""
	}
	if sig.CveID == "" {
		sig.EPSSScore = 0
	}
	return sig
}

func (s *Service) changedSignalRows(current map[string]NodeSignals, ov reachOverlay) (map[string][]map[string]any, int, error) {
	rows := map[string][]map[string]any{}
	index := s.blastAdj.Load()
	if index == nil {
		return nil, 0, fmt.Errorf("signal projection index unavailable")
	}
	count := 0
	add := func(id string, force bool) {
		meta, exists := index.meta[id]
		if !exists {
			return
		}
		label := NodeLabelFor(meta.typ)
		if len(signalRefreshCols[label]) == 0 {
			return
		}
		if !force && canonicalSignal(s.lastSignals[id], label) == canonicalSignal(current[id], label) {
			return
		}
		rows[label] = append(rows[label], signalRow(id, current[id], ov.exposed[id]))
		count++
	}
	if s.signalsDirty {
		// A previous write may have changed any node before failing. Reconcile
		// every loaded signal-bearing node, including zeros, before trusting it.
		for id := range index.meta {
			add(id, true)
		}
	} else {
		for id := range current {
			add(id, false)
		}
		for id := range s.lastSignals {
			if _, ok := current[id]; !ok {
				add(id, false)
			}
		}
	}
	return rows, count, nil
}

// Updates the same cache values as prewarmSignalCache without evicting and
// re-allocating every unaffected node. The mutation writer serializes snapshots,
// topology swaps, and this baseline; readers keep using sync.Map.
func (s *Service) refreshSignalCache(current map[string]NodeSignals) {
	ov, complete, _ := s.lastReach()
	notReached := ReachNone
	if !complete {
		notReached = ReachUnknown
	}
	index := s.blastAdj.Load()
	update := func(id string, sig NodeSignals) {
		merged := ov.signalsFor(id, sig, notReached)
		if strings.HasPrefix(id, "pkg:") {
			merged.InternetHops = ReachUnknown
		}
		s.nodeSignalsCache.Store(id, merged)
	}
	for id, sig := range current {
		if old, ok := s.lastSignals[id]; !ok || old != sig {
			update(id, sig)
		}
	}
	for id := range s.lastSignals {
		if _, ok := current[id]; ok {
			continue
		}
		if index != nil {
			if _, loaded := index.meta[id]; loaded {
				update(id, NodeSignals{})
				continue
			}
		}
		s.nodeSignalsCache.Delete(id)
	}
	s.packageSeeds.Store(kevPackageSeeds(current))
}
