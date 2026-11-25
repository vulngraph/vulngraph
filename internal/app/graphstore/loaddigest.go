package graphstore

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sort"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// loadDigest is a content fingerprint of everything a Ladybug rebuild loads, split so
// the cheap paths can be told apart:
//
//	Topo unchanged  => the rebuilt graph would be identical in every column that is
//	                   not refreshable in place: structure, traversal, and every
//	                   non-score, non-signal property. Only the signal columns
//	                   (applySignals) and the risk-score columns (refreshScores)
//	                   could possibly differ, and both have an in-place writer.
//	all unchanged   => the rebuild is a provable no-op.
//
// Scores is the asset RiskScore half, deliberately kept OUT of Topo: RiskScore
// is rewritten between sweeps by construction (multiple writers, last-writer
// oscillation), so folding it into Topo would make the gate fire essentially
// never. RiskScore IS a BFS input, so a Scores change still can't be ignored —
// it takes the refreshScores path, which re-runs the in-memory BFS and
// rewrites the score column in place. A RiskScore flip that changes graph
// MEMBERSHIP (filterLadybugAssets keeps score>0 assets) still lands in Topo,
// because the digest is computed over the post-filter slice.
//
// A simple "bump a counter after every sweep" version signal doesn't work
// here: correlate sweeps happen far more often than the load set actually
// changes, so an unconditional bump makes every rebuild a full one, and
// producers re-stamp every live edge every sweep, so a written-edge count
// isn't a change signal either. Content hashing is what makes the no-op path
// real.
type loadDigest struct {
	Topo    uint64
	Scores  uint64
	Signals uint64
}

// mix64 avalanches (splitmix64 finalizer) every per-row hash before the
// wrapping-add combine. FNV is byte-linear: two inputs differing only in one
// trailing byte have hash difference k·prime, so two independent trailing-byte
// changes can cancel under addition — observed in a unit fixture, not
// theoretical. Avalanching destroys the linear structure, so cancellation
// needs a real 2^-64 collision.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	x ^= x >> 31
	return x
}

// riskScoreColIdx locates, per label whose `score` column holds asset.RiskScore
// (bfsScoreLabels), the position of that column in the loader's value order. Derived
// from nodeCSVCols — the same authority appendNodeValues is pinned against — so the
// skip cannot drift from the loader. Package is absent by construction: its score
// column holds sig.MaxScore, a finding severity that belongs to the signals half
// (and is zero under the nil-signals digest pass anyway).
// TestRiskScoreColIdxMatchesLoader pins position and coverage.
var riskScoreColIdx = func() map[string]int {
	m := make(map[string]int, len(bfsScoreLabels))
	for _, label := range bfsScoreLabels {
		for i, c := range nodeCSVCols[label] {
			if c == "score" {
				m[label] = i
				break
			}
		}
	}
	return m
}()

// computeLoadDigest fingerprints the load set. It must be called with the same values
// bulkSyncCopy will receive — in particular the POST-filterLadybugAssets asset slice,
// which drops a large share of assets and depends on the edge set.
//
// The topology half is derived by running streamNodeRows with NIL signals. That is the
// single authority on what actually gets loaded (it applies the exposure map and the
// reach degradation), so the digest cannot drift from the loader the way a re-derived
// copy would. With nil signals every signal column emits its zero value, which is
// exactly what keeps them out of the topology half. Edges are NOT covered by
// streamNodeRows (rel rows go through writeRelCSV), so they contribute separately.
//
// SchemaVersion is mixed in so a schema bump with unchanged content cannot take a
// cheap path.
func computeLoadDigest(
	assets []asset.Asset,
	edges []asset.Edge,
	ov reachOverlay,
	sigByResource map[string]NodeSignals,
	reachComplete bool,
) (loadDigest, error) {
	var topo uint64
	var nodeRows uint64
	var scores uint64
	var scoreRows uint64

	// Order independence is mandatory: ClickHouse read order is not stable
	// across reads, so a digest over a stream in stream order would change
	// every sweep and the gate would never fire.
	//
	// Combined by WRAPPING ADDITION rather than the sort-then-join used by
	// asset.ConnectorFingerprint — same order-independence property, but O(n)
	// and allocation-free at this scale, where sorting would mean building and
	// sorting well over a million strings per sweep. NOT xor, which cancels
	// duplicate rows. The row count is mixed in at the end so additive
	// collisions (and any cancellation) cannot hide a changed row count.
	err := streamNodeRows(assets, ov, nil, reachComplete, map[string]string{},
		func(label, id string, vals []any) error {
			riskIdx, hasRisk := riskScoreColIdx[label]
			h := fnv.New64a()
			_, _ = h.Write([]byte(label))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write([]byte(id))
			for i, v := range vals {
				// The asset RiskScore column is folded into the Scores half, not
				// Topo — it is rewritten between sweeps by construction, and hashing
				// it here is the exact bug that kept the gate from ever firing.
				if hasRisk && i == riskIdx {
					sh := fnv.New64a()
					_, _ = sh.Write([]byte(id))
					_, _ = sh.Write([]byte{0})
					_, _ = fmt.Fprintf(sh, "%v", v)
					scores += mix64(sh.Sum64())
					scoreRows++
					continue
				}
				_, _ = h.Write([]byte{0})
				// %v over the loader's own values: they are scalars (string, int32,
				// float64, bool) written to CSV, so this is stable and total.
				_, _ = fmt.Fprintf(h, "%v", v)
			}
			topo += mix64(h.Sum64())
			nodeRows++
			return nil
		})
	if err != nil {
		return loadDigest{}, fmt.Errorf("computeLoadDigest: node rows: %w", err)
	}

	for i := range edges {
		topo += edgeDigest(&edges[i])
	}

	// Mix in the shapes and the schema. Distinct multipliers so a row moving between
	// the node and edge sets cannot cancel out.
	topo += nodeRows * 0x9E3779B97F4A7C15
	topo += uint64(len(edges)) * 0xC2B2AE3D27D4EB4F
	topo += schemaAndReachDigest(reachComplete)
	scores += scoreRows * 0xA0761D6478BD642F

	return loadDigest{Topo: topo, Scores: scores, Signals: signalsDigest(sigByResource)}, nil
}

// edgeDigest fingerprints one edge including its properties. Properties are iterated
// in sorted key order — Go map iteration is randomised, so anything else would make
// the digest unstable for an unchanged edge.
func edgeDigest(e *asset.Edge) uint64 {
	h := fnv.New64a()
	for _, s := range []string{e.SrcID, e.SrcType, e.DstID, e.DstType, e.EdgeType} {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	if len(e.Properties) > 0 {
		keys := make([]string, 0, len(e.Properties))
		for k := range e.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = h.Write([]byte(k))
			_, _ = h.Write([]byte{1})
			_, _ = h.Write([]byte(e.Properties[k]))
			_, _ = h.Write([]byte{0})
		}
	}
	return mix64(h.Sum64())
}

// schemaAndReachDigest folds SchemaVersion and reachComplete into the topology half.
// reachComplete belongs there because it changes the node rows (internet_hops degrades
// to ReachUnknown when the edge set was truncated).
func schemaAndReachDigest(reachComplete bool) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(SchemaVersion))
	if reachComplete {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	return mix64(h.Sum64())
}

// signalsDigest fingerprints the finding rollup — and ONLY the fields a signal-only
// refresh can apply (signalRefreshCols). Exposed, ToxicCombo and InternetHops are
// deliberately absent: they are topology-derived, no SignalSource populates them, and
// including them would make the signals half depend on values that are always zero
// here.
func signalsDigest(sigByResource map[string]NodeSignals) uint64 {
	var sum uint64
	for id, s := range sigByResource {
		h := fnv.New64a()
		_, _ = h.Write([]byte(id))
		var flags byte
		if s.HasKEV {
			flags |= 1
		}
		if s.Exploitable {
			flags |= 2
		}
		_, _ = h.Write([]byte{0, flags})
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], uint64(int64(s.MaxScore)))
		_, _ = h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], uint64(int64(s.PrivescCount)))
		_, _ = h.Write(buf[:])
		_, _ = h.Write([]byte(s.CveID))
		// epss is only meaningful alongside a CveID — appendNodeValues (node_rows.go)
		// zeroes it the same way when loading the row. Hashing the raw EPSSScore
		// unconditionally here would let a stale/leftover score behind an empty
		// CveID mismatch what actually got loaded, an asymmetry between "what the
		// digest hashes" and "what the loader writes" that the load digest exists to forbid.
		epss := float64(0)
		if s.CveID != "" {
			epss = s.EPSSScore
		}
		_, _ = fmt.Fprintf(h, "|%g", epss)
		sum += mix64(h.Sum64())
	}
	// Count mixed in for the same reason as the node rows: a removed resource must
	// change the digest even if the remaining hashes happen to sum the same.
	return sum + uint64(len(sigByResource))*0xD6E8FEB86659FD93
}

// Sync path names, reported through LastSyncPath and the sync metric.
// "signals" covers every in-place refresh: the signal-column UNWIND
// (applySignals), the risk-score rewrite (refreshScores), or both.
const (
	syncPathFull    = "full"
	syncPathSignals = "signals"
	syncPathNoop    = "noop"
)

// SyncRecorder observes which path a sync took and how long it ran. *obs.Metrics
// satisfies it — declared here rather than imported so graphstore keeps no infra
// dependency, and wired from cmd/graph.
//
// Recorded INSIDE the service, not in the caller's closure: an observation in the
// worker's ladybug-sync closure would never see a serve-pod rebuild, even though
// both pods expose /metrics.
type SyncRecorder interface {
	ObserveLadybugSync(path string, seconds float64)
	// ObserveLadybugPhase attributes one phase of a full rebuild. Without it the
	// only rebuild signal is the total, which makes tuning a guessing game
	// since the log line that would carry the decomposition rotates away.
	ObserveLadybugPhase(phase string, seconds float64)
}

// WithSyncMetrics wires sync-path reporting. Optional; nil disables it.
func (s *Service) WithSyncMetrics(r SyncRecorder) *Service {
	s.syncRecorder = r
	return s
}

// recordSyncPath stores the path for LastSyncPath and reports it, if wired.
func (s *Service) recordSyncPath(path string, elapsed time.Duration) {
	s.lastSyncPath.Store(path)
	if s.syncRecorder != nil {
		s.syncRecorder.ObserveLadybugSync(path, elapsed.Seconds())
	}
}

// LastSyncPath reports which path the most recent sync took ("full", "signals",
// "noop"), or "" before the first sync. Exported so a test can assert the gate fired
// without reaching into metrics.
func (s *Service) LastSyncPath() string {
	v, _ := s.lastSyncPath.Load().(string)
	return v
}
