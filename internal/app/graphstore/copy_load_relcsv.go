package graphstore

// The streaming rel-CSV writer used by copy_load.go.

import (
	"encoding/csv"
	"os"
	"path/filepath"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// relCSVSet holds one lazily-created CSV writer per rel table for a streaming edge
// pass, mirroring nodeCSVSet on the node side.
//
// It exists to avoid the biggest transient in the rebuild: materialising one
// map[string]any per loadable edge (buildEdgeRows) and holding them all while
// the asset slice, the edge slice and the nodeLabel map are also live.
//
// Correctness rests on TestEdgeRowKeysMatchRelSpec, which proves over every
// rel-table routing that a row's keys and values are exactly {"src","dst"}
// plus the spec's rowKeys read from Properties (with "via" falling back
// through origin/matched). That is what lets this write CSV records straight
// from the edge, in spec column order, with no map in between — provably the
// same bytes buildEdgeRows + writeRelCSV produced.
type relCSVSet struct {
	dir     string
	writers map[string]*relCSVWriter
}

type relCSVWriter struct {
	f     *os.File
	w     *csv.Writer
	spec  relEndpoints
	rec   []string
	path  string
	stats relLoadStats
}

func newRelCSVSet(dir string) *relCSVSet {
	return &relCSVSet{dir: dir, writers: map[string]*relCSVWriter{}}
}

// writerFor returns the writer for a rel table, creating the file and header on first
// use so a rel table with no surviving rows never produces a file to COPY.
func (s *relCSVSet) writerFor(relTable string) (*relCSVWriter, error) {
	if rw, ok := s.writers[relTable]; ok {
		return rw, nil
	}
	spec := ladybugRelSpec[relTable]
	path := filepath.Join(s.dir, "rel_"+relTable+".csv")
	f, err := os.Create(path) //nolint:gosec // path is built from a temp dir and a rel table name
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)
	w.Comma = '|' // pipe delimiter avoids Ladybug's quoted-comma parser bug
	header := append([]string{"from", "to"}, propCols(spec.prop)...)
	if err := w.Write(header); err != nil {
		_ = f.Close()
		return nil, err
	}
	rw := &relCSVWriter{
		f: f, w: w, spec: spec, path: path,
		rec:   make([]string, len(header)),
		stats: relLoadStats{byType: map[string]edgeTypeLoad{}},
	}
	s.writers[relTable] = rw
	return rw, nil
}

// add routes one edge and writes its row, or records why it was dropped. The endpoint
// decision and its mismatch-vs-absent precedence are shared with writeRelCSV via
// classifyRelEndpoints so the two paths can never disagree about what loads.
//
// verifiedExpired is the caller's bulk asset-table check (see bulkSyncCopy) — the
// set of missing-endpoint ids CONFIRMED to be an aged-out ephemeral asset row,
// not merely declared ephemeral by the edge's own producer-written type.
func (s *relCSVSet) add(e *asset.Edge, nodeLabel map[string]string, verifiedExpired map[string]bool) error {
	relTable := relTableForEdge(*e)
	if relTable == "" {
		return nil // no UNWIND template, or a rel gated out of Ladybug
	}
	rw, err := s.writerFor(relTable)
	if err != nil {
		return err
	}
	load := rw.stats.byType[e.EdgeType]
	if out := classifyRelEndpoints(rw.spec, e.SrcID, e.DstID, verifiedExpired, nodeLabel); out != relRowLoads {
		switch out {
		case relRowLabelMismatch:
			rw.stats.labelMismatch++
			load.labelMismatch++
		case relRowEndpointExpired:
			rw.stats.endpointExpired++
			load.endpointExpired++
		default: // relRowEndpointAbsent
			rw.stats.endpointAbsent++
			load.endpointAbsent++
		}
		rw.stats.byType[e.EdgeType] = load
		return nil
	}
	rw.rec[0], rw.rec[1] = e.SrcID, e.DstID
	for j, p := range rw.spec.prop {
		rw.rec[2+j] = formatCSVValue(edgeRowValue(*e, p.rowKey))
	}
	if err := rw.w.Write(rw.rec); err != nil {
		return err
	}
	rw.stats.written++
	load.loaded++
	rw.stats.byType[e.EdgeType] = load
	return nil
}

// closeAll flushes and closes every writer. It must run before any COPY, since COPY
// reads the file by path. Returns the first error but always attempts every close, so
// a mid-set failure cannot leak file descriptors for the rest of the rebuild.
func (s *relCSVSet) closeAll() error {
	var firstErr error
	for _, rw := range s.writers {
		rw.w.Flush()
		if err := rw.w.Error(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := rw.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// relRowOutcome is what became of one candidate rel row at load time.
type relRowOutcome uint8

const (
	relRowLoads relRowOutcome = iota
	// relRowLabelMismatch — the endpoint IS in the graph, under a different label
	// than the rel declares. Always a producer/rel-label bug.
	relRowLabelMismatch
	// relRowEndpointExpired — the endpoint is absent AND the caller's asset-table
	// check (verifiedExpired) confirmed it is an aged-out ephemeral resource, so
	// the resource no longer exists and this row is a corpse, not a loss. Verified,
	// not merely declared: the edge's own src_type/dst_type never decides this on
	// its own (see classifyRelEndpoints).
	relRowEndpointExpired
	// relRowEndpointAbsent — the endpoint is absent and nothing explains it: a
	// dangling reference to an id the platform does not hold.
	relRowEndpointAbsent
)

// classifyRelEndpoints decides whether a candidate rel row can load, and if not
// which of the three drop reasons applies.
//
// COPY aborts on an unresolvable primary key, so a row whose endpoint is missing or
// carries a different label than the rel declares must be skipped rather than written.
// Mismatch wins when both ends fail: it is the actionable one — a mismatch is ALWAYS a
// producer/rel-label bug.
//
// The absent case is then split by whether the caller VERIFIED the missing
// endpoint against the asset table (verifiedExpired), not by the edge row's own
// declared type. That split is not cosmetic: a large share of "endpoint absent"
// rows are edges whose missing endpoint is a k8s_pod (or k8s_job) that died
// beyond the asset liveness window (asset.EphemeralLivenessCond) while the edge
// itself is still inside its own, longer freshness window — the producer
// re-stamps an edge right up to the moment its pod crosses the liveness cut.
// That is not recoverable loss: the endpoint is genuinely gone, so dropping the
// row is correct. Counting it as "absent" alongside a genuine dangling
// reference makes the number unusable — nothing can then tell ordinary pod
// churn from an exposure chain actually losing its last hop.
//
// verifiedExpired is populated by a single bulk ClickHouse check
// (asset.VerifyDepartedAssets) over missing endpoints of every type — never by trusting the declared type in
// isolation. A producer that mislabels a type, or a future regression that drops
// a live ephemeral asset from the load for an unrelated reason, can no longer
// force "expired" on its own: verifiedExpired only says true for an id that
// actually has an asset row and actually fails EphemeralLivenessCond.
func classifyRelEndpoints(spec relEndpoints, src, dst string, verifiedExpired map[string]bool, nodeLabel map[string]string) relRowOutcome {
	srcLabel, srcLoaded := nodeLabel[src]
	dstLabel, dstLoaded := nodeLabel[dst]
	if srcLabel == spec.from && dstLabel == spec.to {
		return relRowLoads
	}
	if (srcLoaded && srcLabel != spec.from) || (dstLoaded && dstLabel != spec.to) {
		return relRowLabelMismatch
	}
	if (!srcLoaded && verifiedExpired[src]) || (!dstLoaded && verifiedExpired[dst]) {
		return relRowEndpointExpired
	}
	return relRowEndpointAbsent
}
