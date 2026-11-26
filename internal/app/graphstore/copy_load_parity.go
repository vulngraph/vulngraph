package graphstore

import (
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/internal/obs"
)

// edgeTypeLoad is one edge_type's fetch→load accounting for a single build: how
// many rows came out of ClickHouse and what became of each of them.
//
// This is the standing per-edge-type parity signal: it compares "fresh in
// ClickHouse" against "loaded in Ladybug" at the granularity where the two can
// actually diverge. Aggregate counters alone cannot — a type losing 100% of
// its rows is invisible inside a six-figure total.
type edgeTypeLoad struct {
	fetched        int // rows in the edge slice handed to this build
	loaded         int // rel rows actually COPY'd into Ladybug
	labelMismatch  int // endpoint node IS in Ladybug, under a different label — a bug
	endpointAbsent int // endpoint node is not in the inventory at all — dangling
	// endpointExpired is the absent-endpoint rows explained by ephemeral expiry:
	// the missing endpoint's declared type is one of asset.EphemeralTypes, so the
	// resource is GONE and its edge is a corpse the freshness window has
	// not caught up with yet. See relRowEndpointExpired.
	endpointExpired int
}

// notLoaded is the residue: rows whose rel table is gated out of Ladybug entirely
// (declared bfs_only in the registry) or whose edge_type has no rel mapping.
func (l edgeTypeLoad) notLoaded() int {
	return l.fetched - l.loaded - l.labelMismatch - l.endpointAbsent - l.endpointExpired
}

// overDanglingBudget reports whether this type's GENUINELY-dangling share
// exceeds the budget the registry declares for it. Expired endpoints are
// excluded by construction (they are a different field) — without that split,
// normal dead-pod expiry noise swamps the signal, making any threshold over
// the combined number either permanently firing or useless, and hiding a real
// regression (a producer losing most of an edge type's rows) inside it.
func (l edgeTypeLoad) overDanglingBudget(budget float64) bool {
	if l.fetched < graphschema.DanglingBudgetMinRows {
		return false
	}
	return float64(l.endpointAbsent) > budget*float64(l.fetched)
}

// expiredShare is this type's endpoint_expired rows as a fraction of fetched,
// or 0 for a type with nothing fetched (there is nothing to have a share of,
// and reporting 0 rather than NaN keeps the step-change comparison well-defined
// for a type that goes from unfetched to fetched, or back).
func (l edgeTypeLoad) expiredShare() float64 {
	if l.fetched == 0 {
		return 0
	}
	return float64(l.endpointExpired) / float64(l.fetched)
}

// copyStats summarises one bulk load: how many edges entered Ladybug vs how many
// were dropped at each gate. Exported to /metrics so silent drops are visible —
// the ladybugRelSpec gate discarded whole edge classes for months with no signal.
type copyStats struct {
	edgesLoaded          int // rel rows actually COPY'd into Ladybug
	droppedNotLoaded     int // edge_type unmapped, or its rel table not Loaded (bfs_only)
	droppedEndpointMiss  int // FROM/TO node genuinely absent from the inventory — dangling
	droppedEndpointGone  int // FROM/TO node is an expired ephemeral resource — a corpse edge
	droppedLabelMismatch int // FROM/TO node present under a DIFFERENT label — the bug class
	droppedUnsafeID      int // node whose id holds a COPY delimiter/line break; not loaded
	// reachRelsMismatched names the Reach rel tables that lost rows to a LABEL
	// MISMATCH, with the row count. See droppedSecurityEdges.
	reachRelsMismatched map[string]int
	// byType is the per-edge_type parity accounting feeding the obs gauge.
	byType map[string]edgeTypeLoad
	// verifiedExpiry is true when this build ran the ClickHouse verification
	// pass (verifyExpired != nil), i.e. byType's endpointExpired/endpointAbsent
	// split is trustworthy rather than degraded to "everything absent". See
	// expiredShareStepChanges.
	verifiedExpiry bool
	// nodeTableRows is each node table's row count after the load, read back
	// from the engine (node_table_stats.go).
	nodeTableRows map[string]int64
}

// droppedSecurityEdges reports whether this build discarded rows from a rel
// table the attack-path queries depend on BECAUSE OF A LABEL MISMATCH: a
// producer emits an edge whose endpoint type has been promoted off the label
// its rel table declares, the loader's typed MATCH finds nothing, and Ladybug
// drops the row with no error, no warning and no metric.
//
// It counts ONLY label mismatches, deliberately excluding genuinely dangling
// endpoints (e.g. AWS cross-account root principals that are not assets and
// never will be) — those are permanent, irreducible reality, and folding them
// in would make the alarm fire on every build regardless of whether a real
// mismatch is present, which is not a detector.
//
// What it does NOT invalidate is internet_hops: internetHops() runs in Go over
// the full fetched edge slice before COPY, so reach is computed on complete
// data and the existing reachComplete flag (ClickHouse fetch truncation) still
// covers it. What it DOES invalidate is anything read back OUT of Ladybug — blast
// radius (blastRadiusCount), Cypher traversal, expand, named queries. Blast
// radius gates must_fix (`blast >= mustFixBlastThreshold`).
func (s copyStats) droppedSecurityEdges() bool { return len(s.reachRelsMismatched) > 0 }

// danglingOverBudget names the edge types whose genuinely-dangling drop share
// exceeded the budget graphschema declares, mapped to the dropped row count.
//
// This is the second runtime detector, covering the half droppedSecurityEdges
// cannot see. A label mismatch is a bug the loader can prove; an endpoint that
// is not in the inventory AT ALL looks identical whether it is a permanent
// reality (e.g. an AWS cross-account principal) or an asset type the platform
// wrongly excluded from the graph. The registry is where that difference is
// declared, per type, with evidence.
//
// Requires s.verifiedExpiry, for the same reason expiredShareStepChanges does:
// an unverified build — LoadFromSnapshot's fast-boot path, verifyExpired ==
// nil — has no verified map to consult, so classifyRelEndpoints counts every
// expired-ephemeral endpoint as endpointAbsent instead, reproducing the exact
// pre-split noise floor this budget exists to filter out. Without this guard,
// every worker restart would trip this alarm for a build whose classification
// was never trustworthy. A verified build that is genuinely over budget is
// unaffected — the guard only ever suppresses a build that cannot yet know the
// true answer, never one that already does.
//
// The suppression is not reliably bounded to the boot window: when
// LoadFromSnapshot's warm-start follow-up sync finds ClickHouse still matches
// the snapshot, it takes syncPathNoop and never calls bulkSyncCopy at all, so
// verifiedExpiry can stay false for as long as the topology digest keeps
// matching. This is accepted, not a bug: the seed that causes it exists to
// avoid a needless full rebuild on every restart, and this guard can only ever
// suppress a reading that was already unreliable — it never turns a correct
// verdict into a wrong one, only delays a real verdict until the next genuine
// full rebuild.
func (s copyStats) danglingOverBudget() map[string]int {
	if !s.verifiedExpiry {
		return nil
	}
	budgets := graphschema.DanglingBudgets()
	var over map[string]int
	for et, l := range s.byType {
		budget, declared := budgets[et]
		if !declared {
			budget = graphschema.DefaultDanglingBudget
		}
		if l.overDanglingBudget(budget) {
			if over == nil {
				over = map[string]int{}
			}
			over[et] = l.endpointAbsent
		}
	}
	return over
}

// expiredShareStepChanges names the edge types whose endpoint_expired share of
// fetched rows moved, build to build, by more than the ExpiredShareStepBudget
// graphschema declares, mapped to the absolute delta (current share minus
// prev's, signed). prev is the immediately preceding build's stats; a type
// missing from EITHER side (never built, or new this build) is skipped rather
// than treated as a 0→x or x→0 swing, which would page on every process start.
//
// This is the "verified" classification's own reviewable half, exactly as
// danglingOverBudget is for endpointAbsent: a stable population that suddenly
// moves is the signature of a real regression, and nothing upstream of this
// function can tell "pod churn had a busy week" from "the verification query
// stopped seeing live pods" without a human looking — which is what firing on
// the step (not the level) is for.
func (s copyStats) expiredShareStepChanges(prev copyStats) map[string]float64 {
	if !s.verifiedExpiry || !prev.verifiedExpiry {
		return nil
	}
	budgets := graphschema.ExpiredShareStepBudgets()
	var out map[string]float64
	for et, l := range s.byType {
		p, ok := prev.byType[et]
		if !ok || l.fetched < graphschema.ExpiredShareStepBudgetMinRows ||
			p.fetched < graphschema.ExpiredShareStepBudgetMinRows {
			continue
		}
		budget, declared := budgets[et]
		if !declared {
			budget = graphschema.DefaultExpiredShareStepBudget
		}
		delta := l.expiredShare() - p.expiredShare()
		if delta > budget || delta < -budget {
			if out == nil {
				out = map[string]float64{}
			}
			out[et] = delta
		}
	}
	return out
}

// EdgeTypeParity reports, per edge_type, how many rows the last build fetched
// from ClickHouse and what became of each: loaded into Ladybug, dropped because the
// endpoint carries a different node label than the rel declares (always a bug),
// dropped because the endpoint is not in the graph at all (expected attrition),
// or never offered to Ladybug because the rel is gated out (declared bfs_only).
//
// It returns the obs type directly rather than a graphstore mirror of it: the
// two would be field-for-field identical, and a hand-copied parallel struct is
// the same drift this whole change is about. Sorted by edge_type so scrapes are
// stable.
func (s *Service) EdgeTypeParity() []obs.EdgeTypeParityStat {
	st, ok := s.lastLoadStats.Load().(copyStats)
	if !ok {
		return nil
	}
	types := make([]string, 0, len(st.byType))
	for et := range st.byType {
		types = append(types, et)
	}
	sortStrings(types)
	over := st.danglingOverBudget()
	// prev is missing on the process's first build; expiredShareStepChanges
	// already treats a missing prev entry as "skip", so a nil map degrades to
	// "no step changes" rather than every type reading 0→x.
	prev, _ := s.prevLoadStats.Load().(copyStats)
	stepped := st.expiredShareStepChanges(prev)
	out := make([]obs.EdgeTypeParityStat, 0, len(types))
	for _, et := range types {
		l := st.byType[et]
		_, isOver := over[et]
		delta, isStepped := stepped[et]
		out = append(out, obs.EdgeTypeParityStat{
			EdgeType:               et,
			Fetched:                int64(l.fetched),
			Loaded:                 int64(l.loaded),
			LabelMismatch:          int64(l.labelMismatch),
			EndpointAbsent:         int64(l.endpointAbsent),
			EndpointExpired:        int64(l.endpointExpired),
			NotLoaded:              int64(l.notLoaded()),
			OverDanglingBudget:     isOver,
			ExpiredShareStepChange: isStepped,
			ExpiredShareStepDelta:  delta,
		})
	}
	return out
}
