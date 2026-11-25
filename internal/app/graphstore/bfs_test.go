package graphstore

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// One hop: boost = score * (edgeWeight * hopDecay) / bfsBoostScale * 100.
// B(50) reached from A over can_assume (0.8): 50 * (0.8*0.7) = 28 → 28/300*100.
// Edge types are snake_case — the value ClickHouse stores and buildAdjIndex
// indexes (edgeWeight previously expected PascalCase and never matched).
func TestComputeBFSBoost_OneHopDecay(t *testing.T) {
	adj := adjIndex{
		"A": {{neighborID: "B", edgeType: "can_assume"}},
		"B": {{neighborID: "A", edgeType: "can_assume"}},
	}
	got := computeBFSBoost("A", map[string]uint8{"B": 50}, adj)
	require.InDelta(t, 28.0/bfsBoostScale*100, got, 0.001)
}

// TestEdgeWeightCasing pins the contract that broke silently once: BFS edge
// weights key on the snake_case ClickHouse edge_type, NOT the PascalCase Ladybug
// rel name. A PascalCase key must fall back to the 0.5 default; the registry's
// differentiated weights must come through for snake_case keys.
func TestEdgeWeightCasing(t *testing.T) {
	require.Equal(t, 1.0, edgeWeight("exposed_to_internet"))
	require.Equal(t, 0.9, edgeWeight("connected_via_sg"))
	require.Equal(t, 0.8, edgeWeight("can_assume"))
	require.Equal(t, 0.5, edgeWeight("ExposedToInternet"), "PascalCase must not resolve — data is snake_case")
	require.Equal(t, 0.5, edgeWeight("unknown_edge_type"))
}

// Risk propagates THROUGH a zero-score node: B(0) contributes nothing itself
// but is expanded, so C(100) two hops away still raises A — attenuated by both
// hops. Stopping at B (the previous behaviour) cut risk off at every unscored
// intermediate role/SG/subnet.
func TestComputeBFSBoost_ScoreZeroNodeStillPropagates(t *testing.T) {
	adj := adjIndex{
		"A": {{neighborID: "B", edgeType: "can_assume"}},
		"B": {{neighborID: "A", edgeType: "can_assume"}, {neighborID: "C", edgeType: "can_assume"}},
		"C": {{neighborID: "B", edgeType: "can_assume"}},
	}
	got := computeBFSBoost("A", map[string]uint8{"B": 0, "C": 100}, adj)
	hop := edgeWeight("can_assume") * bfsHopDecay
	require.InDelta(t, normaliseBFSBoost(100*hop*hop), got, 1e-9)
	require.Positive(t, got)
}

func TestComputeBFSBoost_EmptyNode(t *testing.T) {
	require.Zero(t, computeBFSBoost("", map[string]uint8{"B": 100}, adjIndex{}))
}

// buildAdjIndex must drop self-loops — BFS ignores them, and they would
// otherwise let a node's own risk propagate back into itself.
func TestBuildAdjIndex_SkipsSelfLoops(t *testing.T) {
	idx := buildAdjIndex([]asset.Edge{{SrcID: "A", DstID: "A", EdgeType: "can_assume"}}, nil)
	require.Empty(t, idx["A"])
}

// TestBFSRiskDoesNotFlowBackwards is the guard for the defect that shipped: the
// adjacency index held BOTH ends of every edge, so risk propagated against the
// direction of the edge. A role that can be assumed raised the principal that
// assumes it, an instance raised the IAM role attached to it, and an account hub
// handed its worst asset's score to every sibling. The post-BFS score feeds
// enrich → must-fix → respond, so backwards risk is automated action
// on an asset nothing can reach.
//
// Built from real asset.Edge values through buildAdjIndex rather than a
// hand-written adjIndex, because a hand-written index IS the thing under test:
// every existing computeBFSBoost test declares its own symmetric adjacency and
// therefore could not see this.
func TestBFSRiskDoesNotFlowBackwards(t *testing.T) {
	// An exposure edge: a k8s service targets a workload, so risk arrives at the
	// workload. The service is upstream and must not be raised by what it fronts.
	exposure := []asset.Edge{{
		SrcID: "svc", SrcType: "k8s_service",
		DstID: "pod", DstType: "k8s_pod",
		EdgeType: "targets",
	}}
	scoreByID := map[string]uint8{"svc": 100, "pod": 100}
	adj := buildAdjIndex(exposure, scoreByID)

	require.Greater(t, computeBFSBoost("pod", scoreByID, adj), 0.0,
		"the targeted workload must take a boost from the service that exposes it")
	require.Zero(t, computeBFSBoost("svc", scoreByID, adj),
		"risk flowed backwards over targets: an exposure edge must not raise its own source")

	// A role→role capability edge is the one shape where BOTH ends are informative,
	// and the registry says so deliberately rather than by default: role-a inherits
	// role-b's PRIVILEGE (owning a gets you b, so a is the remediation target) and
	// role-b inherits role-a's EXPOSURE. Declaring can_assume one-directional, either
	// way, demotes a different set of identities out of the score>=60 band; both
	// directions keep them.
	capability := []asset.Edge{{
		SrcID: "role-a", SrcType: "iam_role",
		DstID: "role-b", DstType: "iam_role",
		EdgeType: "can_assume",
	}}
	scoreByID = map[string]uint8{"role-a": 100, "role-b": 100}
	adj = buildAdjIndex(capability, scoreByID)

	require.Greater(t, computeBFSBoost("role-a", scoreByID, adj), 0.0,
		"the assuming principal must inherit the privilege of the role it can assume — "+
			"risk score is blast radius, and blast radius runs against the direction of attack")
	require.Greater(t, computeBFSBoost("role-b", scoreByID, adj), 0.0,
		"the assumable role must also inherit the exposure of the principal that can assume it — "+
			"dropping this half demotes identities out of the score>=60 band when can_assume is declared reverse")
}

// TestBuildAdjIndexHonoursRegistryDirections derives the expected adjacency for
// EVERY registered edge type from graphschema.DirectionFor, so a direction added
// or changed in the registry cannot silently disagree with the index built from
// it. The three shapes are asserted explicitly: forward indexes under dst only,
// reverse under src only, both under each.
func TestBuildAdjIndexHonoursRegistryDirections(t *testing.T) {
	for _, et := range graphschema.EdgeTypes {
		idx := buildAdjIndex([]asset.Edge{{SrcID: "src", DstID: "dst", EdgeType: et.Type}}, nil)
		dir := graphschema.DirectionFor(et.Type)
		switch dir {
		case graphschema.DirForward:
			require.Equal(t, []adjEntry{{"src", et.Type}}, idx["dst"], "%s: forward must index under dst", et.Type)
			require.Empty(t, idx["src"], "%s: forward must not index under src", et.Type)
		case graphschema.DirReverse:
			require.Equal(t, []adjEntry{{"dst", et.Type}}, idx["src"], "%s: reverse must index under src", et.Type)
			require.Empty(t, idx["dst"], "%s: reverse must not index under dst", et.Type)
		default:
			require.Equal(t, []adjEntry{{"dst", et.Type}}, idx["src"], "%s: both must index under src", et.Type)
			require.Equal(t, []adjEntry{{"src", et.Type}}, idx["dst"], "%s: both must index under dst", et.Type)
		}
	}

	// An edge type no producer has registered keeps the old undirected behaviour:
	// a new producer's edge must over-propagate, not lose a direction in silence.
	idx := buildAdjIndex([]asset.Edge{{SrcID: "src", DstID: "dst", EdgeType: "not_a_registered_type"}}, nil)
	require.Len(t, idx["src"], 1, "an unregistered edge type must fail open to both directions")
	require.Len(t, idx["dst"], 1, "an unregistered edge type must fail open to both directions")
}

// TestBFSScoreLabelsMatchNodeLoader derives, from the node loader itself, which
// labels store asset.RiskScore in their `score` column — and asserts that set is
// exactly bfsScoreLabels.
//
// It is written as a derivation rather than a list because a hardcoded list
// stops being true silently: a label promoted off Asset (as K8sWorkload is)
// carries the same RiskScore-backed `score` column, and a list that misses it
// leaves every such node serving its pre-BFS score.
//
// The distinguishing probe is that RiskScore and MaxScore are given different
// values: Package's score column loads sig.MaxScore, a finding severity rather
// than an asset risk score, so writing a BFS-boosted RiskScore into it would
// manufacture a divergence instead of closing one.
func TestBFSScoreLabelsMatchNodeLoader(t *testing.T) {
	const riskScore, maxScore = 91, 17

	inSet := make(map[string]bool, len(bfsScoreLabels))
	for _, l := range bfsScoreLabels {
		require.Contains(t, nodeCSVCols, l, "bfsScoreLabels names %q, which the node loader does not load", l)
		inSet[l] = true
	}

	for label, cols := range nodeCSVCols {
		scoreIdx := -1
		for i, c := range cols {
			if c == "score" {
				scoreIdx = i
			}
		}
		if scoreIdx < 0 {
			require.False(t, inSet[label], "label %q has no score column but is in bfsScoreLabels", label)
			continue
		}
		a := asset.Asset{ID: "x", Type: "t", RiskScore: riskScore}
		vals := appendNodeValues(nil, label, &a, NodeSignals{MaxScore: maxScore})
		require.Len(t, vals, len(cols), "label %q: appendNodeValues width != nodeCSVCols width", label)

		riskBacked := vals[scoreIdx] == int32(riskScore)
		require.Equal(t, riskBacked, inSet[label],
			"label %q: score column is RiskScore-backed=%v but bfsScoreLabels membership=%v — "+
				"propagateRisk boosts asset.RiskScore, so it must write to exactly the labels "+
				"whose score column holds that quantity",
			label, riskBacked, inSet[label])
	}
}

func TestNormaliseBFSBoost(t *testing.T) {
	require.Equal(t, bfsMaxBoost, normaliseBFSBoost(10_000)) // capped
	require.Zero(t, normaliseBFSBoost(0))
	require.Zero(t, normaliseBFSBoost(-5)) // never negative
	require.InDelta(t, 30.0/bfsBoostScale*100, normaliseBFSBoost(30), 0.001)
}

// TestBFSBoostOrderIndependence is the guard for a non-determinism bug: the
// risk score, which drives enrich → must-fix → respond, was not reproducible.
//
// computeBFSBoost walks at most bfsMaxNodes (20) neighbours and breaks when the
// budget is spent, so adjacency ORDER decides which neighbours contribute. That order
// used to be ClickHouse read order, which loaddigest.go:111 documents as "not stable
// across reads". At scale a few percent of nodes with edges exceed degree 20 and
// hub nodes can be far larger, so their scores flapped between sweeps on
// identical input.
//
// The fixture deliberately exceeds the budget so the truncation is exercised: 30
// neighbours for a 20-node budget. A shuffled edge slice must produce identical
// boosts, and the surviving contributors must be the highest-scoring ones rather than
// whichever arrived first.
//
// The hub is the DESTINATION of its 30 has_role edges: has_role propagates risk
// src→dst (an instance's exposure raises the role it carries), so that is the end
// the contributors are indexed under.
func TestBFSBoostOrderIndependence(t *testing.T) {
	const neighbours = 30
	assets := []asset.Asset{{ID: "hub", Type: "iam_role", RiskScore: 1}}
	edges := make([]asset.Edge, 0, neighbours)
	for i := 0; i < neighbours; i++ {
		id := fmt.Sprintf("n%02d", i)
		// Ascending scores, so a first-wins truncation keeps the LOWEST contributors
		// and a score-ordered one keeps the highest — the two are distinguishable.
		assets = append(assets, asset.Asset{ID: id, Type: "ec2_instance", RiskScore: uint8(i + 1)})
		edges = append(edges, asset.Edge{
			SrcID: id, SrcType: "ec2_instance",
			DstID: "hub", DstType: "iam_role", EdgeType: "has_role",
		})
	}

	scoreByID := make(map[string]uint8, len(assets))
	for _, a := range assets {
		scoreByID[a.ID] = a.RiskScore
	}

	shuffled := append([]asset.Edge(nil), edges...)
	// A fixed permutation rather than a random one: this test must fail
	// deterministically when the ordering regresses, not flakily.
	for i := range shuffled {
		j := (i*7 + 11) % len(shuffled)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	base := computeBFSBoost("hub", scoreByID, buildAdjIndex(edges, scoreByID))
	perm := computeBFSBoost("hub", scoreByID, buildAdjIndex(shuffled, scoreByID))
	require.Equal(t, base, perm,
		"boost changed under a reshuffled edge slice — the %d-node visit budget is "+
			"sampling in input order, so risk scores are not reproducible between sweeps",
		bfsMaxNodes)
	require.Greater(t, base, 0.0, "fixture must produce a boost or it proves nothing")

	// The budget must spend itself on the highest-scoring neighbours. With ascending
	// scores 1..30 and a 20-node budget, a score-ordered walk sums the top 20
	// (11..30); an input-ordered one would sum 1..20 — a much smaller number.
	lowest := computeBFSBoost("hub", scoreByID, func() adjIndex {
		idx := adjIndex{}
		for i := 0; i < neighbours; i++ {
			idx["hub"] = append(idx["hub"], adjEntry{fmt.Sprintf("n%02d", i), "has_role"})
		}
		return idx
	}())
	require.Greater(t, base, lowest,
		"the visit budget should retain the highest-scoring contributors; got the same or "+
			"less than an ascending-order walk, so the sort is not being applied")
}
