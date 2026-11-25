package graphstore

// bfs.go — weighted BFS risk propagation over the graph.
//
// Runs entirely in memory using the edge slice already loaded by SyncFromSources —
// no Ladybug reads during propagation. The adjacency index is built once from allEdges
// and shared across all goroutines read-only. Score updates are collected into a
// channel (parallel read phase) then applied in a single write connection
// (sequential write phase) to respect Ladybug's single-writer constraint.

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	bfsMaxDepth   = 4
	bfsMaxNodes   = 20
	bfsHopDecay   = 0.7
	bfsBoostScale = 300.0
	bfsMaxBoost   = 30.0
)

// bfsScoreLabels are the Ladybug node labels whose `score` column holds
// asset.Asset.RiskScore — the same quantity propagateRisk boosts — and which must
// therefore receive the post-BFS write.
//
// The membership rule is not "has a score column". It is "the score column is the
// asset risk score", and appendNodeValues (node_rows.go) is the authority:
// Asset/IamRole/K8sWorkload/Subnet all load `int32(a.RiskScore)`, while Package
// loads `int32(sig.MaxScore)` — a different number with different units.
// TestBFSScoreLabelsMatchNodeLoader derives both sides from appendNodeValues so
// this list cannot drift from the loader.
//
// Package is deliberately absent: writing a RiskScore-derived value into a
// column that holds MaxScore would not fix a divergence, it would create one —
// the named queries that read pkg.score are asking for finding severity, not
// asset risk.
var bfsScoreLabels = []string{NodeAsset, NodeIamRole, NodeK8sWorkload, NodeSubnet}

// adjEntry is one end of a directed edge in the adjacency index.
type adjEntry struct {
	neighborID string
	edgeType   string
}

// adjIndex maps every node ID to the neighbours whose risk score contributes to
// ITS boost — computeBFSBoost(X) walks adj[X] and adds each visited neighbour's
// score, so idx[X] → N reads "N's risk raises X".
type adjIndex map[string][]adjEntry

// buildAdjIndex builds a directed adjacency index from the edge slice, with
// each node's neighbours ordered by DESCENDING neighbour risk score (ties broken
// by id). O(edges) space, O(edges·log·max-degree) time; built once before the
// parallel BFS phase.
//
// The ordering is load-bearing, not cosmetic. computeBFSBoost walks at most
// bfsMaxNodes (20) nodes and stops when the budget is spent, so adjacency order
// decides WHICH neighbours contribute to a node's boost. Ordering by descending
// score makes that choice deterministic and keeps the budget on the
// highest-scoring (and therefore most boost-relevant) neighbours, rather than an
// arbitrary subset determined by unstable ClickHouse read order.
//
// Which END an edge is indexed under comes from graphschema.DirectionFor — risk
// should only flow the direction an edge type's semantics support (e.g. not from
// a security group to every host it merely permits ingress from). An
// unrecognised edge type still gets both directions (DirBoth), so a new producer
// over-propagates instead of silently losing a direction.
func buildAdjIndex(edges []asset.Edge, scoreByID map[string]uint8) adjIndex {
	idx := make(adjIndex, len(edges)*2)
	for _, e := range edges {
		if e.SrcID == e.DstID {
			continue // self-loops don't contribute to neighbour traversal
		}
		switch graphschema.DirectionFor(e.EdgeType) {
		case graphschema.DirForward:
			// Risk flows src→dst, so dst is the node that receives src's score.
			idx[e.DstID] = append(idx[e.DstID], adjEntry{e.SrcID, e.EdgeType})
		case graphschema.DirReverse:
			idx[e.SrcID] = append(idx[e.SrcID], adjEntry{e.DstID, e.EdgeType})
		default:
			idx[e.SrcID] = append(idx[e.SrcID], adjEntry{e.DstID, e.EdgeType})
			idx[e.DstID] = append(idx[e.DstID], adjEntry{e.SrcID, e.EdgeType})
		}
	}
	for id := range idx {
		list := idx[id]
		sort.Slice(list, func(i, j int) bool {
			si, sj := scoreByID[list[i].neighborID], scoreByID[list[j].neighborID]
			if si != sj {
				return si > sj // highest-scoring contributor first
			}
			if list[i].neighborID != list[j].neighborID {
				return list[i].neighborID < list[j].neighborID
			}
			// Parallel edges between the same pair: order by type so a repeat build
			// over a reshuffled edge slice produces a byte-identical index.
			return list[i].edgeType < list[j].edgeType
		})
	}
	return idx
}

// scoreUpdate is a pending risk score write collected from the BFS read phase.
type scoreUpdate struct {
	nodeID string
	score  uint8
}

// propagateRisk runs BFS risk propagation over db in two phases and returns the
// boosted scores keyed by node id (so the caller can stash them for the score
// digest — the post-BFS value lives only in Ladybug, which serves it):
//
//  1. Read phase (parallel, 8 goroutines, zero Ladybug I/O): compute BFS boosts
//     using a pure in-memory adjacency index built from the edges already loaded
//     by SyncFromSources.
//  2. Write phase (single connection): apply all score updates with one batched
//     UNWIND per label in bfsScoreLabels. Ladybug only allows one writer at a time.
//
// db is the not-yet-published rebuild target, so no swap lock is needed.
//
// The second return reports whether every score reached the graph. This must not
// be treated as best-effort: the caller stashes these boosts in lastScores and
// seeds lastDigest from them, so recording a boost the graph never received
// would make every later sweep believe the live value already matches and skip
// repairing it. The caller must treat !ok as "stash nothing, seed nothing" and
// fall open into a full rebuild.
//
// An error means the read phase did not finish (computeBoostedScores), so the
// rebuild target holds base scores for nodes the BFS never reached. The caller
// must not publish it: the previous graph and its scores keep serving.
func propagateRisk(ctx context.Context, db *ladybugDB, assets []asset.Asset, edges []asset.Edge) (map[string]uint8, bool, error) {
	if db == nil || len(assets) == 0 {
		return map[string]uint8{}, true, nil
	}
	logger := log.FromContext(ctx)

	boosted, err := computeBoostedScores(ctx, assets, edges)
	if err != nil {
		return nil, false, fmt.Errorf("propagateRisk: %w", err)
	}
	if len(boosted) == 0 {
		// Nothing to write, so nothing can fail to write.
		return boosted, true, nil
	}

	// Write phase: single write connection, one batched UNWIND SET per label — each
	// row routed to its own label via NodeLabelFor (the same rule finalRiskScores
	// and refreshScores partition by) rather than sent to every statement and
	// filtered by MATCH, which would be four full passes over the boost set.
	rowsByLabel, _, rowErr := scoreRowsByLabel(assets, func(id string) (int32, bool) {
		s, ok := boosted[id]
		return int32(s), ok
	}, 0)
	if rowErr != nil {
		// Unreachable with an uncapped call, and reported as "not applied" rather
		// than ignored so a future cap here cannot silently drop every score.
		logger.Warn().Err(rowErr).Msg("graphstore: bfs score rows not built")
		return boosted, false, nil
	}

	wc, err := db.newWriteConn()
	if err != nil {
		logger.Warn().Err(err).Msg("graphstore: bfs write conn failed")
		return boosted, false, nil
	}
	defer wc.Close()

	applied := true
	for _, label := range bfsScoreLabels {
		rows := rowsByLabel[label]
		if len(rows) == 0 {
			continue
		}
		if _, err := unwindInsert(wc, scoreSetQuery(label), rows); err != nil {
			logger.Warn().Err(err).Str("label", label).Msg("graphstore: bfs score update failed")
			applied = false
		}
	}
	return boosted, applied, nil
}

// computeBoostedScores is the pure read phase of risk propagation: parallel BFS
// over an in-memory adjacency index, returning only the nodes whose score the
// boost RAISED (id → boosted score). No Ladybug I/O — shared by propagateRisk
// (which writes into a not-yet-published rebuild) and refreshScores (which
// rewrites the live graph in place on the cheap sync path).
//
// A context cancelled before every node's walk was started is an error, not a
// smaller map: a node never walked would keep its base score, which reads as
// less risk than it carries, and nothing downstream could tell the difference.
// A walk that panicked is an error for the same reason.
func computeBoostedScores(ctx context.Context, assets []asset.Asset, edges []asset.Edge) (map[string]uint8, error) {
	boosted := make(map[string]uint8)
	if len(assets) == 0 {
		return boosted, nil
	}

	scoreByID := make(map[string]uint8, len(assets))
	for _, a := range assets {
		scoreByID[a.ID] = a.RiskScore
	}

	// Build adjacency index once; shared read-only across all goroutines.
	adj := buildAdjIndex(edges, scoreByID)

	updates := make(chan scoreUpdate, len(assets))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup

	var panicked atomic.Int64
	started := 0
	for _, a := range assets {
		if ctx.Err() != nil {
			break
		}
		started++
		a := a
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// A panic in one node's BFS must never crash the worker
			// mid-rebuild, but it fails the whole map, like a cancellation.
			defer func() {
				if rec := recover(); rec != nil {
					panicked.Add(1)
					log.FromContext(ctx).Error().Interface("panic", rec).
						Str("node_id", a.ID).Msg("BFS boost panicked")
				}
			}()

			boost := computeBFSBoost(a.ID, scoreByID, adj)
			if boost <= 0 {
				return
			}
			newScore := uint8(math.Min(100, float64(a.RiskScore)+boost))
			if newScore > a.RiskScore {
				updates <- scoreUpdate{nodeID: a.ID, score: newScore}
			}
		}()
	}

	wg.Wait()
	close(updates)
	if started < len(assets) {
		return nil, fmt.Errorf("computeBoostedScores: walked %d of %d nodes: %w", started, len(assets), ctx.Err())
	}
	if n := panicked.Load(); n > 0 {
		return nil, fmt.Errorf("computeBoostedScores: %d of %d node walks panicked", n, len(assets))
	}

	for u := range updates {
		boosted[u.nodeID] = u.score
	}
	return boosted, nil
}

// computeBFSBoost is a pure function — no I/O, no locks, safe to call from
// concurrent goroutines. Traverses adj up to bfsMaxDepth hops from nodeID,
// accumulating propagated risk weighted by edge type and hop decay.
func computeBFSBoost(nodeID string, scoreByID map[string]uint8, adj adjIndex) float64 {
	if nodeID == "" {
		return 0
	}

	type frontier struct {
		id          string
		attenuation float64
	}

	var totalPropagated float64
	visited := make(map[string]struct{}, bfsMaxNodes)
	visited[nodeID] = struct{}{}
	current := []frontier{{id: nodeID, attenuation: 1.0}}

	for depth := 0; depth < bfsMaxDepth && len(current) > 0 && len(visited) < bfsMaxNodes; depth++ {
		var next []frontier
		for _, f := range current {
			if len(visited) >= bfsMaxNodes {
				break
			}
			for _, neighbor := range adj[f.id] {
				if len(visited) >= bfsMaxNodes {
					break
				}
				if _, seen := visited[neighbor.neighborID]; seen {
					continue
				}
				visited[neighbor.neighborID] = struct{}{}

				// A zero-score node contributes nothing itself but is still expanded:
				// roles, SGs and subnets are usually unscored, and stopping at them cut
				// risk off from everything beyond the first intermediate hop.
				hopAttenuation := f.attenuation * edgeWeight(neighbor.edgeType) * bfsHopDecay
				totalPropagated += float64(scoreByID[neighbor.neighborID]) * hopAttenuation

				if len(visited) < bfsMaxNodes {
					next = append(next, frontier{id: neighbor.neighborID, attenuation: hopAttenuation})
				}
			}
		}
		current = next
	}

	return normaliseBFSBoost(totalPropagated)
}

func normaliseBFSBoost(propagated float64) float64 {
	return math.Min(bfsMaxBoost, math.Max(0, propagated/bfsBoostScale*100))
}

// edgeWeight returns the BFS propagation weight for a snake_case edge_type —
// the value ClickHouse stores and buildAdjIndex indexes. Weights are declared
// in the graphschema registry; TestEdgeWeightCasing pins the snake_case
// contract (a PascalCase mismatch here silently propagates everything at the
// 0.5 default).
func edgeWeight(edgeType string) float64 {
	return graphschema.WeightFor(edgeType)
}
