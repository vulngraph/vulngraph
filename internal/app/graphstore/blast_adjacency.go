package graphstore

// blast_adjacency.go — the retained Go-side adjacency ladybugBlastProvider.BlastRadius
// (cmd/graph/ladybug_blast.go) walks instead of querying Ladybug. Built once per
// successful topology build from the exact asset/edge slices
// SyncFromSources/LoadFromSnapshot already hold in memory — no extra ClickHouse
// read, no Ladybug query — and kept on Service until the next build replaces it.
//
// Deliberately NOT shared with bfs.go's adjIndex: that structure answers "whose
// score reaches this node" (direction per graphschema.DirectionFor, sorted for a
// truncation budget), a different question from BlastRadius's "what does an
// attacker holding this node reach" (direction per blastWalkDir). Sharing them
// would couple two traversals with different semantics for no real gain.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// blastNeighbor is one walkable edge in the retained blast-radius adjacency.
// reversed marks an edge walked dst→src (blastWalkDir), so it can be reported
// in its stored orientation.
type blastNeighbor struct {
	id       string
	edgeType string
	reversed bool
}

// blastNodeMeta is the fixed subset of asset fields a reached node needs to be
// rendered as an asset.Asset by ladybugBlastProvider.BlastRadius. It is
// deliberately limited to the fields BlastRadius renders: widening it to the full
// asset.Asset would change BlastRadius's output.
type blastNodeMeta struct {
	name, typ, provider, accountID, region string
}

// blastAdjacency is the retained, directed adjacency ladybugBlastProvider.BlastRadius
// walks in Go instead of calling Ladybug's Neighbors. Replaced wholesale — never
// mutated in place — by the next successful topology build, the same discipline
// lastScores/lastOverlay/lastNodeIDs already follow.
//
// Scope is graphschema.LoadedRels(), NOT ExpandRels(). ExpandRels excludes
// ConnectedViaSG so a UI drill-down doesn't fan out through a shared
// security-group hub — a human-ergonomics rationale that does not transfer to
// blast radius shown to the person approving a fix, where UNDER-counting
// reach is the unsafe direction: shared SG membership is not itself a path,
// but it is kept as an upper bound so the reach of a change they are asked to
// approve is never understated. LoadedRels also
// matches the scope blastRadiusCount already uses, keeping one consistent
// definition.
//
// An edge is admitted only when BOTH:
//  1. relTableForEdge(e) != "" — it is a rel table actually loaded into Ladybug
//     (reusing relTableForEdge, the same routing authority buildEdgeRows uses).
//  2. both endpoints are in the loaded node set (post filterLadybugAssets) — the
//     same gate bulkSyncCopy's COPY step applies. Skipping this would let the
//     Go adjacency reach nodes real Ladybug traversal never could, since COPY
//     silently drops any edge whose endpoint asset was pruned.
type blastAdjacency struct {
	out  map[string][]blastNeighbor
	meta map[string]blastNodeMeta
}

// buildBlastAdjacency builds the retained adjacency from the exact
// (post-filterLadybugAssets) asset slice and the full edge slice a topology build
// already holds in memory.
func buildBlastAdjacency(assets []asset.Asset, edges []asset.Edge) *blastAdjacency {
	nodeIDs := make(map[string]bool, len(assets))
	meta := make(map[string]blastNodeMeta, len(assets))
	for i := range assets {
		a := &assets[i]
		nodeIDs[a.ID] = true
		meta[a.ID] = blastNodeMeta{
			name:      a.Name,
			typ:       a.Type,
			provider:  string(a.Provider),
			accountID: a.AccountID,
			region:    a.Region,
		}
	}

	out := make(map[string][]blastNeighbor)
	for _, e := range edges {
		if relTableForEdge(e) == "" {
			continue // not loaded into Ladybug — never a real BlastRadius hop today
		}
		if !nodeIDs[e.SrcID] || !nodeIDs[e.DstID] {
			continue // one endpoint pruned by filterLadybugAssets — COPY would drop this edge too
		}
		dir := blastWalkDir(e.EdgeType)
		if dir != graphschema.DirReverse {
			out[e.SrcID] = append(out[e.SrcID], blastNeighbor{id: e.DstID, edgeType: e.EdgeType})
		}
		if dir != graphschema.DirForward {
			out[e.DstID] = append(out[e.DstID], blastNeighbor{id: e.SrcID, edgeType: e.EdgeType, reversed: true})
		}
	}
	return &blastAdjacency{out: out, meta: meta}
}

// assetFromMeta synthesizes the asset.Asset ladybugBlastProvider.BlastRadius needs
// for id from the retained meta map plus nodeSignalsCache. RiskScore is set from
// NodeSignals.MaxScore, not asset.RiskScore, mirroring the pre-existing Ladybug-path
// mapping (used for TopReachable ranking) — preserved deliberately rather than
// "fixed" as a side effect of moving the traversal off Ladybug.
func (s *Service) assetFromMeta(id string, adj *blastAdjacency) asset.Asset {
	m := adj.meta[id]
	a := asset.Asset{
		ID:        id,
		Name:      m.name,
		Type:      m.typ,
		Provider:  asset.Provider(m.provider),
		AccountID: m.accountID,
		Region:    m.region,
	}
	if v, ok := s.nodeSignalsCache.Load(id); ok {
		a.RiskScore = uint8(v.(NodeSignals).MaxScore)
	}
	return a
}

// BlastSeed resolves seedID against the retained adjacency's node set. ok=false
// means seedID is not a loaded node (pruned by filterLadybugAssets, unknown to the
// graph, or no successful topology build has completed yet); the caller
// (ladybugBlastProvider.BlastRadius) then falls back to the ClickHouse BFS.
func (s *Service) BlastSeed(seedID string) (asset.Asset, bool) {
	adj := s.blastAdj.Load()
	if adj == nil {
		return asset.Asset{}, false
	}
	if _, ok := adj.meta[seedID]; !ok {
		return asset.Asset{}, false
	}
	return s.assetFromMeta(seedID, adj), true
}

// TryBlastNeighbors returns the walkable (blastWalkDir), LoadedRels()-scoped edges and
// deduplicated reached-node assets for the given frontier ids, from the
// retained Go adjacency. ok=false means no topology build has completed yet
// (adjacency is nil) — the caller falls back to the ClickHouse BFS exactly as
// a Ladybug neighbour-walk failure did.
func (s *Service) TryBlastNeighbors(ids []string) (edges []asset.Edge, nodes []asset.Asset, ok bool) {
	adj := s.blastAdj.Load()
	if adj == nil {
		return nil, nil, false
	}
	seenNode := make(map[string]bool, len(ids))
	for _, id := range ids {
		for _, nb := range adj.out[id] {
			e := asset.Edge{SrcID: id, DstID: nb.id, EdgeType: nb.edgeType}
			if nb.reversed {
				e.SrcID, e.DstID = nb.id, id
			}
			edges = append(edges, e)
			if seenNode[nb.id] {
				continue
			}
			seenNode[nb.id] = true
			nodes = append(nodes, s.assetFromMeta(nb.id, adj))
		}
	}
	return edges, nodes, true
}
