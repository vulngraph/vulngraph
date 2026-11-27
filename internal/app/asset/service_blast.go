package asset

import (
	"context"
	"fmt"
)

type blastWalk struct {
	nodes     []endpoint
	edges     []Edge
	truncated bool
}

// BlastRadiusDir performs a bounded BFS, then hydrates the selected nodes once.
// Traversal depends only on edge endpoints; hydration never changes its reach.
func (s *Service) BlastRadiusDir(ctx context.Context, seedID string, maxDepth int, dir Direction) (BlastRadius, error) {
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	seed, err := s.repo.GetAsset(ctx, seedID)
	if err != nil {
		return BlastRadius{}, fmt.Errorf("BlastRadius: seed: %w", err)
	}
	result := BlastRadius{SeedID: seedID, Assets: []Asset{seed}, MaxDepth: maxDepth}
	walk, err := s.walkBlastRadius(ctx, seedID, maxDepth, dir)
	result.Edges, result.Truncated = walk.edges, walk.truncated
	if err != nil {
		return result, err
	}
	if len(walk.nodes) == 0 {
		return result, nil
	}
	ids := blastNodeIDs(walk.nodes)
	fetched, err := s.repo.ByIDs(ctx, ids)
	if err != nil {
		// A failed read is unmeasured, never a list of apparently valid stubs.
		return result, fmt.Errorf("BlastRadius: hydrate %d nodes: %w", len(ids), err)
	}
	assetByID := make(map[string]Asset, len(fetched))
	for _, a := range fetched {
		assetByID[a.ID] = a
	}
	for _, ep := range walk.nodes {
		a, ok := assetByID[ep.id]
		if !ok {
			a = Asset{ID: ep.id, Type: ep.typ}
		}
		result.Assets = append(result.Assets, a)
	}
	return result, nil
}

// BlastRadiusAccounts uses the identical traversal and node budget as the full
// walk, but reads only account IDs. Full asset metadata is unnecessary to count
// independent accounts and can be much wider than the graph itself.
func (s *Service) BlastRadiusAccounts(ctx context.Context, seedID string, maxDepth int) (BlastAccountCounts, error) {
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	walk, err := s.walkBlastRadius(ctx, seedID, maxDepth, DirAttack)
	if err != nil {
		return BlastAccountCounts{}, err
	}
	// Validate the seed and read reachable accounts in the same current-version
	// lookup. An orphaned edge cannot make an absent seed look measured.
	ids := append(blastNodeIDs(walk.nodes), seedID)
	accounts, err := s.repo.AccountsByIDs(ctx, ids)
	if err != nil {
		return BlastAccountCounts{}, fmt.Errorf("BlastRadiusAccounts: hydrate: %w", err)
	}
	if _, ok := accounts[seedID]; !ok {
		return BlastAccountCounts{}, fmt.Errorf("BlastRadiusAccounts: seed: %w", ErrNotFound)
	}
	out := BlastAccountCounts{Total: len(walk.nodes), ByAccount: map[string]int{}, Truncated: walk.truncated}
	for i, ep := range walk.nodes {
		key := accounts[ep.id]
		if key == "" {
			// The full walk includes its seed at index zero. Preserve its
			// singleton keys so the summary has exactly the same distribution.
			key = fmt.Sprintf("__singleton_%d", i+1)
		}
		out.ByAccount[key]++
	}
	return out, nil
}

func blastNodeIDs(nodes []endpoint) []string {
	ids := make([]string, len(nodes))
	for i, ep := range nodes {
		ids[i] = ep.id
	}
	return ids
}

func (s *Service) walkBlastRadius(ctx context.Context, seedID string, maxDepth int, dir Direction) (blastWalk, error) {
	var result blastWalk
	seen := map[string]bool{seedID: true}
	seenEdge := map[string]bool{}
	frontier := []string{seedID}
	for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
		hopEdges, err := s.hopEdges(ctx, frontier, dir)
		if err != nil {
			return result, fmt.Errorf("BlastRadius: depth %d: %w", depth, err)
		}
		for _, e := range hopEdges {
			key := e.SrcID + "\x00" + e.DstID + "\x00" + e.EdgeType
			if !seenEdge[key] {
				seenEdge[key] = true
				result.edges = append(result.edges, e)
			}
		}
		var next []string
	endpoints:
		for _, e := range hopEdges {
			for _, to := range farEndpoints(e, frontier, dir, seen) {
				if len(seen) >= maxNodeBudget {
					result.truncated = true
					break endpoints
				}
				seen[to.id] = true
				result.nodes = append(result.nodes, to)
				next = append(next, to.id)
			}
		}
		frontier = next
		if result.truncated {
			break
		}
	}
	return result, nil
}
