package explore

import (
	"context"
	"fmt"
)

func (r *CHRepo) withoutDeletedNodes(ctx context.Context, nodes []Node) ([]Node, error) {
	if r.deletions == nil || len(nodes) == 0 {
		return nodes, nil
	}
	ids := make([]string, 0, len(nodes))
	for _, node := range nodes {
		ids = append(ids, node.ID)
	}
	deleted, err := r.deletions.VerifyDeletedAssets(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("MatchSeed: deletion proofs: %w", err)
	}
	out := nodes[:0]
	for _, node := range nodes {
		if !deleted[node.ID] {
			out = append(out, node)
		}
	}
	return out, nil
}

func (r *CHRepo) withoutDeletedEdges(ctx context.Context, edges []Edge) ([]Edge, error) {
	if r.deletions == nil || len(edges) == 0 {
		return edges, nil
	}
	seen := map[string]bool{}
	var ids []string
	for _, edge := range edges {
		for _, id := range []string{edge.SrcID, edge.DstID} {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	deleted, err := r.deletions.VerifyDeletedAssets(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("Neighbors: deletion proofs: %w", err)
	}
	out := edges[:0]
	for _, edge := range edges {
		if !deleted[edge.SrcID] && !deleted[edge.DstID] {
			out = append(out, edge)
		}
	}
	return out, nil
}
