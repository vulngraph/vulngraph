package explore

import (
	"context"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

func inventorySeed(m NodeMatch) bool {
	for _, typ := range m.Types {
		if strings.EqualFold(typ, "package") {
			return true
		}
	}
	for _, id := range m.IDs {
		if strings.HasPrefix(id, "pkg:") {
			return true
		}
	}
	return false
}
func inventoryEdgeFilter(edgeTypes []string) []string {
	if len(edgeTypes) == 0 {
		return graphschema.OnDemandEdgeTypes()
	}
	var out []string
	for _, typ := range chEdgeTypes(edgeTypes) {
		if graphschema.IsOnDemandEdge(typ) {
			out = append(out, typ)
		}
	}
	return out
}

// mergeInventoryNeighbors supplements a successful resident-graph answer.
// Falling back only when it is empty loses memberships beside any core edge.
func mergeInventoryNeighbors(ctx context.Context, inventory Repo, ids, edgeTypes []string, dir Direction, edges []Edge, nodes []Node, truncated bool) ([]Edge, []Node, bool, error) {
	types := inventoryEdgeFilter(edgeTypes)
	if len(types) == 0 {
		return edges, nodes, truncated, nil
	}
	extraEdges, extraNodes, cut, err := inventory.Neighbors(ctx, ids, types, dir)
	if err != nil {
		return nil, nil, false, fmt.Errorf("package inventory neighbors: %w", err)
	}
	truncated = truncated || cut
	seenNodes := map[string]bool{}
	for _, n := range nodes {
		seenNodes[n.ID] = true
	}
	for _, n := range extraNodes {
		if seenNodes[n.ID] {
			continue
		}
		if len(nodes) >= hardMaxNodes {
			truncated = true
			continue
		}
		seenNodes[n.ID] = true
		nodes = append(nodes, n)
	}
	for _, id := range ids {
		seenNodes[id] = true
	}
	seenEdges := map[Edge]bool{}
	for _, e := range edges {
		seenEdges[e] = true
	}
	for _, e := range extraEdges {
		if seenEdges[e] {
			continue
		}
		if len(edges) >= hardMaxEdges || !seenNodes[e.SrcID] || !seenNodes[e.DstID] {
			truncated = true
			continue
		}
		seenEdges[e] = true
		edges = append(edges, e)
	}
	return edges, nodes, truncated, nil
}
