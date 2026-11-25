package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestBuildBlastAdjacency_ConnectedViaSGReachable is the same-as-Ladybug pinning
// test the design note calls for: BlastRadius's retained Go
// adjacency is pinned to graphschema.LoadedRels(), not ExpandRels() (which
// neighbors()/the UI drill-down use and which deliberately excludes
// ConnectedViaSG to avoid fanning out through a shared security-group hub — see
// neighborRels' doc comment in repo.go). A node reachable ONLY via
// ConnectedViaSG must still show up in the Go-side walk, matching
// blastRadiusCount's existing untyped `[]->` Cypher scope (repo_cypher.go),
// which already includes it.
func TestBuildBlastAdjacency_ConnectedViaSGReachable(t *testing.T) {
	assets := []asset.Asset{
		{ID: "i-1", Name: "instance-1", Type: "ec2_instance", Provider: "aws"},
		{ID: "sg-1", Name: "shared-sg", Type: "security_group", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "i-1", SrcType: "ec2_instance", DstID: "sg-1", DstType: "security_group", EdgeType: "connected_via_sg"},
	}

	adj := buildBlastAdjacency(assets, edges)

	neighbors := adj.out["i-1"]
	require.Len(t, neighbors, 1, "ConnectedViaSG must be in the retained adjacency's LoadedRels() scope")
	require.Equal(t, "sg-1", neighbors[0].id)
	require.Equal(t, "connected_via_sg", neighbors[0].edgeType)

	// End-to-end through the Service methods ladybugBlastProvider.BlastRadius
	// actually calls: the seed resolves, and the SG-only hop is walked.
	svc := &Service{}
	svc.blastAdj.Store(adj)

	seed, ok := svc.BlastSeed("i-1")
	require.True(t, ok)
	require.Equal(t, "ec2_instance", seed.Type)

	gotEdges, gotNodes, ok := svc.TryBlastNeighbors([]string{"i-1"})
	require.True(t, ok)
	require.Len(t, gotNodes, 1)
	require.Equal(t, "sg-1", gotNodes[0].ID)
	require.Equal(t, "security_group", gotNodes[0].Type)
	require.Len(t, gotEdges, 1)
	require.Equal(t, "connected_via_sg", gotEdges[0].EdgeType)
}

// TestBuildBlastAdjacency_PrunedEndpointExcluded verifies the second admission
// condition: an edge whose destination was pruned by filterLadybugAssets (absent
// from the loaded asset slice) must not appear in the adjacency, even though
// its edge type is loaded — bulkSyncCopy's COPY step would drop that edge for
// the identical reason (missing endpoint node), so a Go adjacency that kept it
// would reach further than Ladybug itself ever could.
func TestBuildBlastAdjacency_PrunedEndpointExcluded(t *testing.T) {
	assets := []asset.Asset{
		{ID: "i-1", Name: "instance-1", Type: "ec2_instance", Provider: "aws"},
		// "dns-1" deliberately absent — simulates filterLadybugAssets pruning it.
	}
	edges := []asset.Edge{
		{SrcID: "i-1", SrcType: "ec2_instance", DstID: "dns-1", DstType: "dns_record", EdgeType: "connected_via_sg"},
	}

	adj := buildBlastAdjacency(assets, edges)

	require.Empty(t, adj.out["i-1"], "an edge to a pruned endpoint must not be walkable")
}

// TestBuildBlastAdjacency_UnloadedRelExcluded verifies the first admission
// condition: an edge_type with no Ladybug rel table (relTableForEdge returns "")
// must not appear in the adjacency even when both endpoints are loaded —
// e.g. PeeredWith is bfs_only (graphschema.Rels), never traversable.
func TestBuildBlastAdjacency_UnloadedRelExcluded(t *testing.T) {
	assets := []asset.Asset{
		{ID: "vpc-1", Name: "vpc-1", Type: "vpc", Provider: "aws"},
		{ID: "vpc-2", Name: "vpc-2", Type: "vpc", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "vpc-1", SrcType: "vpc", DstID: "vpc-2", DstType: "vpc", EdgeType: "peered_with"},
	}

	adj := buildBlastAdjacency(assets, edges)

	require.Empty(t, adj.out["vpc-1"], "a bfs_only edge type (PeeredWith) must not be walkable in the retained adjacency")
}

// TestServiceBlastMethods_NotBuiltFallsOpen verifies BlastSeed/TryBlastNeighbors
// both report ok=false before the first successful topology build — the state
// ladybugBlastProvider.BlastRadius must treat identically to a Ladybug-not-ready
// startup window (fall back to the ClickHouse BFS).
func TestServiceBlastMethods_NotBuiltFallsOpen(t *testing.T) {
	svc := &Service{}

	_, ok := svc.BlastSeed("i-1")
	require.False(t, ok)

	_, _, ok = svc.TryBlastNeighbors([]string{"i-1"})
	require.False(t, ok)
}
