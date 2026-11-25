package graphstore

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// A new DirReverse edge type must be consciously classified: either the
// attacker moves dst→src along it (blastReverseTypes) or risk flows backwards
// while compromise still moves forwards (blastForwardDespiteReverse).
// blastFixture: lb-b permits ingress FROM lb-a (sg_allows_from lb-b→lb-a), so
// an attacker on lb-a reaches lb-b — and lb-a permitting ingress from lb-c does
// NOT let lb-a reach lb-c. lb-b and lb-d share an SG hub (connected_via_sg,
// DirBoth), and can_assume (DirBoth) is walked both ways.
func blastFixture() ([]asset.Asset, []asset.Edge) {
	assets := []asset.Asset{
		{ID: "lb-a", Type: "load_balancer", Provider: "aws"},
		{ID: "lb-b", Type: "load_balancer", Provider: "aws"},
		{ID: "lb-c", Type: "load_balancer", Provider: "aws"},
		{ID: "lb-d", Type: "load_balancer", Provider: "aws"},
		{ID: "lb-sg", Type: "load_balancer", Provider: "aws"},
		{ID: "role-1", Type: "iam_role", Provider: "aws"},
		{ID: "role-2", Type: "iam_role", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "lb-a", SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role", EdgeType: "has_role"},
		{SrcID: "role-1", SrcType: "iam_role", DstID: "role-2", DstType: "iam_role", EdgeType: "can_assume"},
		{SrcID: "lb-b", SrcType: "load_balancer", DstID: "lb-a", DstType: "load_balancer", EdgeType: "sg_allows_from"},
		{SrcID: "lb-a", SrcType: "load_balancer", DstID: "lb-c", DstType: "load_balancer", EdgeType: "sg_allows_from"},
		{SrcID: "lb-b", SrcType: "load_balancer", DstID: "lb-sg", DstType: "load_balancer", EdgeType: "connected_via_sg"},
		{SrcID: "lb-d", SrcType: "load_balancer", DstID: "lb-sg", DstType: "load_balancer", EdgeType: "connected_via_sg"},
	}
	return assets, edges
}

// goBlastReach walks the retained Go adjacency the way ladybugBlastProvider does.
func goBlastReach(t *testing.T, svc *Service, seed string, depth int) []string {
	t.Helper()
	seen := map[string]bool{seed: true}
	frontier := []string{seed}
	for d := 0; d < depth && len(frontier) > 0; d++ {
		_, nodes, ok := svc.TryBlastNeighbors(frontier)
		require.True(t, ok)
		var next []string
		for _, n := range nodes {
			if !seen[n.ID] {
				seen[n.ID] = true
				next = append(next, n.ID)
			}
		}
		frontier = next
	}
	delete(seen, seed)
	return sortedKeys(seen)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The Go adjacency (respond's blast provider) and the Ladybug walks (enrich's
// BlastRadiusCount, the blast_radius named query) must agree, and both must
// follow sg_allows_from dst→src.
func TestBlastWalks_GoAndLadybugAgreeOnDirection(t *testing.T) {
	assets, edges := blastFixture()
	svc := &Service{}
	svc.blastAdj.Store(buildBlastAdjacency(assets, edges))

	_, wc := openTestDB(t)
	require.NoError(t, bulkSync(context.Background(), wc, assets, edges, nil))

	want := map[int][]string{
		1: {"lb-b", "role-1"},
		2: {"lb-b", "lb-sg", "role-1", "role-2"},
		3: {"lb-b", "lb-d", "lb-sg", "role-1", "role-2"},
	}
	for depth, ids := range want {
		require.Equal(t, ids, goBlastReach(t, svc, "lb-a", depth), "Go adjacency, depth %d", depth)

		n, err := blastRadiusCount(wc, "lb-a", depth)
		require.NoError(t, err)
		require.Equal(t, len(ids), n, "Ladybug blastRadiusCount, depth %d", depth)

		res, err := blastRadiusGraph(wc, "lb-a", depth, HardBudget)
		require.NoError(t, err)
		got := map[string]bool{}
		for _, nd := range res.Nodes {
			if nd.ID != "lb-a" {
				got[nd.ID] = true
			}
		}
		require.Equal(t, ids, sortedKeys(got), "Ladybug blastRadiusGraph, depth %d", depth)
	}

	// The reverse edge is reported in its stored orientation.
	gotEdges, _, ok := svc.TryBlastNeighbors([]string{"lb-a"})
	require.True(t, ok)
	require.Contains(t, gotEdges, asset.Edge{SrcID: "lb-b", DstID: "lb-a", EdgeType: "sg_allows_from"})
}
