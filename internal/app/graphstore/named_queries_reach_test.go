package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// reachFixture: two internet-exposed load balancers. lb-a reaches three services
// and, through role-1, role-2 (five nodes); lb-b reaches one service.
func reachFixture() ([]asset.Asset, []asset.Edge) {
	assets := []asset.Asset{
		{ID: "lb-a", Name: "a", Type: "load_balancer", Provider: "aws"},
		{ID: "lb-b", Name: "b", Type: "load_balancer", Provider: "aws"},
		{ID: "svc-1", Name: "s1", Type: "load_balancer", Provider: "aws"},
		{ID: "svc-2", Name: "s2", Type: "load_balancer", Provider: "aws"},
		{ID: "svc-3", Name: "s3", Type: "load_balancer", Provider: "aws"},
		{ID: "svc-4", Name: "s4", Type: "load_balancer", Provider: "aws"},
		{ID: "role-1", Name: "r1", Type: "iam_role", Provider: "aws"},
		{ID: "role-2", Name: "r2", Type: "iam_role", Provider: "aws"},
	}
	edge := func(src, srcType, dst, dstType, typ string) asset.Edge {
		return asset.Edge{SrcID: src, SrcType: srcType, DstID: dst, DstType: dstType, EdgeType: typ}
	}
	edges := []asset.Edge{
		edge("lb-a", "load_balancer", "internet", "internet", "exposed_to_internet"),
		edge("lb-b", "load_balancer", "internet", "internet", "exposed_to_internet"),
		edge("lb-a", "load_balancer", "svc-1", "load_balancer", "routes_to"),
		edge("lb-a", "load_balancer", "svc-2", "load_balancer", "routes_to"),
		edge("lb-a", "load_balancer", "svc-3", "load_balancer", "routes_to"),
		edge("lb-b", "load_balancer", "svc-4", "load_balancer", "routes_to"),
		edge("lb-a", "load_balancer", "role-1", "iam_role", "has_role"),
		edge("role-1", "iam_role", "role-2", "iam_role", "can_assume"),
	}
	return assets, edges
}

func TestNamedQueries_BlastRadiusDeepRanksByReach(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets, edges := reachFixture()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	res, err := svc.RunNamedQuery(ctx, "blast_radius_deep", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"lb-a", "lb-b"}, nodeIDs(res.Nodes))
	require.False(t, res.MultiHopMayBeIncomplete, "no table of this fixture is above one node group")
}

func TestNamedQueries_AttackPathCheckReturnsThePath(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets, edges := reachFixture()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	res, err := svc.RunNamedQuery(ctx, "attack_path_check", map[string]string{"src_id": "lb-a", "dst_id": "role-2"})
	require.NoError(t, err)
	nodes, rels := res.Nodes, res.Edges
	require.ElementsMatch(t, []string{"lb-a", "role-1", "role-2"}, nodeIDs(nodes))
	var hops []string
	for _, e := range rels {
		hops = append(hops, e.SrcID+"-"+e.EdgeType+"->"+e.DstID)
	}
	require.ElementsMatch(t, []string{"lb-a-HasRole->role-1", "role-1-CanAssume->role-2"}, hops)

	res, err = svc.RunNamedQuery(ctx, "attack_path_check", map[string]string{"src_id": "lb-b", "dst_id": "role-2"})
	require.NoError(t, err)
	nodes, rels = res.Nodes, res.Edges
	require.Empty(t, nodes)
	require.Empty(t, rels)
}
