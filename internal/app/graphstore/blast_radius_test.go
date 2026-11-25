package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestBlastRadiusGraph_SeedsAcrossAllLabels is the regression test for the
// bug where blast_radius/full_blast_radius_3hop only ever
// seeded on the generic Asset label, so any ec2_instance/security_group/
// k8s_*/subnet $id silently returned totally empty — not even the seed node
// itself. blastRadiusGraph must resolve a seed under every label matchSeed
// does. Note: EC2Instance/SecurityGroup/Subnet have no rel table declaring
// them as an OUTBOUND source today (every generic rel table is FROM Asset,
// and EC2Instance/SecurityGroup/Subnet are distinct Ladybug labels from Asset) —
// a separate, already-documented, out-of-scope gap (same class as the
// ProtectedBy Asset/SecurityGroup mismatch found earlier). So
// the meaningful assertion for those three labels is "the seed itself
// resolves," not "traversal finds further nodes" — k8s_pod (K8sWorkload) is
// used for the traversal assertion since ExecutesAsK8sWorkload is a real,
// correctly-routed outbound edge for that label.
func TestBlastRadiusGraph_SeedsAcrossAllLabels(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{
		{ID: "i-1", Name: "instance", Type: "ec2_instance", Provider: "aws"},
		{ID: "sg-1", Name: "sg", Type: "security_group", Provider: "aws"},
		{ID: "subnet-1", Name: "subnet", Type: "subnet", Provider: "aws"},
		{ID: "pod-1", Name: "pod", Type: "k8s_pod", Provider: "kubernetes"},
		{ID: "role-1", Name: "role", Type: "iam_role", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "pod-1", SrcType: "k8s_pod", DstID: "role-1", DstType: "iam_role", EdgeType: "executes_as"},
	}

	_, wc := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wc, assets, edges, nil))

	for _, seed := range []string{"i-1", "sg-1", "subnet-1"} {
		res, err := blastRadiusGraph(wc, seed, 1, HardBudget)
		require.NoError(t, err, seed)
		ids := map[string]bool{}
		for _, n := range res.Nodes {
			ids[n.ID] = true
		}
		require.True(t, ids[seed], "%s: seed itself must resolve (was totally empty before the fix)", seed)
	}

	// k8s_pod seed (K8sWorkload label) — ExecutesAsK8sWorkload is a real
	// outbound edge for this label, so traversal should reach role-1.
	res, err := blastRadiusGraph(wc, "pod-1", 1, HardBudget)
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, n := range res.Nodes {
		ids[n.ID] = true
	}
	require.True(t, ids["pod-1"], "seed itself must resolve")
	require.True(t, ids["role-1"], "expected role-1 reachable from pod-1 via executes_as")

	// Unknown seed id — fails open (empty result, not an error), matching matchSeed's contract.
	res, err = blastRadiusGraph(wc, "does-not-exist", 1, HardBudget)
	require.NoError(t, err)
	require.Empty(t, res.Nodes)
}

// TestBlastRadiusGraph_MultiHopCrossesLabelBoundary verifies traversal
// continues correctly when hop 1 lands on a different label than the seed
// (K8sWorkload --executes_as(K8s)--> IamRole --can_assume--> IamRole).
func TestBlastRadiusGraph_MultiHopCrossesLabelBoundary(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{
		{ID: "pod-1", Name: "pod", Type: "k8s_pod", Provider: "kubernetes"},
		{ID: "role-a", Name: "role-a", Type: "iam_role", Provider: "aws"},
		{ID: "role-b", Name: "role-b", Type: "iam_role", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "pod-1", SrcType: "k8s_pod", DstID: "role-a", DstType: "iam_role", EdgeType: "executes_as"},
		{SrcID: "role-a", SrcType: "iam_role", DstID: "role-b", DstType: "iam_role", EdgeType: "can_assume"},
	}

	_, wc := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wc, assets, edges, nil))

	// 1 hop only reaches role-a, not role-b.
	res, err := blastRadiusGraph(wc, "pod-1", 1, HardBudget)
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, n := range res.Nodes {
		ids[n.ID] = true
	}
	require.True(t, ids["role-a"], "1-hop should reach role-a")
	require.False(t, ids["role-b"], "1-hop should not reach role-b")

	// 2 hops crosses the label boundary (K8sWorkload -> IamRole -> IamRole) to role-b.
	res, err = blastRadiusGraph(wc, "pod-1", 2, HardBudget)
	require.NoError(t, err)
	ids = map[string]bool{}
	for _, n := range res.Nodes {
		ids[n.ID] = true
	}
	require.True(t, ids["role-a"], "2-hop should still reach role-a")
	require.True(t, ids["role-b"], "2-hop should cross the label boundary to reach role-b")
}

// TestBlastRadiusGraph_RespectsNodeBudget verifies the node cap stops the BFS
// and reports truncation rather than returning an unbounded result.
func TestBlastRadiusGraph_RespectsNodeBudget(t *testing.T) {
	ctx := context.Background()
	assets := []asset.Asset{{ID: "hub", Name: "hub", Type: "iam_role", Provider: "aws"}}
	var edges []asset.Edge
	for i := range 20 {
		id := "leaf-" + string(rune('a'+i))
		assets = append(assets, asset.Asset{ID: id, Name: id, Type: "iam_role", Provider: "aws"})
		edges = append(edges, asset.Edge{SrcID: "hub", SrcType: "iam_role", DstID: id, DstType: "iam_role", EdgeType: "can_assume"})
	}

	_, wc := openTestDB(t)
	require.NoError(t, bulkSync(ctx, wc, assets, edges, nil))

	res, err := blastRadiusGraph(wc, "hub", 1, QueryBudget{MaxNodes: 5, MaxEdges: 5})
	require.NoError(t, err)
	require.True(t, res.Truncated, "exceeding the node budget must report truncated")
	require.LessOrEqual(t, len(res.Nodes), 5)
}
