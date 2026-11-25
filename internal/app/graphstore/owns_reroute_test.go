package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestRelTableForEdgeRoutesOwnsBySourceLabel is the direct routing test the
// sibling reroutes get for free from buildEdgeRows
// (TestFederatedAccessFromServiceAccountReroutesToK8sWorkloadTable,
// TestBindsFromServiceAccountReroutesToK8sWorkloadTable): those reroute TARGETS
// are Loaded into Ladybug today, so a full buildEdgeRows call exercises the routing
// decision end to end. owns/OwnsAsset cannot get that: both are declared
// bfs_only (see RelOwnsAsset's DropReason), so ladybugQueryableRelTable rejects
// both and relTableForEdge's final gate returns "" no matter which branch of the
// routing chain ran above it — proven by deleting the "owns"/NodeAsset reroute
// branch in relTableForEdge entirely: every existing test (including
// TestOwnsProducersMatchDeclaredRelEndpoints, which checks the registry
// declaration, not the routing function) keeps passing, because nothing
// downstream of the Loaded gate can observe which branch ran.
//
// This test calls relTableForEdge directly and temporarily promotes Owns/
// OwnsAsset to Loaded in ladybugRelSpec for its own duration, so the routing
// DECISION is observable independent of load status — the same visibility the
// sibling tests get for free from their tables being genuinely Loaded.
func TestRelTableForEdgeRoutesOwnsBySourceLabel(t *testing.T) {
	// ladybugRelSpec is a package-level map built once at init from the registry's
	// Loaded rels; Owns/OwnsAsset are absent from it by design. Save/restore so
	// this test's temporary promotion can't leak into any other test in the
	// package regardless of run order.
	origOwns, hadOwns := ladybugRelSpec[RelOwns]
	origOwnsAsset, hadOwnsAsset := ladybugRelSpec[RelOwnsAsset]
	t.Cleanup(func() {
		if hadOwns {
			ladybugRelSpec[RelOwns] = origOwns
		} else {
			delete(ladybugRelSpec, RelOwns)
		}
		if hadOwnsAsset {
			ladybugRelSpec[RelOwnsAsset] = origOwnsAsset
		} else {
			delete(ladybugRelSpec, RelOwnsAsset)
		}
	})
	ladybugRelSpec[RelOwns] = relEndpoints{from: NodeCloudAccount, to: NodeAsset}
	ladybugRelSpec[RelOwnsAsset] = relEndpoints{from: NodeAsset, to: NodeRepo}

	// CloudAccount-labeled source (collect/aws/aws.go's real cloud_account→
	// ec2_instance inventory-containment producer) must stay on the default
	// Owns table.
	got := relTableForEdge(asset.Edge{
		SrcID: "aws:1", SrcType: "cloud_account",
		DstID: "i-1", DstType: "ec2_instance",
		EdgeType: "owns",
	})
	require.Equal(t, RelOwns, got,
		"a CloudAccount-labeled owns source must stay on the default Owns table")

	// Asset-labeled source (correlate/human_identity.go's human_identity→
	// github_repo producer) must reroute to OwnsAsset — the label-mismatch fix
	// this test guards.
	got = relTableForEdge(asset.Edge{
		SrcID: "human:alice", SrcType: "human_identity",
		DstID: "org/repo", DstType: "github_repo",
		EdgeType: "owns",
	})
	require.Equal(t, RelOwnsAsset, got,
		"an Asset-labeled owns source must reroute to OwnsAsset, or the label "+
			"mismatch resurrects the moment either table is promoted to Loaded")
}
