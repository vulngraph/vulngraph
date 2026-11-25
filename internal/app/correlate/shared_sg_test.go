package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestSharedSecurityGroup_IgnoresNonSGKeys is the regression guard for the
// connected_via_sg inflation bug: the security_groups metadata is polluted with
// non-SG IDs (EC2 instance IDs), which turned instances into fake hubs with
// thousands of members and regenerated the O(N²) mesh. The correlator must group
// only under IDs that are real security_group assets, so every emitted edge points
// at a SecurityGroup node that exists in the graph.
func TestSharedSecurityGroup_IgnoresNonSGKeys(t *testing.T) {
	sg := asset.Asset{ID: "sg-real", Type: "security_group", Provider: asset.ProviderAWS}
	// Two instances both reference the real SG and a bogus instance-ID "SG".
	a1 := asset.Asset{ID: "i-a", Type: "ec2_instance", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"security_groups": "sg-real,i-b"}}
	a2 := asset.Asset{ID: "i-b", Type: "ec2_instance", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"security_groups": "sg-real"}}

	g := NewGraph([]asset.Asset{sg, a1, a2})

	// Only the real SG is a grouping key; the instance ID "i-b" is dropped.
	require.Contains(t, g.AssetsBySG(), "sg-real")
	require.NotContains(t, g.AssetsBySG(), "i-b")
	require.Len(t, g.AssetsBySG(), 1)

	edges := SharedSecurityGroup{}.Correlate(g)
	require.NotEmpty(t, edges)
	for _, e := range edges {
		require.Equal(t, EdgeConnectedViaSG, e.EdgeType)
		require.Equal(t, "security_group", e.DstType, "edge must point at a security group, never an instance")
		require.Equal(t, "sg-real", e.DstID)
	}
}

// TestSharedSecurityGroup_DatastoreMembers: the datastore SG path queries
// (databases_reachable_from_internet, the sg-lateral presets) filter on RDS,
// Redshift and ElastiCache. A type the rule neither loads nor declares never
// gets a connected_via_sg edge, so its branch of those queries never matches.
func TestSharedSecurityGroup_DatastoreMembers(t *testing.T) {
	sg := asset.Asset{ID: "sg-db", Type: "security_group", Provider: asset.ProviderAWS}
	member := func(id, typ string) asset.Asset {
		return asset.Asset{ID: id, Type: typ, Provider: asset.ProviderAWS,
			Metadata: map[string]string{"security_groups": "sg-db"}}
	}
	types := []string{"rds_instance", "redshift_cluster", "elasticache_cluster"}
	assets := []asset.Asset{sg}
	for _, ty := range types {
		assets = append(assets, member("db-"+ty, ty))
	}

	got := map[string]bool{}
	for _, e := range (SharedSecurityGroup{}).Correlate(NewGraph(assets)) {
		require.Equal(t, "sg-db", e.DstID)
		got[e.SrcType] = true
	}
	for _, ty := range types {
		require.True(t, got[ty], "%s member of sg-db got no connected_via_sg edge", ty)
		require.Contains(t, SharedSecurityGroup{}.InterestedIn(), ty,
			"a %s change must re-run the rule on the partial path", ty)
		require.Contains(t, correlationTypes, ty, "the full sweep must load %s", ty)
	}
}
