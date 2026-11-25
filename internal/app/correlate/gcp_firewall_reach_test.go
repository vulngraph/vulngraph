package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func gceInstance(id, network, tags string) asset.Asset {
	return asset.Asset{
		ID: id, Name: id, Type: "gce_instance", AccountID: "proj", Provider: asset.ProviderGCP,
		Metadata: map[string]string{"network": network, "network_tags": tags},
	}
}

func gcpFirewallRule(id, network, sourceTags, targetTags string) asset.Asset {
	return asset.Asset{
		ID: id, Name: id, Type: "gcp_firewall", AccountID: "proj", Provider: asset.ProviderGCP,
		Metadata: map[string]string{
			"network": network, "direction": "INGRESS", "disabled": "false",
			"source_tags": sourceTags, "target_tags": targetTags, "allowed": "tcp:22",
		},
	}
}

func TestGCPFirewallReachability_TagBasedIntraVPC(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpFirewallRule("fw-ssh", "vpc1", "bastion", "app"),
		gceInstance("bastion-1", "vpc1", "bastion"),
		gceInstance("app-1", "vpc1", "app"),
	})

	edges := GCPFirewallReachability{}.Correlate(g)
	require.Len(t, edges, 1, "governed app instance permits ingress from the bastion")
	e := edges[0]
	require.Equal(t, EdgeSGAllowsFrom, e.EdgeType)
	require.Equal(t, "app-1", e.SrcID, "governed instance is the source of the sg_allows_from edge")
	require.Equal(t, "bastion-1", e.DstID, "source-tagged instance is what it allows ingress from")
	require.Equal(t, "gcp_firewall_reachability", e.Properties["rule"])
	require.Equal(t, "tcp:22", e.Properties["ports"])
}

func TestGCPFirewallReachability_WholeNetworkTargetGoverned(t *testing.T) {
	// No target tags → the rule governs the whole network; every same-network
	// instance is a governed endpoint.
	g := NewGraph([]asset.Asset{
		gcpFirewallRule("fw", "vpc1", "bastion", ""),
		gceInstance("bastion-1", "vpc1", "bastion"),
		gceInstance("app-1", "vpc1", "app"),
	})
	edges := GCPFirewallReachability{}.Correlate(g)
	// Governed = all in vpc1 (bastion-1, app-1); source = bastion-1.
	// bastion-1 -> bastion-1 self is skipped; so app-1 -> bastion-1.
	require.Len(t, edges, 1)
	require.Equal(t, "app-1", edges[0].SrcID)
	require.Equal(t, "bastion-1", edges[0].DstID)
}

func TestGCPFirewallReachability_NoSourceTagsSkipped(t *testing.T) {
	// A world-open or CIDR-only rule (no source tags) is not lateral movement.
	g := NewGraph([]asset.Asset{
		gcpFirewallRule("fw", "vpc1", "", "app"),
		gceInstance("app-1", "vpc1", "app"),
	})
	require.Empty(t, GCPFirewallReachability{}.Correlate(g))
}

func TestGCPFirewallReachability_CrossNetworkExcluded(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpFirewallRule("fw", "vpc1", "bastion", "app"),
		gceInstance("bastion-1", "vpc2", "bastion"), // different network
		gceInstance("app-1", "vpc1", "app"),
	})
	require.Empty(t, GCPFirewallReachability{}.Correlate(g), "no source instance in the rule's network")
}

func TestGCPFirewallReachability_DisabledSkipped(t *testing.T) {
	fw := gcpFirewallRule("fw", "vpc1", "bastion", "app")
	fw.Metadata["disabled"] = "true"
	g := NewGraph([]asset.Asset{
		fw,
		gceInstance("bastion-1", "vpc1", "bastion"),
		gceInstance("app-1", "vpc1", "app"),
	})
	require.Empty(t, GCPFirewallReachability{}.Correlate(g))
}

func TestGCPFirewallReachability_EgressSkipped(t *testing.T) {
	fw := gcpFirewallRule("fw", "vpc1", "bastion", "app")
	fw.Metadata["direction"] = "EGRESS"
	g := NewGraph([]asset.Asset{
		fw,
		gceInstance("bastion-1", "vpc1", "bastion"),
		gceInstance("app-1", "vpc1", "app"),
	})
	require.Empty(t, GCPFirewallReachability{}.Correlate(g))
}

func TestAzureNSGFoldedIntoSharedSG(t *testing.T) {
	// Azure VMs carry their NSGs in nsg_ids; folding that key into the SG index
	// gives them the same connected_via_sg lateral adjacency as AWS.
	nsg := asset.Asset{ID: "nsg-1", Type: "security_group", Provider: asset.ProviderAzure}
	vm1 := asset.Asset{ID: "vm-a", Type: "azure_vm", Provider: asset.ProviderAzure,
		Metadata: map[string]string{"nsg_ids": "nsg-1"}}
	vm2 := asset.Asset{ID: "vm-b", Type: "azure_vm", Provider: asset.ProviderAzure,
		Metadata: map[string]string{"nsg_ids": "nsg-1"}}

	g := NewGraph([]asset.Asset{nsg, vm1, vm2})
	require.Contains(t, g.AssetsBySG(), "nsg-1")
	require.Len(t, g.AssetsBySG()["nsg-1"], 2, "both VMs indexed under the shared NSG")

	edges := SharedSecurityGroup{}.Correlate(g)
	require.NotEmpty(t, edges, "VMs sharing an NSG are connected_via_sg")
	for _, e := range edges {
		require.Equal(t, EdgeConnectedViaSG, e.EdgeType)
		require.Equal(t, "nsg-1", e.DstID)
	}
}
