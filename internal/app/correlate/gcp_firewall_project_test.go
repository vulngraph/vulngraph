package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func fw(project, network, targetTags string) asset.Asset {
	return asset.Asset{
		ID: project + "/firewall/allow", Type: "gcp_firewall", AccountID: project,
		Metadata: map[string]string{
			"network": network, "direction": "INGRESS", "target_tags": targetTags,
		},
	}
}

func fwSourced(project, network, sourceTags, targetTags string) asset.Asset {
	a := fw(project, network, targetTags)
	a.Name = a.ID
	a.Metadata["source_tags"] = sourceTags
	a.Metadata["allowed"] = "tcp:22"
	return a
}

func gce(project, network, tags string) asset.Asset {
	return gceNamed(project, "vm", network, tags)
}

func gceNamed(project, name, network, tags string) asset.Asset {
	return asset.Asset{
		ID: project + "/instance/" + name, Type: "gce_instance", AccountID: project,
		Metadata: map[string]string{"network": network, "network_tags": tags},
	}
}

// metadata["network"] is an unqualified name, and "default" is the auto-created
// network in essentially every GCP project. Without a project comparison, one
// project's firewall would govern every other project's instances, marking
// gce_instances internet-exposed on the strength of another project's rule.
func TestFirewallApplies_RejectsCrossProject(t *testing.T) {
	require.False(t, firewallApplies(
		fw("example-project-f", "default", ""),
		gce("example-project-e", "default", "")),
		"a firewall must never govern an instance in another project")
}

func TestFirewallApplies_AcceptsSameProject(t *testing.T) {
	require.True(t, firewallApplies(
		fw("example-project-e", "default", ""),
		gce("example-project-e", "default", "")))
}

// An empty AccountID must not act as a wildcard that matches everything — that
// is the same failure mode one layer down (see gcp_impersonation.go, where an
// empty bucket produced a mesh of bogus cross-project can_assume edges).
func TestFirewallApplies_EmptyProjectNeverMatches(t *testing.T) {
	require.False(t, firewallApplies(
		fw("", "default", ""),
		gce("", "default", "")))
	require.False(t, firewallApplies(
		fw("", "default", ""),
		gce("example-project-x", "default", "")))
	require.False(t, firewallApplies(
		fw("example-project-x", "default", ""),
		gce("", "default", "")))
}

// The pre-existing gates must still work inside the right project.
func TestFirewallApplies_KeepsExistingGates(t *testing.T) {
	t.Run("different network in the same project", func(t *testing.T) {
		require.False(t, firewallApplies(
			fw("p", "prod-vpc", ""), gce("p", "default", "")))
	})
	t.Run("disabled rule", func(t *testing.T) {
		f := fw("p", "default", "")
		f.Metadata["disabled"] = "true"
		require.False(t, firewallApplies(f, gce("p", "default", "")))
	})
	t.Run("egress direction", func(t *testing.T) {
		f := fw("p", "default", "")
		f.Metadata["direction"] = "EGRESS"
		require.False(t, firewallApplies(f, gce("p", "default", "")))
	})
	t.Run("target tags must intersect", func(t *testing.T) {
		require.False(t, firewallApplies(
			fw("p", "default", "web"), gce("p", "default", "db")))
		require.True(t, firewallApplies(
			fw("p", "default", "web,db"), gce("p", "default", "db")))
	})
}

// firewallApplies guards the GOVERNED side of every rule in this file, but two
// other loops build their endpoint set with their own inline comparison and so
// need the project guard separately. Both were once unguarded and both
// are invisible to the firewallApplies tests above.

// GCPFirewallApplies' tagged branch iterates instances itself rather than
// calling firewallApplies. Without its guard it emitted cross-project
// applies_to edges.
func TestGCPFirewallApplies_TaggedBranchNeverCrossesProjects(t *testing.T) {
	cross := NewGraph([]asset.Asset{
		fw("example-project-f", "default", "web"),
		gce("example-project-e", "default", "web"), // same tag, other project
	})
	require.Empty(t, GCPFirewallApplies{}.Correlate(cross),
		"a tagged rule must not govern a same-tagged instance in another project")

	same := NewGraph([]asset.Asset{
		fw("example-project-e", "default", "web"),
		gce("example-project-e", "default", "web"),
	})
	edges := GCPFirewallApplies{}.Correlate(same)
	require.Len(t, edges, 1, "the in-project pairing must still be emitted")
	require.Equal(t, "example-project-e/instance/vm", edges[0].DstID)
	require.Equal(t, "tagged", edges[0].Properties["scope"])
}

// The whole-network branch keys its destination on AccountID. An accountless
// firewall would emit "gcp-network:/default" — a malformed key that re-collapses
// every project's auto-created network into one node, which is the exact defect
// the project qualifier exists to prevent. Emptiness must therefore suppress the
// edge, not merely be interpolated into it.
func TestGCPFirewallApplies_WholeNetworkNeedsAProject(t *testing.T) {
	accountless := NewGraph([]asset.Asset{fw("", "default", "")})
	require.Empty(t, GCPFirewallApplies{}.Correlate(accountless),
		"an accountless whole-network rule must emit nothing, not a network key with an empty project")

	edges := GCPFirewallApplies{}.Correlate(NewGraph([]asset.Asset{fw("example-project-x", "default", "")}))
	require.Len(t, edges, 1)
	require.Equal(t, "gcp-network:example-project-x/default", edges[0].DstID)
	require.Equal(t, "whole_network", edges[0].Properties["scope"])
}

// GCPFirewallReachability builds its SOURCE set with its own comparison, so
// cross-project lateral movement survived the governed-side fix: a large share of
// deduped-fresh gce→gce sg_allows_from edges linked instances in different
// projects. sg_allows_from is a loaded rel feeding risk propagation, so those
// edges were spreading risk scores across unrelated projects.
//
// The governed side here is deliberately in-project (firewallApplies passes), so
// the ONLY thing that can suppress the edge is the source-side guard.
func TestGCPFirewallReachability_SourceSideNeverCrossesProjects(t *testing.T) {
	cross := NewGraph([]asset.Asset{
		fwSourced("example-project-e", "default", "bastion", "web"),
		gceNamed("example-project-e", "app", "default", "web"),      // governed, same project
		gceNamed("example-project-f", "bast", "default", "bastion"), // source-tagged, OTHER project
	})
	require.Empty(t, GCPFirewallReachability{}.Correlate(cross),
		"a bastion in another project is not a lateral-movement source")

	same := NewGraph([]asset.Asset{
		fwSourced("example-project-e", "default", "bastion", "web"),
		gceNamed("example-project-e", "app", "default", "web"),
		gceNamed("example-project-e", "bast", "default", "bastion"),
	})
	edges := GCPFirewallReachability{}.Correlate(same)
	require.Len(t, edges, 1, "the in-project pairing must still be emitted")
	require.Equal(t, "example-project-e/instance/app", edges[0].SrcID)
	require.Equal(t, "example-project-e/instance/bast", edges[0].DstID)
}
