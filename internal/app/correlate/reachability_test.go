package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

func sg(id, ingress string) asset.Asset {
	return asset.Asset{ID: id, Type: "security_group", Metadata: map[string]string{"ingress": ingress}}
}

func TestSecurityGroupAllows_EmitsSGtoSGEdges(t *testing.T) {
	g := NewGraph([]asset.Asset{
		sg("sg-app", `[{"protocol":"tcp","from_port":443,"to_port":443,"sg_refs":["sg-lb"]}]`),
		sg("sg-lb", `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["0.0.0.0/0"]}]`),
	})

	edges := SecurityGroupAllows{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "sg-app", edges[0].SrcID)
	require.Equal(t, "sg-lb", edges[0].DstID)
	require.Equal(t, EdgeSGAllowsFrom, edges[0].EdgeType)
	require.Equal(t, "tcp:443", edges[0].Properties["ports"])
}

// A self-referencing rule is what lets an SG's members reach each other, so
// it is a self-loop; a world-only rule yields no SG→SG edge.
func TestSecurityGroupAllows_SelfReferenceIsASelfLoop(t *testing.T) {
	g := NewGraph([]asset.Asset{
		sg("sg-1", `[{"protocol":"-1","sg_refs":["sg-1"]},{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`),
	})
	edges := SecurityGroupAllows{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "sg-1", edges[0].SrcID)
	require.Equal(t, "sg-1", edges[0].DstID)
	require.Equal(t, "all", edges[0].Properties["ports"])
}

func TestSecurityGroupAllows_WorldOnlyYieldsNothing(t *testing.T) {
	g := NewGraph([]asset.Asset{
		sg("sg-1", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`),
	})
	require.Empty(t, SecurityGroupAllows{}.Correlate(g))
}

func TestInternetReachability_AWSWorldOpenSG(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"security_groups": "sg-open"}},
		sg("sg-open", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`),
	})

	edges := InternetReachability{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "i-1", edges[0].SrcID)
	require.Equal(t, InternetNodeID, edges[0].DstID)
	require.Equal(t, EdgeExposedToInternet, edges[0].EdgeType)
	require.Equal(t, "aws_sg_world_open", edges[0].Properties["via"])
	require.Equal(t, "sg-open", edges[0].Properties["security_group"])
}

// The graph reads a world-open rule as the CSPM checks do: ranges that
// together span a family count, and a rule without ports (ICMP) is no entry
// point, so a host that only answers ping is not promoted to internet-facing.
func TestInternetReachability_AWSWorldOpenMatchesChecks(t *testing.T) {
	tests := []struct {
		name    string
		ingress string
		ipv6    bool
		ports   string
	}{
		{"tcp 22", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`, false, "tcp:22"},
		{"all traffic", `[{"protocol":"-1","from_port":0,"to_port":0,"cidrs":["0.0.0.0/0"]}]`, false, "all"},
		{"udp over ipv6", `[{"protocol":"udp","from_port":53,"to_port":53,"cidrs":["::/0"]}]`, true, "udp:53"},
		{"split world range", `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["0.0.0.0/1","128.0.0.0/1"]}]`, false, "tcp:443"},
		{"icmp only", `[{"protocol":"icmp","from_port":8,"to_port":0,"cidrs":["0.0.0.0/0"]}]`, false, ""},
		{"icmpv6 only", `[{"protocol":"58","from_port":-1,"to_port":-1,"cidrs":["::/0"]}]`, true, ""},
		{"icmp beside a private tcp rule", `[{"protocol":"icmp","from_port":-1,"to_port":-1,"cidrs":["0.0.0.0/0"]},{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["10.0.0.0/8"]}]`, false, ""},
		{"half the internet", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/1"]}]`, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			world, inst := cidrset.WorldV4, asset.Asset{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4",
				Metadata: map[string]string{"security_groups": "sg-1"}}
			if tt.ipv6 {
				world, inst.PublicIP = cidrset.WorldV6, ""
				inst.Metadata["ipv6_addresses"] = "2001:db8:1::10"
			}
			require.Equal(t, tt.ports, worldOpenPorts(sg("sg-1", tt.ingress), world))
			g := NewGraph([]asset.Asset{inst, sg("sg-1", tt.ingress)})
			edges := InternetReachability{}.Correlate(g)
			if tt.ports == "" {
				require.Empty(t, edges)
				return
			}
			require.Len(t, edges, 1)
			require.Equal(t, tt.ports, edges[0].Properties["ports"])
		})
	}
}

// An instance with no public IPv4 is still internet-facing through a global
// IPv6 address, but only a rule spanning the IPv6 internet opens it; a
// unique-local address is not routable and a private subnet demotes it.
func TestInternetReachability_AWSIPv6OnlyInstance(t *testing.T) {
	const (
		v6World = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["::/0"]}]`
		v4World = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`
	)
	inst := func(v6, inPublic, inPublicV6 string) asset.Asset {
		meta := map[string]string{"security_groups": "sg-1", "ipv6_addresses": v6}
		if inPublic != "" {
			meta["in_public_subnet"] = inPublic
		}
		if inPublicV6 != "" {
			meta["in_public_subnet_v6"] = inPublicV6
		}
		return asset.Asset{ID: "i-1", Type: "ec2_instance", Metadata: meta}
	}
	tests := []struct {
		name     string
		inst     asset.Asset
		ingress  string
		exposed  bool
		basis    string
		demotion bool
	}{
		{"global IPv6 and a ::/0 rule", inst("2001:db8:1::10", "true", "true"), v6World, true, basisRouteConfirmed, false},
		{"global IPv6 but only an IPv4 world rule", inst("2001:db8:1::10", "true", "true"), v4World, false, "", false},
		{"unique-local IPv6", inst("fd00::10", "true", "true"), v6World, false, "", false},
		{"no IPv6 and no public IPv4", inst("", "true", "true"), v6World, false, "", false},
		{"private subnet demotes", inst("2001:db8:1::10", "false", "false"), v6World, false, "", true},
		{"IPv4-only IGW route demotes an IPv6-only instance", inst("2001:db8:1::10", "true", "false"), v6World, false, "", true},
		{"unknown IPv6 routing keeps the edge as route_unknown", inst("2001:db8:1::10", "true", ""), v6World, true, basisRouteUnknown, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGraph([]asset.Asset{tt.inst, sg("sg-1", tt.ingress)})
			edges := InternetReachability{}.Correlate(g)
			if !tt.exposed {
				require.Empty(t, edges)
			} else {
				require.Len(t, edges, 1)
				require.Equal(t, "aws_sg_world_open", edges[0].Properties["via"])
				require.Equal(t, "tcp:22", edges[0].Properties["ports"])
				require.Equal(t, tt.basis, edges[0].Properties["exposure_basis"])
			}
			require.Equal(t, tt.demotion, len(InternetReachability{}.Demotions(g)) == 1)
		})
	}
}

// Each address family is its own entry point: a public IPv4 address is opened
// only by a rule spanning the IPv4 internet and routed by the IPv4 IGW route,
// a global IPv6 address only by one spanning ::/0 and the IPv6 route.
func TestInternetReachability_AWSDualStackPerFamily(t *testing.T) {
	const (
		v4World   = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`
		v6World   = `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["::/0"]}]`
		bothWorld = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]},{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["::/0"]}]`
	)
	inst := func(publicIP, v6, inPublic, inPublicV6 string) asset.Asset {
		meta := map[string]string{"security_groups": "sg-1"}
		for k, v := range map[string]string{"ipv6_addresses": v6, "in_public_subnet": inPublic, "in_public_subnet_v6": inPublicV6} {
			if v != "" {
				meta[k] = v
			}
		}
		return asset.Asset{ID: "i-1", Type: "ec2_instance", PublicIP: publicIP, Metadata: meta}
	}
	tests := []struct {
		name     string
		inst     asset.Asset
		ingress  string
		family   string // "" = no edge
		ports    string
		demotion bool
	}{
		{"IPv4 only, ::/0 rule", inst("1.2.3.4", "", "true", ""), v6World, "", "", false},
		{"IPv4 only, 0.0.0.0/0 rule", inst("1.2.3.4", "", "true", ""), v4World, "ipv4", "tcp:22", false},
		{"IPv4 plus unique-local IPv6, ::/0 rule", inst("1.2.3.4", "fd00::10", "true", "true"), v6World, "", "", false},
		{"dual-stack, ::/0 rule, IPv6 IGW route", inst("1.2.3.4", "2001:db8:1::10", "true", "true"), v6World, "ipv6", "tcp:443", false},
		{"dual-stack, ::/0 rule, IPv4-only IGW route", inst("1.2.3.4", "2001:db8:1::10", "true", "false"), v6World, "", "", true},
		{"dual-stack, 0.0.0.0/0 rule, IPv4 IGW route", inst("1.2.3.4", "2001:db8:1::10", "true", "false"), v4World, "ipv4", "tcp:22", false},
		{"dual-stack, 0.0.0.0/0 rule, private subnet", inst("1.2.3.4", "2001:db8:1::10", "false", "true"), v4World, "", "", true},
		{"dual-stack, both rules, only IPv6 routed", inst("1.2.3.4", "2001:db8:1::10", "false", "true"), bothWorld, "ipv6", "tcp:443", false},
		{"dual-stack, both rules, both routed", inst("1.2.3.4", "2001:db8:1::10", "true", "true"), bothWorld, "ipv4", "tcp:22", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGraph([]asset.Asset{tt.inst, sg("sg-1", tt.ingress)})
			edges := InternetReachability{}.Correlate(g)
			if tt.family == "" {
				require.Empty(t, edges)
			} else {
				require.Len(t, edges, 1)
				require.Equal(t, tt.family, edges[0].Properties["address_family"])
				require.Equal(t, tt.ports, edges[0].Properties["ports"])
				require.Equal(t, basisRouteConfirmed, edges[0].Properties["exposure_basis"])
			}
			require.Equal(t, tt.demotion, len(InternetReachability{}.Demotions(g)) == 1)
		})
	}
}

func TestInternetReachability_AWSPublicIPButNoWorldOpen(t *testing.T) {
	// A public IP alone is NOT exposure: the SG only allows a peer SG, not the world.
	g := NewGraph([]asset.Asset{
		{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"security_groups": "sg-tight"}},
		sg("sg-tight", `[{"protocol":"tcp","from_port":443,"to_port":443,"sg_refs":["sg-lb"]}]`),
	})
	require.Empty(t, InternetReachability{}.Correlate(g))
}

func TestInternetReachability_GCPFirewallOpenApplies(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "proj/vm", Type: "gce_instance", AccountID: "proj", PublicIP: "34.1.2.3",
			Metadata: map[string]string{"network": "default", "network_tags": "web"}},
		{ID: "proj/firewall/allow-http", Type: "gcp_firewall", AccountID: "proj",
			Metadata: map[string]string{
				"network": "default", "direction": "INGRESS",
				"open_to_internet": "true", "target_tags": "web",
			}},
	})

	edges := InternetReachability{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "proj/vm", edges[0].SrcID)
	require.Equal(t, "gcp_firewall_open", edges[0].Properties["via"])
}

func TestInternetReachability_GCPFirewallWrongTagDoesNotApply(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "proj/vm", Type: "gce_instance", AccountID: "proj", PublicIP: "34.1.2.3",
			Metadata: map[string]string{"network": "default", "network_tags": "db", "firewall_rules_complete": "true"}},
		{ID: "proj/firewall/allow-http", Type: "gcp_firewall", AccountID: "proj",
			Metadata: map[string]string{
				"network": "default", "direction": "INGRESS",
				"open_to_internet": "true", "target_tags": "web",
			}},
	})
	require.Empty(t, InternetReachability{}.Correlate(g))
}

// TestInternetReachability_ManagedPublic pins the tier contract: BOTH tiers get
// an exposed_to_internet edge, and the tier rides on the edge as public_access.
//
// It used to pin the inverse — possible-tier assets got no edge at all — which
// is the defect this replaced. A scoring grade was deciding graph construction,
// and because exposed_to_internet is the only BFS seed, every serverless entry
// point whose collector cannot PROVE unauthenticated access (most
// api_gateway, lambda_function and cloud_function assets) sat
// at infinite distance from the internet together with everything downstream.
func TestInternetReachability_ManagedPublic(t *testing.T) {
	g := NewGraph([]asset.Asset{
		// Legacy public=true with no tier — an open network entry point. Absent
		// grade must read as confirmed, or every pre-tier collector silently
		// demotes to a 1-hop seed.
		{ID: "p/lb", Type: "load_balancer", Metadata: map[string]string{"public": "true"}},
		// Possible tier: network-reachable but credential/IAM-gated.
		{ID: "p/cloudsql/db", Type: "cloudsql_instance", Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessPossible}},
		{ID: "p/cloudrun/api", Type: "cloudrun_service", Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessPossible}},
		{ID: "sub/storage", Type: "azure_storage_account", Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessPossible}},
		// Confirmed tier (e.g. a wildcard-invocable lambda).
		{ID: "p/fn", Type: "lambda_function", Metadata: map[string]string{"public": "true", "public_access": asset.PublicAccessConfirmed}},
		{ID: "p/cloudsql/private", Type: "cloudsql_instance", Metadata: map[string]string{"public": "false"}},
	})
	via := map[string]string{}
	tier := map[string]string{}
	for _, e := range (InternetReachability{}).Correlate(g) {
		require.Equal(t, InternetNodeID, e.DstID)
		via[e.SrcID] = e.Properties["via"]
		tier[e.SrcID] = e.Properties[asset.EdgePropPublicAccess]
	}
	require.Equal(t, "managed_public", via["p/lb"])
	require.Equal(t, "managed_public", via["p/fn"])
	require.Equal(t, asset.PublicAccessConfirmed, tier["p/lb"], "an untiered legacy public flag must default to confirmed")
	require.Equal(t, asset.PublicAccessConfirmed, tier["p/fn"])

	for _, id := range []string{"p/cloudsql/db", "p/cloudrun/api", "sub/storage"} {
		require.Contains(t, via, id, "the possible tier must still produce a seed edge")
		require.Equal(t, asset.PublicAccessPossible, tier[id],
			"the possible tier must be carried on the edge, not encoded as the edge's absence")
	}
	require.NotContains(t, via, "p/cloudsql/private", "public=false is not an entry point at either tier")
}

// TestInternetReachability_ObservedRouteAndSGConfirmNetworkPath pins that an
// network topology with an observed public route and world-open SG confirms
// a path even when the asset carries a possible hint. Unknown routing is
// separately tested as possible.
func TestInternetReachability_ObservedRouteAndSGConfirmNetworkPath(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"security_groups": "sg-1", "public_access": asset.PublicAccessPossible, "in_public_subnet": "true"}},
		{ID: "sg-1", Type: "security_group",
			Metadata: map[string]string{"ingress": `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`}},
	})
	edges := InternetReachability{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "aws_sg_world_open", edges[0].Properties["via"])
	require.Equal(t, asset.PublicAccessConfirmed, edges[0].Properties[asset.EdgePropPublicAccess],
		"the tier grades the EVIDENCE, not the asset — an observed world-open rule is confirmed")
}

func TestGCPFirewallApplies_WholeNetworkEmitsNetworkEdge(t *testing.T) {
	// Whole-network rules (no target tags) now emit fw→network (not fw→instance)
	// to avoid the O(firewalls×instances) cardinality explosion.
	g := NewGraph([]asset.Asset{
		{ID: "proj/vm", Type: "gce_instance", AccountID: "proj",
			Metadata: map[string]string{"network": "default", "network_tags": ""}},
		{ID: "proj/firewall/all", Type: "gcp_firewall", AccountID: "proj",
			Metadata: map[string]string{"network": "default", "direction": "INGRESS", "target_tags": ""}},
	})

	edges := GCPFirewallApplies{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "proj/firewall/all", edges[0].SrcID)
	require.Equal(t, "gcp-network:proj/default", edges[0].DstID) // project-qualified
	require.Equal(t, "vpc_network", edges[0].DstType)
	require.Equal(t, EdgeFirewallAppliesTo, edges[0].EdgeType)
	require.Equal(t, "whole_network", edges[0].Properties["scope"])
}

func TestGCPFirewallApplies_SkipsDisabled(t *testing.T) {
	// Disabled firewalls produce no edges regardless of target tags or network.
	g := NewGraph([]asset.Asset{
		{ID: "proj/vm", Type: "gce_instance", AccountID: "proj", Metadata: map[string]string{"network": "default"}},
		{ID: "fw-disabled", Type: "gcp_firewall", AccountID: "proj",
			Metadata: map[string]string{"network": "default", "direction": "INGRESS", "disabled": "true"}},
	})
	require.Empty(t, GCPFirewallApplies{}.Correlate(g))
}

func TestGCPFirewallApplies_CrossNetworkNoInstanceEdge(t *testing.T) {
	// A firewall on "other" network emits fw→gcp-network:<project>/other but never touches
	// instances on "default" network.
	g := NewGraph([]asset.Asset{
		{ID: "proj/vm", Type: "gce_instance", AccountID: "proj", Metadata: map[string]string{"network": "default"}},
		{ID: "fw-othernet", Type: "gcp_firewall", AccountID: "proj",
			Metadata: map[string]string{"network": "other", "direction": "INGRESS"}},
	})
	edges := GCPFirewallApplies{}.Correlate(g)
	require.Len(t, edges, 1)
	// Project-qualified: a bare "gcp-network:default" key collapsed every
	// project's auto-created network into one node.
	require.Equal(t, "gcp-network:proj/other", edges[0].DstID) // its own network, not proj/vm
}

// A managed Kubernetes control plane whose endpoint is public and whose
// authorized-network allowlist is the whole internet is an entry point. Both
// collectors already graded exactly that as public_access=possible and nothing
// consumed it: neither cluster type reached publicManaged, so no seed edge was
// ever emitted and EKS and GKE clusters sat at infinite distance from the
// internet along with everything downstream.
//
// Keyed on public_access, not `public`: these collectors grade the tier and
// never set the boolean, which is precisely why the managed-services branch
// skipped them.
func TestInternetReachability_ManagedClusterEndpoints(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "arn:eks/open", Type: "eks_cluster", Metadata: map[string]string{
			"endpoint_public_access": "true", "public_access": asset.PublicAccessPossible}},
		{ID: "gke/open", Type: "gke_cluster", Metadata: map[string]string{
			"endpoint_public_access": "true", "public_access": asset.PublicAccessPossible}},
		// Public endpoint, but the allowlist was unreadable so the collector
		// declined to grade it. No key, no seed — unproven is not exposed.
		{ID: "arn:eks/ungraded", Type: "eks_cluster", Metadata: map[string]string{
			"endpoint_public_access": "true"}},
		// Private endpoint.
		{ID: "arn:eks/private", Type: "eks_cluster", Metadata: map[string]string{
			"endpoint_public_access": "false"}},
	})

	tier := map[string]string{}
	for _, e := range (InternetReachability{}).Correlate(g) {
		tier[e.SrcID] = e.Properties[asset.EdgePropPublicAccess]
	}

	require.Equal(t, asset.PublicAccessPossible, tier["arn:eks/open"],
		"a public EKS API server open to 0.0.0.0/0 is a possible-tier entry point")
	require.Equal(t, asset.PublicAccessPossible, tier["gke/open"])
	require.NotContains(t, tier, "arn:eks/ungraded",
		"an ungraded endpoint is unproven, and must not be seeded")
	require.NotContains(t, tier, "arn:eks/private")
}

// A public S3/GCS bucket is a direct unauthenticated internet entry point —
// same class of fact as a public storage account, which was already seeded.
// Before this, aws-s3-public-bucket and gcp-gcs-public-bucket were checks-only:
// the bucket carried no exposed_to_internet edge at all, so its blast radius
// (anything DSPM classified as PII/financial inside it) never reached the BFS.
func TestInternetReachability_PublicBuckets(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "b/s3-open", Type: "s3_bucket", Metadata: map[string]string{
			"public": "true", "public_access": asset.PublicAccessConfirmed}},
		// S3's own possible tier: public-access-block missing/not locked, no
		// observed public policy or ACL.
		{ID: "b/s3-unblocked", Type: "s3_bucket", Metadata: map[string]string{
			"public": "true", "public_access": asset.PublicAccessPossible}},
		{ID: "b/s3-private", Type: "s3_bucket", Metadata: map[string]string{"public": "false"}},
		// GCS carries only the plain boolean, no tier key — managedTier's
		// no-tier-key-means-confirmed fallback must still apply here exactly as
		// it does for the legacy load_balancer case above.
		{ID: "b/gcs-open", Type: "gcs_bucket", Metadata: map[string]string{"public": "true"}},
		{ID: "b/gcs-private", Type: "gcs_bucket", Metadata: map[string]string{"public": "false"}},
	})

	tier := map[string]string{}
	for _, e := range (InternetReachability{}).Correlate(g) {
		tier[e.SrcID] = e.Properties[asset.EdgePropPublicAccess]
	}

	require.Equal(t, asset.PublicAccessConfirmed, tier["b/s3-open"])
	require.Equal(t, asset.PublicAccessPossible, tier["b/s3-unblocked"])
	require.Equal(t, asset.PublicAccessConfirmed, tier["b/gcs-open"],
		"a bucket with no tier key at all must default to confirmed, like the legacy load_balancer case")
	require.NotContains(t, tier, "b/s3-private")
	require.NotContains(t, tier, "b/gcs-private")
}

// A publicly-accessible RDS instance is network-reachable but never
// unauthenticated — always the possible tier, never confirmed, matching
// aws-rds-publicly-accessible's own documented severity model ("network
// reachability, not confirmed unauthenticated exposure"). Before this,
// rds_instance reached no seed mechanism at all: indexed only for DSPM
// classification, so it sat at infinite distance from the internet regardless
// of PubliclyAccessible.
func TestInternetReachability_PubliclyAccessibleRDS(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "db/public", Type: "rds_instance", Metadata: map[string]string{"publicly_accessible": "true"}},
		{ID: "db/private", Type: "rds_instance", Metadata: map[string]string{"publicly_accessible": "false"}},
	})

	tier := map[string]string{}
	for _, e := range (InternetReachability{}).Correlate(g) {
		tier[e.SrcID] = e.Properties[asset.EdgePropPublicAccess]
	}

	require.Equal(t, asset.PublicAccessPossible, tier["db/public"],
		"publicly_accessible must always seed at possible, never confirmed — credentials are still required")
	require.NotContains(t, tier, "db/private")
}

// A leaked KMS/ECR/SQS/SNS resource policy is unauthenticated access, full
// stop — always confirmed, no possible tier, because there is no credential to
// check for a wildcard-principal grant with no restricting condition. Before
// this, all four types were excluded from Ladybug sync entirely
// (asset.NeverSyncTypes) — worse than merely unreachable, since the type could
// never become a Ladybug node under any circumstance, regardless of how public
// the resource was.
func TestInternetReachability_LeakedResourcePolicies(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "key/leaked", Type: "kms_key", Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}},
		{ID: "repo/leaked", Type: "ecr_repository", Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}},
		{ID: "q/leaked", Type: "sqs_queue", Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}},
		{ID: "topic/leaked", Type: "sns_topic", Metadata: map[string]string{"public_access": asset.PublicAccessConfirmed}},
		// Read, and found closed — must NOT seed.
		{ID: "key/closed", Type: "kms_key", Metadata: map[string]string{"public_access": asset.PublicAccessNone}},
	})

	tier := map[string]string{}
	for _, e := range (InternetReachability{}).Correlate(g) {
		tier[e.SrcID] = e.Properties[asset.EdgePropPublicAccess]
	}

	for _, id := range []string{"key/leaked", "repo/leaked", "q/leaked", "topic/leaked"} {
		require.Equal(t, asset.PublicAccessConfirmed, tier[id], "%s must seed confirmed", id)
	}
	require.NotContains(t, tier, "key/closed")
}

// A public EBS/RDS snapshot, AMI, GCP image/snapshot, or internet-exportable
// Azure disk is directly copyable by anyone with no credential — confirmed
// tier, same reasoning as the leaked resource-policy cases above. Before this,
// all six types had zero graph presence beyond the bare asset node: no case in
// NewGraph's switch, absent from correlationTypes and InterestedIn, despite
// their own checks (aws-ebs-snapshot-public etc.) firing correctly all along.
func TestInternetReachability_PublicSnapshots(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "snap/ebs-open", Type: "ebs_snapshot", Metadata: map[string]string{"public": "true"}},
		{ID: "snap/ebs-closed", Type: "ebs_snapshot", Metadata: map[string]string{"public": "false"}},
		{ID: "snap/rds-open", Type: "rds_snapshot", Metadata: map[string]string{"public": "true"}},
		{ID: "ami/open", Type: "ami", Metadata: map[string]string{"public": "true"}},
		{ID: "img/gcp-open", Type: "gcp_image", Metadata: map[string]string{"public": "true"}},
		{ID: "snap/gcp-open", Type: "gcp_disk_snapshot", Metadata: map[string]string{"public": "true"}},
		// Azure uses a different metadata key from the other five.
		{ID: "disk/azure-open", Type: "azure_disk", Metadata: map[string]string{"internet_exportable": "true"}},
		{ID: "disk/azure-closed", Type: "azure_disk", Metadata: map[string]string{"internet_exportable": "false"}},
	})

	tier := map[string]string{}
	for _, e := range (InternetReachability{}).Correlate(g) {
		tier[e.SrcID] = e.Properties[asset.EdgePropPublicAccess]
	}

	for _, id := range []string{"snap/ebs-open", "snap/rds-open", "ami/open", "img/gcp-open", "snap/gcp-open", "disk/azure-open"} {
		require.Equal(t, asset.PublicAccessConfirmed, tier[id], "%s must seed confirmed", id)
	}
	require.NotContains(t, tier, "snap/ebs-closed")
	require.NotContains(t, tier, "disk/azure-closed")
}
