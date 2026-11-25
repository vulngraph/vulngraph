package correlate

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// GCPFirewallApplies links a gcp_firewall to what it governs.
// Whole-network rules (no target tags) emit fw→network (1 edge, not N×instances).
// Tagged rules emit fw→instance only for instances whose tags intersect. This
// keeps the edge count from growing as O(firewalls×instances), which was a
// major cause of worker OOM kills on large projects.
type GCPFirewallApplies struct{}

func (GCPFirewallApplies) Name() string { return "applies_to" }

func (GCPFirewallApplies) InterestedIn() []string {
	return []string{"gcp_firewall", "gce_instance", "vpc_network"}
}

func (GCPFirewallApplies) Correlate(g Graph) []asset.Edge {
	var edges []asset.Edge
	for _, fw := range g.GCPFirewalls() {
		if fw.Metadata["disabled"] == "true" {
			continue
		}
		if dir := fw.Metadata["direction"]; dir != "" && dir != "INGRESS" {
			continue
		}
		network := fw.Metadata["network"]
		targets := splitValues(fw.Metadata["target_tags"])
		targetSAs := splitValues(fw.Metadata["target_sas"])

		if len(targets) == 0 && len(targetSAs) == 0 {
			// Whole-network rule: emit fw→network (1 edge). Traversal recovers
			// which instances are affected via (fw)-[:AppliesTo]->(net)<-[:InVPC]-(inst).
			if network != "" && fw.AccountID != "" {
				edges = append(edges, asset.Edge{
					SrcID: fw.ID, SrcType: "gcp_firewall",
					// Project-qualified: a bare "gcp-network:default" key would collapse
					// every project's auto-created network into one node.
					DstID: "gcp-network:" + fw.AccountID + "/" + network, DstType: "vpc_network",
					EdgeType: EdgeFirewallAppliesTo,
					Properties: map[string]string{
						"origin": edgeOrigin,
						"rule":   "applies_to",
						"scope":  "whole_network",
					},
				})
			}
			continue
		}

		// Targeted rule (tags or service accounts): only emit edges to instances
		// in the SAME PROJECT it targets. The project check is the same one
		// firewallApplies makes and for the same reason — this loop has its own
		// inline network comparison rather than calling that helper, so it needs
		// the guard separately.
		scope := "tagged"
		if len(targetSAs) > 0 {
			scope = "service_account"
		}
		for _, inst := range g.GCEInstances() {
			if fw.AccountID == "" || fw.AccountID != inst.AccountID {
				continue
			}
			if inst.Metadata["network"] != network {
				continue
			}
			if !firewallTargets(fw, inst) {
				continue
			}
			edges = append(edges, asset.Edge{
				SrcID: fw.ID, SrcType: "gcp_firewall",
				DstID: inst.ID, DstType: "gce_instance",
				EdgeType: EdgeFirewallAppliesTo,
				Properties: map[string]string{
					"origin": edgeOrigin,
					"rule":   "applies_to",
					"scope":  scope,
				},
			})
		}
	}
	return edges
}

// maxFirewallReachEdgesPerRule caps the instance→instance fan-out one firewall
// rule may produce (governed × source instances). A permissive tag-based rule in
// a large project is O(N²); the cap keeps a single rule from flooding the graph,
// mirroring the applies_to O(N²) OOM lesson. Deterministic (instances iterate in
// stable index order); truncation is logged by the caller via the edge count.
const maxFirewallReachEdgesPerRule = 2000

// GCPFirewallReachability projects tag-based intra-VPC ingress into asset→asset
// sg_allows_from edges — the GCP counterpart to SecurityGroupAllows. A firewall
// rule that admits ingress from source-tagged instances means each governed
// instance "permits ingress from" each source instance; that lateral adjacency
// is invisible today because gcp_firewall is never loaded into Ladybug as a node.
// World-open ingress (0.0.0.0/0) is deliberately NOT emitted here — that is
// internet exposure, owned by InternetReachability, not lateral movement.
//
// Reuses the loaded sg_allows_from edge type (no SchemaVersion bump). Like AWS
// sg_allows_from these are query-traversable and feed risk BFS but are not in
// the reach set, so they don't extend internet_hops.
type GCPFirewallReachability struct{}

func (GCPFirewallReachability) Name() string { return "sg_allows_from" }

func (GCPFirewallReachability) InterestedIn() []string {
	return []string{"gcp_firewall", "gce_instance"}
}

func (GCPFirewallReachability) Correlate(g Graph) []asset.Edge {
	var edges []asset.Edge
	for _, fw := range g.GCPFirewalls() {
		if fw.Metadata["disabled"] == "true" {
			continue
		}
		if dir := fw.Metadata["direction"]; dir != "" && dir != "INGRESS" {
			continue
		}
		sourceTags := splitValues(fw.Metadata["source_tags"])
		if len(sourceTags) == 0 {
			continue // no source tags → nothing to link laterally (world-open is InternetReachability's job)
		}
		network := fw.Metadata["network"]

		// Source instances: SAME PROJECT, same network, network_tags ∩ source_tags.
		//
		// firewallApplies guards the GOVERNED side below, but this loop builds the
		// SOURCE side with its own comparison, so it needs the same project guard
		// separately — otherwise cross-project lateral movement leaks into
		// sg_allows_from, which feeds risk propagation across unrelated projects.
		var sources []asset.Asset
		for _, inst := range g.GCEInstances() {
			if fw.AccountID == "" || fw.AccountID != inst.AccountID {
				continue
			}
			if inst.Metadata["network"] == network &&
				intersects(sourceTags, splitValues(inst.Metadata["network_tags"])) {
				sources = append(sources, inst)
			}
		}
		if len(sources) == 0 {
			continue
		}

		ports := fw.Metadata["allowed"]
		count := 0
	governedLoop:
		for _, gov := range g.GCEInstances() {
			if !firewallApplies(fw, gov) {
				continue
			}
			for _, src := range sources {
				if src.ID == gov.ID {
					continue
				}
				if count >= maxFirewallReachEdgesPerRule {
					break governedLoop
				}
				count++
				edges = append(edges, asset.Edge{
					SrcID: gov.ID, SrcType: "gce_instance", // governed instance permits ingress...
					DstID: src.ID, DstType: "gce_instance", // ...from the source-tagged instance
					EdgeType: EdgeSGAllowsFrom,
					Properties: map[string]string{
						"origin":   edgeOrigin,
						"rule":     "gcp_firewall_reachability",
						"ports":    ports,
						"firewall": fw.Name,
					},
				})
			}
		}
	}
	return edges
}

// firewallApplies reports whether an INGRESS firewall rule governs an instance:
// SAME PROJECT, same network, not disabled, and target tags either absent (whole
// network) or overlapping the instance's network tags.
//
// The project check is load-bearing, not defence in depth. metadata["network"]
// is an unqualified network NAME, and "default" is the auto-created network's
// name in essentially every GCP project, so without an account_id comparison
// every "default"-network firewall in the estate would govern every
// "default"-network instance in every other project too.
//
// Shared VPC (a service project governed by a host project's rules) would be
// the legitimate cross-project case, but it is not supported today.
// If it is ever adopted, this guard must become a host-project-aware network
// key, not a plain AccountID comparison.
//
// Comparing AccountID (the GCP project) rather than re-keying the network name
// is deliberate: it is one comparison, it needs no collector change, and two
// networks in the same project genuinely cannot share a name.
func firewallApplies(fw, inst asset.Asset) bool {
	if fw.AccountID == "" || fw.AccountID != inst.AccountID {
		return false
	}
	fwNet := fw.Metadata["network"]
	if fwNet == "" || fwNet != inst.Metadata["network"] {
		return false
	}
	if fw.Metadata["disabled"] == "true" {
		return false
	}
	if dir := fw.Metadata["direction"]; dir != "" && dir != "INGRESS" {
		return false
	}
	return firewallTargets(fw, inst)
}

// firewallTargets applies a rule's target scoping to a same-network instance:
// target service accounts (matched against the SA the instance runs as) or
// target tags, and the whole network when the rule names neither.
func firewallTargets(fw, inst asset.Asset) bool {
	if sas := splitValues(fw.Metadata["target_sas"]); len(sas) > 0 {
		sa := instanceServiceAccount(inst)
		return sa != "" && intersects(sas, []string{sa})
	}
	targets := splitValues(fw.Metadata["target_tags"])
	if len(targets) == 0 {
		return true // applies to the whole network
	}
	return intersects(targets, splitValues(inst.Metadata["network_tags"]))
}

func intersects(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok {
			return true
		}
	}
	return false
}
