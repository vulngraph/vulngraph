package correlate

import (
	"iter"
	"net"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// maxDNSTargetsPerValue caps how many assets a single DNS value may fan out to.
// A value resolving to more than this is an anycast / shared-load-balancer IP
// where the edges connect one record to many unrelated assets and carry no
// lateral-movement signal — capping at the source keeps dns_points_to bulk
// volume under the per-type sync limit (asset/repo.go) instead of letting the
// downstream ORDER-BY truncation silently drop the same records every rebuild.
const maxDNSTargetsPerValue = 25

// DNSPointsTo links DNS records to the infrastructure they resolve to. For each
// dns_record, every value is matched against the inventory: IP values against
// public-IP-bearing assets (EC2, Elastic IP, GCE instance), hostname values
// against domain-bearing assets (load balancers). A match emits a dns_points_to
// edge. Cross-account and cross-cloud links fall out naturally because the index
// spans the whole inventory, not one connector.
//
// A dns_record with values but no match is a dangling-record candidate. This is
// also why NewGraph must never index a DNS name asset as a resolution target: a
// record resolving only to other records would read as resolved while pointing
// at nothing real.
type DNSPointsTo struct{}

func (DNSPointsTo) Name() string { return "dns_points_to" }

// dnsPointsToTargetTypes are the only asset types this rule may emit as a
// dns_points_to destination — everything after "dns_record" in InterestedIn.
// NewGraph's byPublicIP/byDomain index is NOT restricted to this set — any
// non-DNS-name asset with a PublicIP or Domain gets indexed, promoted type or
// not — so Correlate must filter at match time, or a future asset type that
// starts carrying either field becomes a silent match the moment its value
// collides with a DNS record's. Filtering here rather than in the shared
// index, since the index is used only by this rule but a blanket
// index-level restriction would risk excluding a legitimately DNS-matchable
// type added to InterestedIn later.
var dnsPointsToTargetTypes = map[string]bool{
	"ec2_instance": true, "elastic_ip": true, "load_balancer": true,
	"gce_instance": true, "gcp_forwarding_rule": true, "azure_public_ip": true, "azure_vm": true,
}

func (DNSPointsTo) InterestedIn() []string {
	return []string{
		"dns_record", "ec2_instance", "elastic_ip", "load_balancer",
		"gce_instance", "gcp_forwarding_rule", "azure_public_ip", "azure_vm",
	}
}

func (r DNSPointsTo) Correlate(g Graph) []asset.Edge {
	return slices.Collect(r.Edges(g))
}

func (DNSPointsTo) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		for _, rec := range g.DNSRecords() {
			for _, val := range splitValues(rec.Metadata["values"]) {
				var targets []asset.Asset
				if net.ParseIP(val) != nil {
					targets = g.AssetsByPublicIP(val)
				} else {
					targets = g.AssetsByDomain(val)
				}
				// Deterministic truncation: sort by ID before capping so a value
				// over the cap drops the same tail every rebuild rather than a
				// nondeterministic subset (the map-iteration order of the index).
				if len(targets) > maxDNSTargetsPerValue {
					targets = slices.Clone(targets)
					slices.SortFunc(targets, func(a, b asset.Asset) int {
						return strings.Compare(a.ID, b.ID)
					})
					targets = targets[:maxDNSTargetsPerValue]
				}
				// No self/record-to-record guard is needed here: NewGraph keeps DNS
				// name assets out of byPublicIP/byDomain entirely, so a target is
				// always infrastructure.
				for _, t := range targets {
					if !dnsPointsToTargetTypes[t.Type] {
						continue
					}
					if !yield(dnsResolutionEdge(rec.ID, t.ID, t.Type, val)) {
						return
					}
				}
			}
		}
	}
}

func dnsResolutionEdge(record, target, kind, value string) asset.Edge {
	return asset.Edge{SrcID: record, SrcType: "dns_record", DstID: target, DstType: kind,
		EdgeType: EdgeDNSPointsTo, Properties: map[string]string{
			"origin": edgeOrigin, "rule": "dns_points_to", "matched_value": value,
		}}
}

// splitValues parses a dns_record's comma-joined values into trimmed,
// non-empty entries.
func splitValues(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
