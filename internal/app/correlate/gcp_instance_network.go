package correlate

import (
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// This is the collector's per-interface evidence. An absent legacy value does
// not establish that a VM lacks another interface or an external IPv6 address.
type gceNIC struct {
	Network      string   `json:"network"`
	PrivateIPv4  string   `json:"private_ipv4"`
	PublicIPv4   string   `json:"public_ipv4"`
	ExternalIPv6 []string `json:"external_ipv6"`
	Unknown      bool     `json:"unknown"`
}

type gceDestination struct {
	prefix  netip.Prefix
	v6      bool
	unknown bool
}

func gceNICs(inst asset.Asset) []gceNIC {
	if raw, present := inst.Metadata["network_interfaces"]; present {
		var nics []gceNIC
		if json.Unmarshal([]byte(raw), &nics) == nil && nics != nil {
			return nics
		}
		return []gceNIC{{Network: inst.Metadata["network"], Unknown: true}}
	}
	if inst.PublicIP == "" {
		if inst.Metadata["external_ip_configured"] == "true" {
			// Legacy collection scanned every access config but kept only
			// the first NIC's IPv4 address/network in top-level fields.
			// The public endpoint may belong to a different NIC or family.
			return []gceNIC{{Unknown: true}}
		}
		return nil
	}
	return []gceNIC{{Network: inst.Metadata["network"], PrivateIPv4: inst.PrivateIP,
		PublicIPv4: inst.PublicIP, Unknown: true}}
}

func gceDestinations(n gceNIC) []gceDestination {
	var out []gceDestination
	if n.PublicIPv4 != "" {
		public, err := netip.ParseAddr(n.PublicIPv4)
		d, known := addressPrefix(n.PrivateIPv4)
		known = known && d.Addr().Is4()
		if !known {
			d = netip.Prefix{}
		}
		out = append(out, gceDestination{prefix: d, unknown: !known || err != nil || !public.Is4()})
	}
	for _, v := range n.ExternalIPv6 {
		if p, ok := addressPrefix(v); ok && p.Addr().Is6() {
			out = append(out, gceDestination{prefix: p, v6: true})
		} else {
			out = append(out, gceDestination{v6: true, unknown: true})
		}
	}
	if n.Unknown {
		out = append(out, gceDestination{unknown: true}, gceDestination{v6: true, unknown: true})
	}
	return out
}

func gceExposure(g Graph, inst asset.Asset) (asset.Edge, bool) {
	var possible asset.Edge
	budget := 100_000
	for _, n := range gceNICs(inst) {
		var rules []worldFirewallRule
		var destinations []string
		for _, fw := range g.GCPFirewalls() {
			if fw.AccountID == "" || fw.AccountID != inst.AccountID || fw.Metadata["disabled"] == "true" ||
				(fw.Metadata["direction"] != "" && fw.Metadata["direction"] != "INGRESS") || !firewallTargets(fw, inst) {
				continue
			}
			if n.Network != "" && fw.Metadata["network"] != n.Network {
				continue
			}
			if r, ok := toWorldFirewallRule(fw); ok {
				r.unknown = r.unknown || n.Network == ""
				rules = append(rules, r)
				destinations = append(destinations, r.destinations...)
			}
		}
		set := prepareGCEFirewallRules(rules)
		for _, dst := range gceDestinations(n) {
			ips := []netip.Addr{{}}
			if dst.prefix.IsValid() {
				ips = destinationCandidates(dst.prefix, destinations)
			}
			// A bounded fallback must retain a candidate, never certify a closed
			// path after abandoning part of a large address partition.
			if len(ips) > 512 {
				possible = exposureEdge(inst, "gcp_firewall_unknown", asset.PublicAccessPossible, map[string]string{"ports": "all"})
				continue
			}
			for _, ip := range ips {
				p, fws := gceInstanceExposure(set, ip, dst.v6, &budget)
				observed := inst.Metadata["firewall_rules_complete"] == "true"
				if !observed && p.all == "" {
					p = networkPorts{all: "all", possible: "all"}
				}
				ports, possiblePorts, tier := p.summary(observed && !dst.unknown)
				if ports == "" {
					continue
				}
				props := map[string]string{"ports": ports, "firewall": strings.Join(fws, ",")}
				if possiblePorts != "" {
					props["possible_ports"] = possiblePorts
				}
				edge := exposureEdge(inst, "gcp_firewall_open", tier, props)
				if tier == asset.PublicAccessConfirmed {
					return edge, true
				}
				possible = edge
			}
		}
	}
	return possible, possible.SrcID != ""
}

// Unknown destination families are partitioned against the entire family only
// for candidate matching; they never provide confirmed endpoint evidence.
func familyWorld(v6 bool) netip.Prefix {
	if v6 {
		return cidrset.WorldV6
	}
	return cidrset.WorldV4
}
