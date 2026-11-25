package correlate

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// fwPortRange is one protocol/port range from a firewall's allowed/denied
// summary ("tcp:22,8000-8100;udp;all"). Protocol "all" matches every protocol;
// a protocol with no ports covers all of its ports.
type fwPortRange struct {
	proto    string
	from, to int32
}

// worldFirewallRule is a GCP INGRESS rule whose source includes the internet
// for at least one IP family.
type worldFirewallRule struct {
	id           string
	priority     int64
	deny         bool
	v4, v6       bool
	ranges       []fwPortRange
	destinations []string
	unknown      bool
}

// parseFirewallPorts parses the collector's "proto:ports;proto" summary.
func parseFirewallPorts(s string) []fwPortRange {
	var out []fwPortRange
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		proto, ports, _ := strings.Cut(part, ":")
		proto = normalizedIPProtocol(proto)
		if ports == "" {
			out = append(out, fwPortRange{proto: proto, from: 0, to: 65535})
			continue
		}
		for p := range strings.SplitSeq(ports, ",") {
			lo, hi, isRange := strings.Cut(strings.TrimSpace(p), "-")
			from, err := strconv.ParseInt(lo, 10, 32)
			if err != nil {
				continue
			}
			to := from
			if isRange {
				if to, err = strconv.ParseInt(hi, 10, 32); err != nil {
					continue
				}
			}
			if from >= 0 && from <= to && to <= 65535 {
				out = append(out, fwPortRange{proto: proto, from: int32(from), to: int32(to)})
			}
		}
	}
	return out
}

// toWorldFirewallRule reads a gcp_firewall asset as a world-sourced rule, or
// ok=false when no IP family's internet range is among its sources. A row
// without source_ranges/denied falls back to the open_to_internet/deny_world
// flags, a flag with no port summary reading as every protocol and port.
func toWorldFirewallRule(fw asset.Asset) (worldFirewallRule, bool) {
	r := worldFirewallRule{id: fw.ID, priority: parsePriority(fw.Metadata["priority"]),
		destinations: splitValues(fw.Metadata["destination_ranges"])}
	if src := splitValues(fw.Metadata["source_ranges"]); len(src) > 0 {
		prefixes := cidrset.Parse(src)
		r.v4, r.v6 = cidrset.Cover(prefixes, cidrset.WorldV4), cidrset.Cover(prefixes, cidrset.WorldV6)
		// Narrow-source denies may affect a world allow. Without a source
		// partition they can weaken certainty but cannot prove a closure.
		if fw.Metadata["denied"] != "" && !r.v4 && !r.v6 {
			for _, p := range prefixes {
				r.v4 = r.v4 || p.Addr().Is4()
				r.v6 = r.v6 || p.Addr().Is6()
			}
			r.unknown = true
		}
	} else {
		legacy := fw.Metadata["open_to_internet"] == "true" || fw.Metadata["deny_world"] == "true"
		r.v4, r.v6, r.unknown = legacy, legacy, legacy
	}
	if !r.v4 && !r.v6 {
		return r, false
	}
	switch {
	case fw.Metadata["denied"] != "":
		r.deny = true
		r.ranges = parseFirewallPorts(fw.Metadata["denied"])
	case fw.Metadata["deny_world"] == "true":
		r.deny = true
		r.ranges = []fwPortRange{{proto: "all", from: 0, to: 65535}}
	case fw.Metadata["allowed"] != "":
		r.ranges = parseFirewallPorts(fw.Metadata["allowed"])
	case fw.Metadata["open_to_internet"] == "true":
		r.ranges = []fwPortRange{{proto: "all", from: 0, to: 65535}}
	}
	return r, len(r.ranges) > 0
}

// Prepare ordering and port boundaries once per interface, then reuse them
// across destination samples. Deny wins a priority tie.
type gceFirewallSet struct {
	rules  []worldFirewallRule
	protos []string
	cuts   []int32
}

func prepareGCEFirewallRules(rules []worldFirewallRule) gceFirewallSet {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].priority != rules[j].priority {
			return rules[i].priority < rules[j].priority
		}
		return rules[i].deny && !rules[j].deny
	})
	protoSet := map[string]bool{"tcp": true, "udp": true}
	var cuts []int32
	for _, r := range rules {
		for _, pr := range r.ranges {
			if pr.proto == "all" {
				protoSet["other"] = true
			} else {
				protoSet[pr.proto] = true
			}
			cuts = append(cuts, pr.from, pr.to+1)
		}
	}
	protos := make([]string, 0, len(protoSet))
	for p := range protoSet {
		protos = append(protos, p)
	}
	sort.Strings(protos)

	return gceFirewallSet{rules: rules, protos: protos, cuts: cuts}
}

func gceInstanceExposure(set gceFirewallSet, destination netip.Addr, v6 bool, budget *int) (networkPorts, []string) {
	var firewalls []string
	openers := map[string]bool{}
	ports := evaluateNetworkPorts(set.protos, set.cuts, func(proto string, port int32) networkMatch {
		id, match := decidingFirewallRule(set.rules, v6, proto, port, destination, budget)
		if proto != "tcp" && proto != "udp" && match == networkYes {
			match = networkUnknown
		}
		if match != networkNo {
			openers[id] = true
		}
		return match
	})
	if *budget < 0 {
		return networkPorts{all: "all", possible: "all"}, nil
	}
	for id := range openers {
		firewalls = append(firewalls, id)
	}
	sort.Strings(firewalls)
	return ports, firewalls
}

// decidingFirewallRule returns the first (highest-precedence) rule of the
// given family matching proto/port in the pre-sorted rules.
func decidingFirewallRule(sorted []worldFirewallRule, v6 bool, proto string, port int32, destination netip.Addr, budget *int) (string, networkMatch) {
	unknownDeny, possibleAllow := false, ""
	for _, r := range sorted {
		*budget--
		if *budget < 0 {
			return "", networkUnknown
		}
		if (v6 && !r.v6) || (!v6 && !r.v4) {
			continue
		}
		matchesPort := false
		for _, pr := range r.ranges {
			matchesPort = matchesPort || (pr.proto == "all" || pr.proto == proto) && pr.from <= port && port <= pr.to
		}
		if !matchesPort {
			continue
		}
		m := addressMatch(r.destinations, destination, networkYes)
		if r.unknown && m == networkYes {
			m = networkUnknown
		}
		switch {
		case m == networkNo:
			continue
		case m == networkUnknown:
			if r.deny {
				unknownDeny = true
			} else {
				possibleAllow = r.id
			}
		case r.deny:
			if possibleAllow != "" {
				return possibleAllow, networkUnknown
			}
			return "", networkNo
		default:
			if unknownDeny {
				return r.id, networkUnknown
			}
			return r.id, networkYes
		}
	}
	if possibleAllow != "" {
		return possibleAllow, networkUnknown
	}
	return "", networkNo
}

// instanceServiceAccount returns the email a GCE instance runs as, from the
// exec_role the collector stamps ("serviceAccount:<email>").
func instanceServiceAccount(inst asset.Asset) string {
	return strings.TrimPrefix(inst.Metadata["exec_role"], "serviceAccount:")
}
