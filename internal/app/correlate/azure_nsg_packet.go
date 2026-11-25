package correlate

import (
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// nsgPacketPorts evaluates the SAME destination, source port, protocol and
// destination port through every NSG. Boundaries, rather than port/address
// enumeration, keep this exact for supported literals and CIDRs. Missing
// evidence can produce a possible path; it cannot make a Deny definitive.
func nsgPacketPorts(sets [][]ingressRule, nic azureNIC) networkPorts {
	if len(sets) == 0 {
		return networkPorts{}
	}
	// All traffic must pass every NSG. A fully observed empty set applies
	// default deny, independent of the other NSGs' number of boundaries.
	for _, rules := range sets {
		if len(rules) == 0 {
			return networkPorts{}
		}
	}
	var dstValues []string
	protoSet := map[string]bool{"tcp": true, "udp": true}
	cuts, sourceCuts := []int32{0, 65536}, []int32{0, 65536}
	for i := range sets {
		sets[i] = slices.Clone(sets[i])
		sort.SliceStable(sets[i], func(a, b int) bool { return sets[i][a].Priority < sets[i][b].Priority })
		for _, r := range sets[i] {
			proto := normalizedIPProtocol(r.Protocol)
			switch proto {
			case "*", "any", "-1":
				protoSet["other"] = true
			case "":
			default:
				protoSet[proto] = true
			}
			cuts = append(cuts, r.FromPort, r.ToPort+1)
			dstValues = append(dstValues, r.Prefixes...)
			for _, v := range r.SourcePorts {
				if lo, hi, ok := nsgSourcePortRange(v); ok {
					sourceCuts = append(sourceCuts, lo, hi+1)
				}
			}
		}
	}
	slices.Sort(sourceCuts)
	sourceCuts = slices.Compact(sourceCuts)
	dst, dstKnown := addressPrefix(nic.PrivateIP)
	public, publicErr := netip.ParseAddr(nic.PublicIP)
	publicKnown := publicErr == nil && !public.Is4In6()
	families := []bool{false, true}
	if publicKnown {
		families = []bool{public.Is6()}
	} else if dstKnown {
		families = []bool{dst.Addr().Is6()}
	}
	var ips []netip.Addr
	for _, v6 := range families {
		if dstKnown && dst.Addr().Is6() != v6 {
			continue
		}
		target := dst
		if !dstKnown {
			target = familyWorld(v6)
		}
		ips = append(ips, destinationCandidates(target, dstValues)...)
	}
	endpointKnown := publicKnown && (dstKnown || destinationsUnrestricted(sets))
	// Charge tuples as well as individual rule visits. The bound still holds
	// when an empty or nonmatching rule set short-circuits a tuple.
	budget := 100_000
	protos := make([]string, 0, len(protoSet))
	for proto := range protoSet {
		protos = append(protos, proto)
	}
	slices.Sort(protos)
	ports := evaluateNetworkPorts(protos, cuts, func(proto string, port int32) networkMatch {
		best := networkNo
		for _, ip := range ips {
			for _, sourcePort := range sourceCuts {
				if sourcePort >= 65536 {
					continue
				}
				budget--
				if budget < 0 {
					return networkUnknown
				}
				match := networkYes
				for _, rules := range sets {
					m := nsgPacketDecision(rules, nic, ip, ip.Is6(), proto, port, sourcePort, &budget)
					if budget < 0 {
						return networkUnknown
					}
					if m < match {
						match = m
					}
					if match == networkNo {
						break
					}
				}
				if match == networkYes && (!endpointKnown || (proto != "tcp" && proto != "udp")) {
					match = networkUnknown
				}
				if match > best {
					best = match
				}
				if best == networkYes {
					return best
				}
			}
		}
		return best
	})
	if budget < 0 {
		return networkPorts{all: "all", possible: "all"}
	}
	return ports
}

func destinationsUnrestricted(sets [][]ingressRule) bool {
	for _, rules := range sets {
		for _, r := range rules {
			if len(r.ASGs) > 0 || len(r.Prefixes) != 1 || r.Prefixes[0] != "*" {
				return false
			}
		}
	}
	return true
}

func nsgPacketDecision(rules []ingressRule, nic azureNIC, ip netip.Addr, v6 bool, proto string, port, sourcePort int32, budget *int) networkMatch {
	unknownDeny, possibleAllow := false, false
	for _, r := range rules {
		*budget--
		if *budget < 0 {
			return networkUnknown
		}
		if !nsgProtoMatches(r.Protocol, proto) || port < r.FromPort || port > r.ToPort {
			continue
		}
		m := nsgDestinationMatch(r, nic, ip)
		source := nsgSourceFamily(r.CIDRs, v6)
		// A limited-source deny cannot be treated as wholly irrelevant to a
		// world allow without partitioning sources too. Retain uncertainty.
		if source == networkNo && strings.EqualFold(r.Access, "deny") {
			for _, v := range r.CIDRs {
				if p, ok := addressPrefix(v); ok && p.Addr().Is6() == v6 {
					source = networkUnknown
				}
			}
		}
		for _, other := range []networkMatch{source, nsgSourcePortMatch(r.SourcePorts, sourcePort)} {
			if other < m {
				m = other
			}
		}
		switch {
		case m == networkNo:
			continue
		case m == networkUnknown:
			if strings.EqualFold(r.Access, "deny") {
				unknownDeny = true
			} else {
				possibleAllow = true
			}
		case strings.EqualFold(r.Access, "deny"):
			if possibleAllow {
				return networkUnknown
			}
			return networkNo
		default:
			if unknownDeny {
				return networkUnknown
			}
			return networkYes
		}
	}
	if possibleAllow {
		return networkUnknown
	}
	return networkNo
}

func nsgDestinationMatch(r ingressRule, nic azureNIC, ip netip.Addr) networkMatch {
	m := addressMatch(r.Prefixes, ip, networkNo)
	for _, group := range r.ASGs {
		if slices.ContainsFunc(nic.ASGs, func(v string) bool { return strings.EqualFold(v, group) }) {
			return networkYes
		}
		if !nic.EndpointKnown {
			m = networkUnknown
		}
	}
	if len(r.Prefixes) == 0 && len(r.ASGs) == 0 {
		return networkUnknown
	}
	return m
}

func nsgSourceFamily(values []string, v6 bool) networkMatch {
	prefixes := cidrset.Parse(values)
	if cidrset.Cover(prefixes, familyWorld(v6)) {
		return networkYes
	}
	unknown := len(values) == 0
	for _, v := range values {
		switch strings.ToLower(v) {
		case "*", "any", "internet":
			return networkYes
		case "virtualnetwork", "azureloadbalancer":
			continue
		}
		if _, ok := addressPrefix(v); !ok {
			unknown = true
		}
	}
	if unknown {
		return networkUnknown
	}
	return networkNo
}

func nsgSourcePortRange(s string) (int32, int32, bool) {
	if s == "*" {
		return 0, 65535, true
	}
	a, b, interval := strings.Cut(s, "-")
	lo, err := strconv.ParseInt(a, 10, 32)
	if err != nil {
		return 0, 0, false
	}
	hi := lo
	if interval {
		hi, err = strconv.ParseInt(b, 10, 32)
	}
	return int32(lo), int32(hi), err == nil && lo >= 0 && hi >= lo && hi <= 65535
}

func nsgSourcePortMatch(values []string, port int32) networkMatch {
	unknown := len(values) == 0
	for _, v := range values {
		lo, hi, ok := nsgSourcePortRange(v)
		if !ok {
			unknown = true
			continue
		}
		if lo <= port && port <= hi {
			return networkYes
		}
	}
	if unknown {
		return networkUnknown
	}
	return networkNo
}
