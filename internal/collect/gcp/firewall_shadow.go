package gcp

import (
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Well-known admin ports the CIS GCP benchmark singles out (3.6 SSH, 3.7 RDP).
const (
	sshPort = 22
	rdpPort = 3389
)

// fwRange is one protocol/port range from a rule's allowed/denied summary. A
// protocol with no ports covers all of them; "all" matches every protocol.
type fwRange struct {
	proto    string
	from, to int
}

// fwExposure is what an internet-open allow rule actually exposes once the
// project's higher-precedence world-sourced deny rules are applied.
type fwExposure struct {
	// AllPorts: every TCP port is reachable through this rule. SSH and RDP
	// are then left false — the all-ports rule is the one root cause, and
	// reporting it again per admin port would be three findings for it.
	AllPorts bool
	SSH      bool // tcp:22 reachable through a rule that does not open every port
	RDP      bool // tcp:3389 likewise
	Shadowed bool // every protocol/port the rule allows is denied first
	// Open is the "proto:ports;proto" summary of what remains reachable from
	// the internet after the denies; "" when Shadowed.
	Open string
}

// internetExposure resolves each internet-open allow rule against the deny
// rules that take precedence over it, keyed by rule name. GCP evaluates VPC
// firewall rules by priority (lower number first, deny wins a tie), so a
// world-sourced deny at a higher precedence blocks the same ports from the
// same sources whatever the allow says; open_to_internet alone ignored that.
//
// A deny is applied only when it provably covers the allow: same network,
// takes precedence, applies to every instance the allow targets, reaches every
// destination the allow does, and denies each internet family (IPv4
// 0.0.0.0/0, IPv6 ::/0) the allow admits. Anything less leaves the exposure
// standing — a missed deny costs a finding, a wrongly applied one would hide a
// reachable port. Hierarchical and network firewall policies are not read, so
// neither a deny nor an allow defined there is seen.
func internetExposure(rules []gcpFirewall) map[string]fwExposure {
	out := map[string]fwExposure{}
	for _, r := range rules {
		if !r.OpenToInternet {
			continue
		}
		v4, v6 := worldFamilies(r.SourceRanges)
		var denyV4, denyV6 []fwRange
		for _, d := range rules {
			if !d.DenyWorld || d.Network != r.Network || d.Priority > r.Priority ||
				!targetsCover(d, r) || !destinationsCover(d, r) {
				continue
			}
			dv4, dv6 := worldFamilies(d.SourceRanges)
			ranges := parseFWSummary(d.Denied)
			if dv4 {
				denyV4 = append(denyV4, ranges...)
			}
			if dv6 {
				denyV6 = append(denyV6, ranges...)
			}
		}
		allowed := parseFWSummary(r.Allowed)
		// A port is reachable when it stays open for any family the allow admits.
		var open []fwRange
		if v4 {
			open = append(open, subtractRanges(allowed, denyV4)...)
		}
		if v6 {
			open = append(open, subtractRanges(allowed, denyV6)...)
		}
		reach := func(port int) bool { return rangeCovered(open, fwRange{proto: "tcp", from: port, to: port}) }
		ex := fwExposure{Shadowed: len(open) == 0, Open: fwSummary(open)}
		ex.AllPorts = rangeCovered(open, fwRange{proto: "tcp", from: 0, to: 65535})
		ex.SSH = reach(sshPort) && !ex.AllPorts
		ex.RDP = reach(rdpPort) && !ex.AllPorts
		out[r.Name] = ex
	}
	return out
}

// destinationsCover reports whether deny d reaches every destination allow r
// does. Destination ranges apply to ingress rules too: a deny limited to one
// subnet blocks nothing for the rest of the network, so it is credited only
// when the allow is itself limited to destinations inside the deny's ranges.
func destinationsCover(d, r gcpFirewall) bool {
	if len(d.DestinationRanges) == 0 {
		return true
	}
	if len(r.DestinationRanges) == 0 {
		return false
	}
	for _, dst := range r.DestinationRanges {
		p, err := netip.ParsePrefix(strings.TrimSpace(dst))
		if err != nil {
			return false
		}
		inside := false
		for _, dr := range d.DestinationRanges {
			q, err := netip.ParsePrefix(strings.TrimSpace(dr))
			if err == nil && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				inside = true
				break
			}
		}
		if !inside {
			return false
		}
	}
	return true
}

// subtractRanges removes from each allowed range the ports a matching deny
// range covers. A deny of protocol "all" cuts any protocol; an allowed "all"
// is cut only by an "all" deny (a tcp-only deny leaves every other protocol
// open, which "all" minus tcp cannot express, so the whole range stays — the
// over-report errs towards exposure).
func subtractRanges(allowed, denied []fwRange) []fwRange {
	var out []fwRange
	for _, a := range allowed {
		pieces := []fwRange{a}
		for _, d := range denied {
			if d.proto != "all" && d.proto != a.proto {
				continue
			}
			var next []fwRange
			for _, p := range pieces {
				if d.to < p.from || d.from > p.to {
					next = append(next, p)
					continue
				}
				if d.from > p.from {
					next = append(next, fwRange{proto: p.proto, from: p.from, to: d.from - 1})
				}
				if d.to < p.to {
					next = append(next, fwRange{proto: p.proto, from: d.to + 1, to: p.to})
				}
			}
			pieces = next
		}
		out = append(out, pieces...)
	}
	return out
}

// fwSummary renders ranges back to the collector's "proto:p1,p2-p3;proto"
// form, merged and sorted per protocol; a protocol open on every port is
// rendered without ports.
func fwSummary(ranges []fwRange) string {
	byProto := map[string][]fwRange{}
	var protos []string
	for _, r := range ranges {
		if _, ok := byProto[r.proto]; !ok {
			protos = append(protos, r.proto)
		}
		byProto[r.proto] = append(byProto[r.proto], r)
	}
	sort.Strings(protos)
	var parts []string
	for _, proto := range protos {
		rs := byProto[proto]
		sort.Slice(rs, func(i, j int) bool { return rs[i].from < rs[j].from })
		var merged []fwRange
		for _, r := range rs {
			if n := len(merged); n > 0 && r.from <= merged[n-1].to+1 {
				merged[n-1].to = max(merged[n-1].to, r.to)
				continue
			}
			merged = append(merged, r)
		}
		if len(merged) == 1 && merged[0].from == 0 && merged[0].to == 65535 {
			parts = append(parts, proto)
			continue
		}
		var ports []string
		for _, m := range merged {
			if m.from == m.to {
				ports = append(ports, strconv.Itoa(m.from))
			} else {
				ports = append(ports, strconv.Itoa(m.from)+"-"+strconv.Itoa(m.to))
			}
		}
		parts = append(parts, proto+":"+strings.Join(ports, ","))
	}
	return strings.Join(parts, ";")
}

// worldFamilies reports which internet families a source-range list admits.
func worldFamilies(src []string) (v4, v6 bool) {
	return containsCIDR(src, internetCIDR), containsCIDR(src, internetCIDRv6)
}

// targetsCover reports whether deny d applies to every instance allow r
// targets. A rule with no target tags or service accounts applies to the
// whole network; target tags match an instance carrying ANY of them, so a
// deny covers a tag-targeted allow only when it lists every one of its tags.
func targetsCover(d, r gcpFirewall) bool {
	if len(d.TargetTags) == 0 && len(d.TargetSAs) == 0 {
		return true
	}
	if len(r.TargetTags) > 0 && subset(r.TargetTags, d.TargetTags) {
		return true
	}
	return len(r.TargetSAs) > 0 && subset(r.TargetSAs, d.TargetSAs)
}

func subset(small, big []string) bool {
	for _, s := range small {
		if !slices.Contains(big, s) {
			return false
		}
	}
	return true
}

// parseFWSummary parses the collector's "proto:p1,p2-p3;proto" summary. IANA
// protocol numbers the API also accepts are mapped to names so "6" and "tcp"
// compare equal. An unparseable port entry is dropped, which can only shrink
// what a deny is credited with.
func parseFWSummary(s string) []fwRange {
	var out []fwRange
	for part := range strings.SplitSeq(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		proto, ports, _ := strings.Cut(part, ":")
		proto = normaliseProto(proto)
		if ports == "" {
			out = append(out, fwRange{proto: proto, from: 0, to: 65535})
			continue
		}
		for p := range strings.SplitSeq(ports, ",") {
			lo, hi, isRange := strings.Cut(strings.TrimSpace(p), "-")
			from, err := strconv.Atoi(lo)
			if err != nil {
				continue
			}
			to := from
			if isRange {
				if to, err = strconv.Atoi(hi); err != nil {
					continue
				}
			}
			out = append(out, fwRange{proto: proto, from: from, to: to})
		}
	}
	return out
}

func normaliseProto(p string) string {
	switch p = strings.ToLower(strings.TrimSpace(p)); p {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	case "58":
		return "ipv6-icmp"
	}
	return p
}

// rangeCovered reports whether the union of ranges covers every port of want
// for want's protocol. A range of protocol "all" covers any protocol; a want
// of protocol "all" is covered only by "all" ranges.
func rangeCovered(ranges []fwRange, want fwRange) bool {
	var match []fwRange
	for _, r := range ranges {
		if r.proto == "all" || r.proto == want.proto {
			match = append(match, r)
		}
	}
	sort.Slice(match, func(i, j int) bool { return match[i].from < match[j].from })
	next := want.from
	for _, r := range match {
		if r.from > next {
			break
		}
		if r.to >= next {
			next = r.to + 1
		}
		if next > want.to {
			return true
		}
	}
	return false
}
