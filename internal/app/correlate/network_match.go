package correlate

import (
	"net/netip"
	"strings"
)

// Unknown is distinct from both a matching packet and an observed mismatch.
// An unread destination or unsupported service tag cannot prove a Deny.
type networkMatch uint8

const (
	networkNo networkMatch = iota
	networkUnknown
	networkYes
)

func addressPrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil && !p.Addr().Is4In6() {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && !a.Is4In6() {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func addressMatch(values []string, ip netip.Addr, absent networkMatch) networkMatch {
	if len(values) == 0 {
		return absent
	}
	result := networkNo
	for _, v := range values {
		if v == "*" || strings.EqualFold(v, "Any") {
			return networkYes
		}
		p, ok := addressPrefix(v)
		switch {
		case !ok || !ip.IsValid():
			result = networkUnknown
		case p.Contains(ip):
			return networkYes
		}
	}
	return result
}

// Prefix boundaries partition addresses into cells with identical rule
// outcomes. Testing the starts and the address after each end avoids walking
// large IPv6 prefixes, and keeps every NSG on the same destination packet.
func destinationCandidates(target netip.Prefix, values []string) []netip.Addr {
	out := []netip.Addr{target.Addr()}
	seen := map[netip.Addr]bool{target.Addr(): true}
	for _, v := range values {
		p, ok := addressPrefix(v)
		if !ok || !p.Overlaps(target) {
			continue
		}
		b := p.Addr().AsSlice()
		for i := p.Bits(); i < len(b)*8; i++ {
			b[i/8] |= 1 << (7 - uint(i%8))
		}
		last, _ := netip.AddrFromSlice(b)
		for _, a := range []netip.Addr{p.Addr(), last.Next()} {
			if target.Contains(a) && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

func normalizedIPProtocol(p string) string {
	switch p = strings.ToLower(strings.TrimSpace(p)); p {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	case "58":
		return "ipv6-icmp"
	default:
		return p
	}
}
