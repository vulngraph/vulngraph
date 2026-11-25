// Package cidrset answers coverage questions over sets of CIDR ranges: does
// their union cover the whole internet, or a given prefix. It is
// dependency-free so the posture checks, the collectors, the correlator and
// the policy-condition classifier all agree on what a world-open range is.
//
// keyscan digests this package's source into the logic digest of every check
// that calls it (keyscan.logicPackages), so a behaviour change here re-checks
// unchanged assets.
package cidrset

import (
	"net/netip"
	"strings"
)

// Internet families: a CIDR set is "the world" for a family when its union
// covers that family's whole address space, not only when it lists the
// literal 0.0.0.0/0 or ::/0 — 0.0.0.0/1 plus 128.0.0.0/1 admits exactly the
// same sources, and a check that compared strings would wave it through.
var (
	WorldV4 = netip.MustParsePrefix("0.0.0.0/0")
	WorldV6 = netip.MustParsePrefix("::/0")
)

// CoversWorld reports whether the CIDRs' union covers all of IPv4 or all of
// IPv6. Unparseable entries are ignored, which can only shrink the union.
func CoversWorld(cidrs []string) bool {
	ps := Parse(cidrs)
	return Cover(ps, WorldV4) || Cover(ps, WorldV6)
}

// WorldOf returns the world prefix of the family a CIDR belongs to.
func WorldOf(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4() {
		return WorldV4
	}
	return WorldV6
}

// Parse returns the masked prefixes of cidrs, skipping unparseable entries
// and IPv4-mapped IPv6 forms.
func Parse(cidrs []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		p = p.Masked()
		if p.Addr().Is4In6() {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Cover reports whether the union of ps covers every address of target. A
// prefix containing target covers it outright; otherwise target is split in
// half and both halves must be covered. The split stops as soon as no prefix
// of ps lies strictly inside target, so the recursion depth is bounded by the
// most specific prefix in the set.
func Cover(ps []netip.Prefix, target netip.Prefix) bool {
	narrower := false
	for _, p := range ps {
		if p.Addr().Is4() != target.Addr().Is4() {
			continue
		}
		if p.Bits() <= target.Bits() && p.Contains(target.Addr()) {
			return true
		}
		if p.Bits() > target.Bits() && target.Contains(p.Addr()) {
			narrower = true
		}
	}
	if !narrower || target.Bits() >= target.Addr().BitLen() {
		return false
	}
	lo := netip.PrefixFrom(target.Addr(), target.Bits()+1)
	hi := netip.PrefixFrom(lowerHalfEnd(lo).Next(), target.Bits()+1)
	return Cover(ps, lo) && Cover(ps, hi)
}

// lowerHalfEnd returns the last address of prefix p.
func lowerHalfEnd(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
