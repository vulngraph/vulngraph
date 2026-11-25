package checks

// aws_sg_public_ranges.go — security-group and network-ACL conditions that
// depend on whether a CIDR is a globally routable (public) range: specific
// public sources, wide public IPv4 blocks, and an ACL that admits all traffic.

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsSGPublicRangeChecks() []Check {
	return []Check{
		awsSGSpecificPublicSource,
		awsSGWidePublicIPv4,
		awsNACLAllowsAllTraffic,
	}
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

// nonGlobalRanges are the special-purpose ranges (private, shared, loopback,
// link-local, documentation, reserved) a CIDR must sit entirely inside to be
// non-public. globalExceptions carve globally routable blocks out of them.
var (
	nonGlobalRanges = mustPrefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/29", "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
		"::1/128", "::/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "5f00::/16", "fc00::/7", "fe80::/10",
	)
	globalExceptions = mustPrefixes(
		"2001:1::1/128", "2001:1::2/128", "2001:3::/32", "2001:4:112::/48", "2001:20::/28", "2001:30::/28",
	)
)

func prefixWithin(p, outer netip.Prefix) bool {
	return p.Addr().BitLen() == outer.Addr().BitLen() && p.Bits() >= outer.Bits() && outer.Contains(p.Addr())
}

// cidrIsGlobal reports whether the CIDR is a globally routable range: it is
// not entirely inside any special-purpose range. Unparseable input is not
// public.
func cidrIsGlobal(cidr string) bool {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	p = p.Masked()
	for _, ex := range globalExceptions {
		if prefixWithin(p, ex) {
			return true
		}
	}
	for _, r := range nonGlobalRanges {
		if prefixWithin(p, r) {
			return false
		}
	}
	return true
}

func isWorldLiteral(cidr string) bool { return cidr == "0.0.0.0/0" || cidr == "::/0" }

// ruleHasSpecificPublicSource reports a rule that lists at least one globally
// routable source other than the literal world ranges. A world range beside a
// private CIDR is not specific: the private range adds no public address.
func ruleHasSpecificPublicSource(r sgIngressRule) bool {
	return slices.ContainsFunc(r.CIDRs, func(c string) bool { return !isWorldLiteral(c) && cidrIsGlobal(c) })
}

var awsSGSpecificPublicSource = Check{
	ID:          "aws-sg-ingress-specific-public-source",
	Title:       "Security group allows inbound traffic from a specific public address",
	Description: "An inbound rule lists a source other than the whole internet together with a publicly routable source, so a port is open to an outside address or range rather than only to private networks. A single public address is often a stale office or contractor IP that now belongs to someone else. Groups open to every port from the world are reported by aws-sg-open-all-ports instead and are skipped here.",
	Remediation: "Replace public sources with private ranges, a VPN, or a source security group, or remove the rule. Console: VPC > Security groups > Inbound rules > Edit. CLI: `aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port PORT --cidr CIDR`.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	Violates: func(a asset.Asset) bool {
		if sgAllPortsWorldOpen(a) {
			return false
		}
		for _, r := range parseSGRules(a) {
			if ruleHasSpecificPublicSource(r) {
				return true
			}
		}
		return false
	},
}

// wideIPv4 returns the globally routable IPv4 CIDRs with a prefix length of
// 1 to 23 in the rule list.
func wideIPv4(rules []sgIngressRule) []string {
	var out []string
	for _, r := range rules {
		for _, c := range r.CIDRs {
			p, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil || !p.Addr().Is4() || p.Bits() < 1 || p.Bits() > 23 {
				continue
			}
			if cidrIsGlobal(c) {
				out = append(out, c)
			}
		}
	}
	return out
}

func sgEgressRules(a asset.Asset) []sgIngressRule {
	rules, err := decodeSGRules(a.Metadata["egress"])
	if err != nil {
		return nil
	}
	return rules
}

var awsSGWidePublicIPv4 = Check{
	ID:          "aws-sg-wide-public-ipv4-range",
	Title:       "Security group has a wide public IPv4 range in a rule",
	Description: "An inbound or outbound rule names a publicly routable IPv4 block larger than a /24 (prefix /1 to /23), other than 0.0.0.0/0. Such a block usually belongs to an ISP or cloud provider and admits or reaches thousands of addresses nobody on your team controls; it is often a mistyped mask on an intended private range.",
	Remediation: "Narrow the block to the exact addresses needed or use a private range or security group reference. Console: VPC > Security groups > Edit inbound/outbound rules. CLI: `aws ec2 revoke-security-group-ingress --group-id SG_ID --protocol tcp --port PORT --cidr WIDE_CIDR` then `aws ec2 authorize-security-group-ingress --group-id SG_ID --protocol tcp --port PORT --cidr NARROW_CIDR` (use the -egress variants for outbound rules).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	Violates: func(a asset.Asset) bool {
		return len(wideIPv4(parseSGRules(a))) > 0 || len(wideIPv4(sgEgressRules(a))) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"ingress_ranges": strings.Join(wideIPv4(parseSGRules(a)), ","),
			"egress_ranges":  strings.Join(wideIPv4(sgEgressRules(a)), ","),
		}
	},
}

// naclFamilyAllows applies a family's first matching all-protocol entry for
// the exact world CIDR, lowest rule number first: allow opens the ACL, deny
// closes this family.
func naclFamilyAllows(entries []naclIngressEntry, world string) bool {
	for _, e := range entries {
		if e.CIDR != world || e.Protocol != "-1" {
			continue
		}
		return strings.EqualFold(e.Action, "allow")
	}
	return false
}

var awsNACLAllowsAllTraffic = Check{
	ID:          "aws-nacl-allows-all-ingress",
	Title:       "Network ACL allows all inbound traffic from the internet",
	Description: "An inbound entry allows every protocol and port from 0.0.0.0/0 or ::/0, and no lower-numbered all-protocol deny for the same range precedes it (the first matching entry decides). The ACL then filters nothing at the subnet edge and security groups are the only control. A VPC's stock default ACL is built this way, so it is reported at Info.",
	Remediation: "Replace the allow-all entry with entries for the ports the subnet serves, or deny the internet first. Console: VPC > Network ACLs > Inbound rules > Edit. CLI: `aws ec2 delete-network-acl-entry --network-acl-id ACL_ID --ingress --rule-number 100` then `aws ec2 create-network-acl-entry --network-acl-id ACL_ID --ingress --rule-number 100 --protocol tcp --port-range From=443,To=443 --cidr-block 0.0.0.0/0 --rule-action allow`.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_acl",
	Violates: func(a asset.Asset) bool {
		entries, ok := naclEntries(a)
		return ok && (naclFamilyAllows(entries, "::/0") || naclFamilyAllows(entries, "0.0.0.0/0"))
	},
	TableProbes: []string{`[{"rule_number":1,"protocol":"-1","action":"allow","cidr":"0.0.0.0/0","from_port":0,"to_port":65535}]`},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["is_default"] == "true" {
			return finding.SeverityInfo
		}
		return finding.SeverityMedium
	},
}
