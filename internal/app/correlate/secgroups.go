package correlate

import (
	"encoding/json"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// ingressRule mirrors the JSON the AWS collector serializes into a
// security_group's metadata["ingress"] (see internal/collect/aws sgIngressRule).
// Azure NSGs share the shape and add Access/Priority (internal/collect/azure
// nsgRule); AWS rules leave them empty, which reads as an allow.
// Kept local so correlate does not import the collector package.
type ingressRule struct {
	Protocol    string   `json:"protocol"`
	FromPort    int32    `json:"from_port"`
	ToPort      int32    `json:"to_port"`
	CIDRs       []string `json:"cidrs"`
	SourcePorts []string `json:"source_ports"`
	SGRefs      []string `json:"sg_refs"`
	Access      string   `json:"access"`
	Priority    int32    `json:"priority"`
	checks.NSGDestination
}

// parseIngress decodes a security_group's serialized ingress rules; an absent or
// malformed value yields no rules (the SG simply contributes no edges).
func parseIngress(s string) []ingressRule {
	if s == "" {
		return nil
	}
	var rules []ingressRule
	if err := json.Unmarshal([]byte(s), &rules); err != nil {
		return nil
	}
	return rules
}

// worldOpenPorts returns a human summary of the ports an AWS SG exposes to
// one address family of the internet (e.g. "tcp:22", "all"), or "" if none —
// the signal the reachability rule keys off. world is cidrset.WorldV4 or
// cidrset.WorldV6: a rule open only to ::/0 admits nothing on an IPv4 address.
// It reads a rule exactly as the world-open checks do: its ranges must
// together span the family (0.0.0.0/1 + 128.0.0.0/1 counts), and its protocol
// must carry ports, so an ICMP-only rule opens no entry point.
func worldOpenPorts(sg asset.Asset, world netip.Prefix) string {
	var parts []string
	for _, r := range parseIngress(sg.Metadata["ingress"]) {
		if !cidrset.Cover(cidrset.Parse(r.CIDRs), world) || !checks.PortAddressed(r.Protocol) {
			continue
		}
		parts = append(parts, portLabel(r))
	}
	return strings.Join(parts, ",")
}

// hasGlobalIPv6 reports whether an EC2 instance carries an IPv6 address that
// can be routed on the internet (global unicast, not unique-local). Whether
// its subnet routes to an internet gateway is routeBasis's question.
func hasGlobalIPv6(a asset.Asset) bool {
	for _, v := range splitValues(a.Metadata["ipv6_addresses"]) {
		if ip, err := netip.ParseAddr(v); err == nil && ip.Is6() && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

// AWS records an empty rule count on a successful DescribeSecurityGroups.
// Missing or malformed JSON without that zero count is not an observed deny.
func sgIngressObserved(sg asset.Asset) bool {
	raw := sg.Metadata["ingress"]
	if raw == "" {
		return sg.Metadata["ingress_rules"] == "0"
	}
	var rules []ingressRule
	return json.Unmarshal([]byte(raw), &rules) == nil && rules != nil
}

// portLabel renders a rule's protocol/port range. "-1" protocol (AWS "all") and
// a 0/0 port range both mean "everything".
func portLabel(r ingressRule) string {
	proto := r.Protocol
	if proto == "" || proto == "-1" {
		return "all"
	}
	if r.FromPort == r.ToPort {
		return fmt.Sprintf("%s:%d", proto, r.FromPort)
	}
	return fmt.Sprintf("%s:%d-%d", proto, r.FromPort, r.ToPort)
}

// SecurityGroupAllows turns serialized SG ingress rules into a security-group
// graph: for every rule that references a security group, it emits an edge
// from the owning SG to the referenced source SG (A permits ingress from B).
// A self-referencing rule is a self-loop: it is the rule that lets members of
// one SG reach each other, which sharing the SG alone does not. World-open
// (0.0.0.0/0) ingress is handled by InternetReachability, not here, and CIDR
// rules covering another SG's members' private addresses are not modelled.
type SecurityGroupAllows struct{}

func (SecurityGroupAllows) Name() string { return "sg_allows_from" }

func (SecurityGroupAllows) InterestedIn() []string {
	return []string{"security_group"}
}

func (r SecurityGroupAllows) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (SecurityGroupAllows) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {

		for _, sg := range g.SecurityGroups() {
			for _, r := range parseIngress(sg.Metadata["ingress"]) {
				for _, ref := range r.SGRefs {
					if ref == "" {
						continue
					}
					if !yield(asset.Edge{
						SrcID: sg.ID, SrcType: "security_group",
						DstID: ref, DstType: "security_group",
						EdgeType: EdgeSGAllowsFrom,
						Properties: map[string]string{
							"origin": edgeOrigin,
							"rule":   "sg_allows_from",
							"ports":  portLabel(r),
						},
					}) {
						return
					}
				}
			}
		}
	}
}
