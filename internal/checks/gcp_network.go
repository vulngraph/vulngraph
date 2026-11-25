package checks

// gcp_network.go — CIS GCP Foundation section 3: firewall rules exposing SSH
// and RDP (3.6, 3.7) and Cloud DNS DNSSEC (3.3-3.5).
//
// The firewall keys are resolved by the collector against the project's whole
// rule list (internal/collect/gcp/firewall_shadow.go): an allow rule only
// counts as exposing a port when no higher-precedence world-sourced deny on
// the same network blocks it for every instance it targets.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// firewallEvidence carries what a responder needs to judge an internet-open
// rule without opening the console.
func firewallEvidence(a asset.Asset) map[string]string {
	ev := map[string]string{}
	for _, k := range []string{"network", "allowed", "open_ports", "source_ranges", "destination_ranges", "target_tags", "target_sas", "priority"} {
		if v := a.Metadata[k]; v != "" {
			ev[k] = v
		}
	}
	return ev
}

// gcpFirewallPolicyNote ends the description of every check over gcp_firewall
// assets: only VPC firewall rules are collected, so policy rules are seen in
// neither direction.
const gcpFirewallPolicyNote = "Hierarchical (organization and folder) and network firewall policies are not read: a deny defined there is not credited, and an allow defined there is never reported, by this check or by the internet-exposure paths in the graph."

// gcpFirewallAllPortsOpenInternet is the rollup for one rule that leaves every
// TCP port reachable from the internet: the SSH and RDP checks then stay
// silent (the collector does not mark an all-ports rule as SSH/RDP-open), so
// one rule is one finding — the same shape as azure-nsg-all-ports-open-internet.
var gcpFirewallAllPortsOpenInternet = Check{
	ID:          "gcp-firewall-all-ports-open-internet",
	Title:       "Firewall rule exposes every port to the internet",
	Description: "An enabled ingress allow rule admits 0.0.0.0/0 or ::/0 to every TCP port (or every protocol), and no higher-priority deny on the same network closes them for every instance and destination the rule covers. Every service on the targeted VMs — SSH, RDP, databases, admin consoles — is reachable from anywhere; this is effectively no firewall. " + gcpFirewallPolicyNote,
	Remediation: "Replace the rule with rules allowing only the ports each service needs, from the narrowest source ranges possible: `gcloud compute firewall-rules update RULE --allow=tcp:443 --source-ranges=CIDR`, or delete it.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_firewall",
	Violates:    func(a asset.Asset) bool { return a.Metadata["all_ports_open_to_internet"] == "true" },
	EvidenceFor: firewallEvidence,
}

var gcpFirewallSSHOpenInternet = Check{
	ID:          "gcp-firewall-ssh-open-internet",
	Title:       "Firewall rule exposes SSH to the internet",
	Description: "An enabled ingress allow rule admits 0.0.0.0/0 or ::/0 to tcp:22, and no higher-priority deny rule on the same network blocks it for every instance the rule targets. Any VM the rule targets is open to SSH brute force and to exploitation of the SSH daemon from anywhere. " + gcpFirewallPolicyNote,
	Remediation: "Restrict the rule's source ranges to known CIDRs, or remove it and reach VMs through Identity-Aware Proxy TCP forwarding (allow only 35.235.240.0/20) or OS Login over a bastion: `gcloud compute firewall-rules update RULE --source-ranges=CIDR`.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_firewall",
	Violates:    func(a asset.Asset) bool { return a.Metadata["ssh_open_to_internet"] == "true" },
	EvidenceFor: firewallEvidence,
}

var gcpFirewallRDPOpenInternet = Check{
	ID:          "gcp-firewall-rdp-open-internet",
	Title:       "Firewall rule exposes RDP to the internet",
	Description: "An enabled ingress allow rule admits 0.0.0.0/0 or ::/0 to tcp:3389, and no higher-priority deny rule on the same network blocks it for every instance the rule targets. Internet-reachable RDP is one of the most attacked services there is: credential spraying and RDP vulnerabilities give direct interactive access. " + gcpFirewallPolicyNote,
	Remediation: "Restrict the rule's source ranges to known CIDRs, or remove it and reach Windows VMs through Identity-Aware Proxy TCP forwarding (allow only 35.235.240.0/20): `gcloud compute firewall-rules update RULE --source-ranges=CIDR`.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_firewall",
	Violates:    func(a asset.Asset) bool { return a.Metadata["rdp_open_to_internet"] == "true" },
	EvidenceFor: firewallEvidence,
}

// gcpFirewallOpenIngressViolates is gcp-firewall-open-ingress's predicate: an
// internet-open allow rule that a higher-precedence deny does not fully shadow,
// and that the all-ports, SSH and RDP checks do not already report.
func gcpFirewallOpenIngressViolates(a asset.Asset) bool {
	return a.Metadata["open_to_internet"] == "true" && a.Metadata["shadowed_by_deny"] == "false" &&
		a.Metadata["all_ports_open_to_internet"] != "true" &&
		a.Metadata["ssh_open_to_internet"] != "true" && a.Metadata["rdp_open_to_internet"] != "true"
}

// firewallOpenSeverity grades an internet-open rule by what it opens: every
// port or protocol, or a well-known database port, is High; web ports only
// (80/443, usually a deliberate public service) are Low; anything else is
// Medium. It grades open_ports — what stays reachable after the denies — and
// falls back to the rule's own allowed list on an asset collected before
// open_ports existed. Both are "proto:p1,p2-p3;proto" summaries.
func firewallOpenSeverity(a asset.Asset) finding.Severity {
	ports, ok := a.Metadata["open_ports"]
	if !ok {
		ports = a.Metadata["allowed"]
	}
	webOnly := true
	for part := range strings.SplitSeq(ports, ";") {
		proto, ports, _ := strings.Cut(strings.TrimSpace(part), ":")
		if proto == "" {
			continue
		}
		if proto == "all" || ports == "" {
			return finding.SeverityHigh
		}
		for p := range strings.SplitSeq(ports, ",") {
			lo, hi, isRange := strings.Cut(strings.TrimSpace(p), "-")
			from, err := strconv.Atoi(lo)
			if err != nil {
				return finding.SeverityHigh // unreadable: do not grade it down
			}
			to := from
			if isRange {
				if to, err = strconv.Atoi(hi); err != nil {
					return finding.SeverityHigh
				}
			}
			if slices.ContainsFunc(databasePorts, func(d int32) bool { return int(d) >= from && int(d) <= to }) {
				return finding.SeverityHigh
			}
			if from != to || (from != 80 && from != 443) {
				webOnly = false
			}
		}
	}
	if webOnly {
		return finding.SeverityLow
	}
	return finding.SeverityMedium
}

// ── Cloud DNS (CIS 3.3-3.5) ──────────────────────────────────────────────────

var gcpDNSDNSSECDisabled = Check{
	ID:          "gcp-dns-dnssec-disabled",
	Title:       "Public Cloud DNS zone does not have DNSSEC enabled",
	Description: "DNSSEC is off for this public managed zone, so resolvers cannot verify that answers for it are authentic and an attacker able to spoof or poison DNS responses can redirect its names undetected.",
	Remediation: "Enable DNSSEC: `gcloud dns managed-zones update ZONE --dnssec-state on`, then publish the DS record at the parent zone's registrar.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "dns_zone",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["visibility"] == "public" && a.Metadata["dnssec_state"] == "off"
	},
}

var gcpDNSDNSSECKSKRSASHA1 = Check{
	ID:          "gcp-dns-dnssec-ksk-rsasha1",
	Title:       "Cloud DNS zone signs DNSSEC keys with RSASHA1",
	Description: "The zone's DNSSEC key-signing key uses RSASHA1, whose SHA-1 digest is no longer collision-resistant and is deprecated for DNSSEC signing (RFC 8624), weakening the chain of trust for the whole zone.",
	Remediation: "Move the zone to a stronger algorithm (RSASHA256 or ECDSAP256SHA256): turn DNSSEC off, update the key specs with `gcloud dns managed-zones update ZONE --ksk-algorithm=ECDSAP256SHA256 ...`, turn it back on, and update the DS record at the registrar.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "dns_zone",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["dnssec_state"] == "on" && listHas(a.Metadata["dnssec_ksk_algorithms"], "rsasha1")
	},
}

var gcpDNSDNSSECZSKRSASHA1 = Check{
	ID:          "gcp-dns-dnssec-zsk-rsasha1",
	Title:       "Cloud DNS zone signs records with RSASHA1",
	Description: "The zone's DNSSEC zone-signing key uses RSASHA1, whose SHA-1 digest is no longer collision-resistant and is deprecated for DNSSEC signing (RFC 8624), so signatures over the zone's records are weaker than resolvers now expect.",
	Remediation: "Move the zone to a stronger algorithm (RSASHA256 or ECDSAP256SHA256): turn DNSSEC off, update the key specs with `gcloud dns managed-zones update ZONE --zsk-algorithm=ECDSAP256SHA256 ...`, and turn it back on.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "dns_zone",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["dnssec_state"] == "on" && listHas(a.Metadata["dnssec_zsk_algorithms"], "rsasha1")
	},
}

// listHas reports whether a comma-separated metadata list contains v.
func listHas(list, v string) bool {
	return slices.Contains(strings.Split(list, ","), v)
}
