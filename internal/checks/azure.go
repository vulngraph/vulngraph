package checks

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// Azure checks covering topics from the CIS Microsoft Azure Foundations
// Benchmark. Original implementations; IDs are Vulngraph's own labels, not
// official CIS recommendation numbers (see NOTICE).
// Azure asset collection alone doesn't give us posture analysis; every check
// here fills that gap.

var azureNSGRDPOpenInternet = Check{
	ID:          "azure-nsg-rdp-not-open-internet",
	Title:       "Azure NSG allows RDP (3389) from the internet",
	Description: "An inbound NSG rule permits TCP/3389 from 0.0.0.0/0 or ::/0, exposing RDP to the whole internet.",
	Remediation: "Remove or restrict the NSG inbound rule. Use Azure Bastion or a VPN for RDP access instead.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   "security_group",
	Violates:    func(a asset.Asset) bool { return nsgAllowsWorldPort(a, 3389) },
}

var azureNSGSSHOpenInternet = Check{
	ID:          "azure-nsg-ssh-not-open-internet",
	Title:       "Azure NSG allows SSH (22) from the internet",
	Description: "An inbound NSG rule permits TCP/22 from 0.0.0.0/0 or ::/0, exposing SSH to the whole internet.",
	Remediation: "Remove or restrict the NSG inbound rule. Use Azure Bastion or a VPN for SSH access instead.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   "security_group",
	Violates:    func(a asset.Asset) bool { return nsgAllowsWorldPort(a, 22) },
}

var azureStoragePublicAccess = Check{
	ID:          "azure-storage-public-blob-access",
	Title:       "Azure storage account permits public blob access",
	Description: "AllowBlobPublicAccess is enabled, which permits containers to be made public. This is account-level permission, not proof any container is actually public — the individual container access levels are not collected — so it is surfaced at low severity.",
	Remediation: "Set AllowBlobPublicAccess=false on the storage account unless public containers are required.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

var azureStorageHTTPSOnly = Check{
	ID:          "azure-storage-https-not-enforced",
	Title:       "Azure storage account permits HTTP traffic",
	Description: "Secure transfer is not required, allowing unencrypted HTTP connections to the storage account.",
	Remediation: "Enable 'Secure transfer required' (EnableHTTPSTrafficOnly=true) on the storage account.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["https_only"] == "false" },
}

var azureSQLServerPublicAccess = Check{
	ID:          "azure-sql-server-public-network-access",
	Title:       "Azure SQL server has public network access enabled",
	Description: "PublicNetworkAccess is Enabled, so the SQL server endpoint is reachable from the internet. Server firewall rules and SQL/AAD authentication still gate access — this is network reachability, not confirmed unauthenticated exposure — so it is surfaced at low severity.",
	Remediation: "Set PublicNetworkAccess=Disabled and route connectivity via a private endpoint.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_sql_server",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

var azureVMDirectPublicIP = Check{
	ID:          "azure-vm-direct-public-ip",
	Title:       "Azure VM has a directly assigned public IP address",
	Description: "The VM NIC has a public IP assigned, making it directly internet-reachable without a load balancer.",
	Remediation: "Remove the public IP from the VM NIC and route traffic via an Azure Load Balancer or Application Gateway.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_vm",
	// direct_public_ip, not PublicIP: the collector leaves the key out when a
	// NIC could not be read, so that VM is not evaluable rather than clean.
	Violates: func(a asset.Asset) bool { return a.Metadata["direct_public_ip"] == "true" },
}

// nsgAllowsWorldPort checks whether an Azure NSG admits internet traffic on
// the given TCP port through a port-scoped rule. Rules (the collector's
// nsgRule JSON: allow AND deny, with priority) are evaluated as Azure does:
// ascending priority, the first rule matching protocol, port and an internet
// source wins. A port admitted by an all-ports rule is left to
// azure-nsg-all-ports-open-internet.
func nsgAllowsWorldPort(a asset.Asset, port int32) bool {
	return nsgFirstMatch(nsgWorldRules(a), "tcp", port) == nsgAllowedNarrow
}

// nsgRule is one entry of the collector's Metadata["ingress"] JSON.
type nsgRule struct {
	Protocol string   `json:"protocol"`
	FromPort int32    `json:"from_port"`
	ToPort   int32    `json:"to_port"`
	CIDRs    []string `json:"cidrs"`
	Access   string   `json:"access"`
	Priority int32    `json:"priority"`
	NSGDestination
}

// nsgWorldRules returns the NSG's inbound rules whose source includes the
// internet, in Azure's evaluation order (ascending priority). Rules from
// narrower sources can neither admit nor block internet traffic.
func nsgWorldRules(a asset.Asset) []nsgRule {
	var rules []nsgRule
	if err := json.Unmarshal([]byte(a.Metadata["ingress"]), &rules); err != nil {
		return nil
	}
	world := rules[:0]
	for _, r := range rules {
		if azureWorldCIDR(r.CIDRs) {
			world = append(world, r)
		}
	}
	sort.SliceStable(world, func(i, j int) bool { return world[i].Priority < world[j].Priority })
	return world
}

// nsgRuleMatches reports whether r applies to internet traffic of protocol
// proto ("tcp"/"udp") on port. A 0-0 range is the collector's "any port".
func nsgRuleMatches(r nsgRule, proto string, port int32) bool {
	p := strings.ToLower(r.Protocol)
	if p != proto && p != "*" && p != "any" {
		return false
	}
	return (r.FromPort == 0 && r.ToPort == 0) || (r.FromPort <= port && port <= r.ToPort)
}

// nsgVerdict is what an NSG does with internet traffic on one protocol/port.
type nsgVerdict int

const (
	nsgDenied nsgVerdict = iota
	// nsgAllowedNarrow: admitted by a rule scoped to particular ports — the
	// per-port checks (RDP, SSH, WinRM, UDP, HTTP) report these.
	nsgAllowedNarrow
	// nsgAllowedAllPorts: admitted by a rule spanning every port. One such
	// rule is one root cause, reported once by azure-nsg-all-ports-open-internet
	// rather than once per per-port check.
	nsgAllowedAllPorts
)

// nsgFirstMatch evaluates world rules (already priority-ordered) as Azure
// does: for each destination the first rule matching protocol and port wins;
// no match falls through to the default DenyAllInBound. An Allow is therefore
// closed only when the Denies above it cover every destination it reaches
// (NSGDestinationsCover); the first Allow left open decides the verdict.
func nsgFirstMatch(rules []nsgRule, proto string, port int32) nsgVerdict {
	var denies []NSGDestination
	for _, r := range rules {
		if !nsgRuleMatches(r, proto, port) {
			continue
		}
		switch {
		case strings.EqualFold(r.Access, "deny"):
			denies = append(denies, r.NSGDestination)
		case NSGDestinationsCover(denies, r.NSGDestination):
			// Closed wherever it reaches; a later Allow may still open elsewhere.
		case nsgRuleAllPorts(r):
			return nsgAllowedAllPorts
		default:
			return nsgAllowedNarrow
		}
	}
	return nsgDenied
}

// NSGDestination is where an NSG rule applies, as the Azure collector
// serialises it: address prefixes (CIDRs, single IPs, service tags, "*") and
// application security group IDs.
type NSGDestination struct {
	Prefixes []string `json:"destinations,omitempty"`
	ASGs     []string `json:"destination_asgs,omitempty"`
}

// NSGDestinationsCover reports whether the union of the denies' destinations
// provably covers every destination allow reaches, so that the denies close
// the allow outright. A "*" or "Any" deny covers everything; address ranges
// are covered by the union of the deny ranges; a service tag or an
// application security group is covered only by the same tag or group (their
// members are not collected). An allow or deny with no destination recorded,
// or one in a form not recognised, covers nothing: a deny credited wrongly
// would hide a reachable port, a missed one costs at most a finding.
// Exported so the internet-reachability correlator agrees with these checks.
func NSGDestinationsCover(denies []NSGDestination, allow NSGDestination) bool {
	var ranges []netip.Prefix
	named := map[string]bool{}
	for _, d := range denies {
		for _, p := range d.Prefixes {
			t := strings.ToLower(strings.TrimSpace(p))
			if t == "*" || t == "any" {
				return true
			}
			if pf, ok := nsgAddressPrefix(t); ok {
				ranges = append(ranges, pf)
			} else {
				named["prefix:"+t] = true
			}
		}
		for _, g := range d.ASGs {
			named["asg:"+strings.ToLower(strings.TrimSpace(g))] = true
		}
	}
	if len(allow.Prefixes) == 0 && len(allow.ASGs) == 0 {
		return false
	}
	for _, p := range allow.Prefixes {
		t := strings.ToLower(strings.TrimSpace(p))
		if pf, ok := nsgAddressPrefix(t); ok {
			if !cidrset.Cover(ranges, pf) {
				return false
			}
		} else if !named["prefix:"+t] {
			return false
		}
	}
	for _, g := range allow.ASGs {
		if !named["asg:"+strings.ToLower(strings.TrimSpace(g))] {
			return false
		}
	}
	return true
}

// nsgAddressPrefix parses an NSG address prefix written as a CIDR or a single
// IP; anything else (a service tag, "*") is not an address range.
func nsgAddressPrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// nsgRuleAllPorts reports whether r spans the whole port range ("*" in the
// rule, serialised 0-65535; a 0-0 range is the collector's "any port").
func nsgRuleAllPorts(r nsgRule) bool {
	return (r.FromPort == 0 && r.ToPort == 0) || (r.FromPort <= 0 && r.ToPort >= 65535)
}

// nsgPortCandidates are the ports at which first-match outcomes can change:
// port 0 and every rule's FromPort and ToPort+1. Outcomes are constant
// between them, so evaluating these is exact without walking 65536 ports.
func nsgPortCandidates(rules []nsgRule) []int32 {
	out := []int32{0}
	for _, r := range rules {
		out = append(out, r.FromPort, r.ToPort+1)
	}
	return out
}

// azureWorldCIDR reports whether a CIDR list includes an internet-wide range,
// including Azure's "Internet" service tag and the "*"/"Any" wildcards.
func azureWorldCIDR(cidrs []string) bool {
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "0.0.0.0/0" || c == "::/0" || c == "*" || strings.EqualFold(c, "Internet") || strings.EqualFold(c, "Any") {
			return true
		}
	}
	return false
}
