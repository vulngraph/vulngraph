package checks

import (
	"encoding/json"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// VPC-edge posture: network ACLs, VPC endpoints, transit gateways and
// Site-to-Site / Client VPN. Benchmarks: CIS AWS Foundations 6.2, AWS FSBP
// EC2.10/16/20/21/23/51/55-58/60/171/183.

// naclIngressEntry is one network ACL ingress entry as the collector stores
// it in `ingress_entries`.
type naclIngressEntry struct {
	RuleNumber int32  `json:"rule_number"`
	Protocol   string `json:"protocol"`
	Action     string `json:"action"`
	CIDR       string `json:"cidr"`
	FromPort   int32  `json:"from_port"`
	ToPort     int32  `json:"to_port"`
}

// naclEntries parses `ingress_entries`; ok is false when the key is absent or
// malformed (an unread ACL, never "no entries").
func naclEntries(a asset.Asset) ([]naclIngressEntry, bool) {
	raw, present := a.Metadata["ingress_entries"]
	if !present {
		return nil, false
	}
	var out []naclIngressEntry
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, false
	}
	// Evaluation order is the rule number, whatever order the JSON is in.
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleNumber < out[j].RuleNumber })
	return out, true
}

// naclMatchesTCP reports whether an entry applies to TCP traffic on port.
// Only TCP (6) and all-traffic (-1) entries can; UDP and ICMP never match a
// TCP admin port.
func naclMatchesTCP(e naclIngressEntry, port int32) bool {
	switch e.Protocol {
	case "-1":
		return true
	case "6":
		return e.FromPort <= port && port <= e.ToPort
	}
	return false
}

// naclWorldOpenPorts returns the ports from candidates that internet traffic
// reaches through the ACL, with the deciding rule number per port.
//
// AWS evaluates ingress entries lowest rule number first and the first match
// decides. For each internet family the verdict for a port is set by the
// first entry at which either the allowed or the denied ranges seen so far
// (entries covering the port, in rule order) add up to the whole family: an
// allow side reaching it opens the port, a deny side closes it, and neither
// leaves it closed (the `*` entry). So 0.0.0.0/0 and 0.0.0.0/1 + 128.0.0.0/1
// are the same world, a narrower deny ahead of a world allow still lets the
// rest of the internet in, and a narrower allow alone is not world-open — the
// GCP firewall-shadow stance: a miss costs at most a finding, never a hidden
// open port.
func naclWorldOpenPorts(entries []naclIngressEntry, candidates []int32) ([]int32, []string) {
	var (
		open  []int32
		rules []string
	)
	for _, port := range candidates {
		for _, world := range []netip.Prefix{cidrset.WorldV4, cidrset.WorldV6} {
			if rule, ok := naclDecidingEntry(entries, world, port); ok && strings.EqualFold(rule.Action, "allow") {
				open = append(open, port)
				rules = append(rules, strconv.Itoa(int(port))+"@"+strconv.Itoa(int(rule.RuleNumber)))
				break
			}
		}
	}
	return open, rules
}

// naclDecidingEntry returns the entry whose range completes the whole of the
// world family for TCP traffic to port, on the allow side or the deny side,
// whichever gets there first in rule-number order.
func naclDecidingEntry(entries []naclIngressEntry, world netip.Prefix, port int32) (naclIngressEntry, bool) {
	var allowed, denied []netip.Prefix
	for _, e := range entries {
		p, err := netip.ParsePrefix(strings.TrimSpace(e.CIDR))
		if err != nil || cidrset.WorldOf(p.Masked()) != world || !naclMatchesTCP(e, port) {
			continue
		}
		side := &denied
		if strings.EqualFold(e.Action, "allow") {
			side = &allowed
		}
		*side = append(*side, p.Masked())
		if cidrset.Cover(*side, world) {
			return e, true
		}
	}
	return naclIngressEntry{}, false
}

func naclAdminPortsOpen(a asset.Asset) []int32 {
	entries, ok := naclEntries(a)
	if !ok {
		return nil
	}
	open, _ := naclWorldOpenPorts(entries, adminPorts)
	return open
}

var awsNACLWorldOpenAdminPort = Check{
	ID:          "aws-nacl-world-open-admin-port",
	Title:       "Network ACL allows internet ingress to an admin port",
	Description: "Inbound network ACL entries allow the whole internet (0.0.0.0/0 or ::/0, or ranges that add up to it) to reach SSH, RDP or WinRM, and no lower-numbered deny of the whole internet blocks it first (AWS applies the first matching entry). The ACL is the subnet-level layer under the security groups: with it open, one permissive security group is all that stands between those ports and the internet. Severity follows the subnets it filters: Low only when every one is known to be private, Medium when one is public (routed to an internet gateway) or when the routing could not be read (an unknown path is graded as the worst case), and Info on a VPC's default ACL, which allows all inbound traffic out of the box and which AWS FSBP EC2.21 exempts (CIS AWS 6.2 does not).",
	Remediation: "Add a deny entry for the admin ports from 0.0.0.0/0 and ::/0 numbered below the allow, or narrow the allow to known ranges. Console: VPC > Network ACLs > Inbound rules. CLI: `aws ec2 create-network-acl-entry --network-acl-id ACL_ID --ingress --rule-number 50 --protocol tcp --port-range From=22,To=22 --cidr-block 0.0.0.0/0 --rule-action deny` (repeat for 3389 and for --ipv6-cidr-block ::/0).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_acl",
	// An ACL with no subnets filters nothing; aws-nacl-unused reports it.
	Violates: func(a asset.Asset) bool {
		n, ok := sgRuleCount(a, "subnet_association_count")
		return ok && n > 0 && len(naclAdminPortsOpen(a)) > 0
	},
	// The entries are JSON, which no literal in the predicate can stand in
	// for: without a world-open probe an unread ACL would read as closed.
	TableProbes: []string{`[{"rule_number":1,"protocol":"-1","action":"allow","cidr":"0.0.0.0/0","from_port":0,"to_port":65535}]`, "1"},
	SeverityFor: func(a asset.Asset) finding.Severity {
		switch {
		case a.Metadata["is_default"] == "true":
			return finding.SeverityInfo
		case a.Metadata["filters_public_subnet"] == "false":
			return finding.SeverityLow
		}
		// Public, or unknown (route tables unread, a subnet unclassified):
		// an unproven internet path is graded as the worst case, never down.
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		entries, _ := naclEntries(a)
		open, rules := naclWorldOpenPorts(entries, adminPorts)
		return map[string]string{
			"world_open_ports":      joinPorts(open),
			"allowing_rules":        strings.Join(rules, ","),
			"subnet_ids":            a.Metadata["subnet_ids"],
			"filters_public_subnet": a.Metadata["filters_public_subnet"],
		}
	},
}

var awsNACLUnused = Check{
	ID:          "aws-nacl-unused",
	Title:       "Network ACL is not associated with any subnet",
	Description: "The custom network ACL filters no subnet. An orphaned ACL is dead configuration that someone can later associate without reviewing its entries. A VPC's default ACL cannot be deleted and is not reported.",
	Remediation: "Delete the ACL if it is not needed. Console: VPC > Network ACLs > Actions > Delete. CLI: `aws ec2 delete-network-acl --network-acl-id ACL_ID`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_acl",
	Violates: func(a asset.Asset) bool {
		n, ok := sgRuleCount(a, "subnet_association_count")
		return ok && n == 0 && a.Metadata["is_default"] == "false"
	},
}

// requiredVPCEndpointServices are the services AWS FSBP expects an endpoint
// for in every VPC: EC2.10 (ec2), EC2.55 (ecr.api), EC2.56 (ecr.dkr), EC2.57
// (ssm), EC2.58 (ssm-contacts) and EC2.60 (ssm-incidents).
var requiredVPCEndpointServices = []string{"ec2", "ecr.api", "ecr.dkr", "ssm", "ssm-contacts", "ssm-incidents"}

// missingVPCEndpoints returns the required services the VPC has no endpoint
// for; ok is false when the endpoint listing was not read.
func missingVPCEndpoints(a asset.Asset) ([]string, bool) {
	raw, ok := a.Metadata["endpoint_services"]
	if !ok {
		return nil, false
	}
	have := strings.Split(raw, ",")
	var missing []string
	for _, s := range requiredVPCEndpointServices {
		if !slices.Contains(have, s) {
			missing = append(missing, s)
		}
	}
	return missing, true
}

var awsVPCMissingServiceEndpoints = Check{
	ID:          "aws-vpc-missing-service-endpoints",
	Title:       "VPC has no private endpoint for core AWS services",
	Description: "The VPC lacks a VPC endpoint for one or more of EC2, ECR (API and Docker registry), Systems Manager, and Incident Manager (contacts and incidents), so calls to them leave through an internet or NAT gateway. AWS FSBP EC2.10/55/56/57/58/60 expect all six. One finding per VPC lists every missing service. Info: this is a design preference (private API paths), not an exposure.",
	Remediation: "Create interface endpoints for the services the workloads in the VPC call. Console: VPC > Endpoints > Create endpoint. CLI: `aws ec2 create-vpc-endpoint --vpc-id VPC_ID --vpc-endpoint-type Interface --service-name com.amazonaws.REGION.ssm --subnet-ids SUBNET_IDS --security-group-ids SG_ID`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "vpc",
	Violates: func(a asset.Asset) bool {
		missing, ok := missingVPCEndpoints(a)
		return ok && len(missing) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		missing, _ := missingVPCEndpoints(a)
		return map[string]string{"missing_endpoint_services": strings.Join(missing, ",")}
	},
}

var awsTGWAutoAcceptSharedAttachments = Check{
	ID:          "aws-tgw-auto-accept-shared-attachments",
	Title:       "Transit gateway auto-accepts shared attachments",
	Description: "The transit gateway accepts VPC attachment requests from every account it is shared with without review. Any of those accounts can then join a VPC to the gateway's routing domain and, with default route-table association and propagation, reach the networks behind it.",
	Remediation: "Turn off automatic acceptance and approve attachments individually. Console: VPC > Transit gateways > Modify > uncheck Auto accept shared attachments. CLI: `aws ec2 modify-transit-gateway --transit-gateway-id TGW_ID --options AutoAcceptSharedAttachments=disable`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "transit_gateway",
	Violates:    func(a asset.Asset) bool { return a.Metadata["auto_accept_shared_attachments"] == "enable" },
}

var awsVPNTunnelDown = Check{
	ID:          "aws-vpn-tunnel-down",
	Title:       "Site-to-Site VPN connection has a tunnel down",
	Description: "At least one of the connection's two tunnels reports DOWN, so the link to the remote network has no redundancy (or no path at all). Resilience only.",
	Remediation: "Check the customer gateway's configuration for the down tunnel and its tunnel options. Console: VPC > Site-to-Site VPN connections > Tunnel details. CLI: `aws ec2 describe-vpn-connections --vpn-connection-ids VPN_ID --query 'VpnConnections[].VgwTelemetry'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "vpn_connection",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["state"] == "available" && countAbove(a, "tunnels_down")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"tunnels_down": a.Metadata["tunnels_down"], "tunnel_count": a.Metadata["tunnel_count"]}
	},
}

var awsVPNTunnelLoggingDisabled = Check{
	ID:          "aws-vpn-tunnel-logging-disabled",
	Title:       "Site-to-Site VPN tunnel does not log to CloudWatch",
	Description: "A tunnel of the connection has no CloudWatch Logs delivery, so IKE negotiation, tunnel establishment and dead-peer events are not recorded for troubleshooting or investigation.",
	Remediation: "Enable tunnel activity logging on both tunnels. Console: VPC > Site-to-Site VPN connections > Actions > Modify VPN tunnel options > Tunnel activity log. CLI: `aws ec2 modify-vpn-tunnel-options --vpn-connection-id VPN_ID --vpn-tunnel-outside-ip-address IP --tunnel-options 'LogOptions={CloudWatchLogOptions={LogEnabled=true,LogGroupArn=ARN}}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "vpn_connection",
	Violates:    func(a asset.Asset) bool { return countAbove(a, "tunnels_without_logging") },
}

var awsVPNIKEv1Allowed = Check{
	ID:          "aws-vpn-ikev1-allowed",
	Title:       "Site-to-Site VPN tunnel allows IKEv1",
	Description: "A tunnel of the connection accepts IKEv1, either explicitly or by listing no IKE version (both are then allowed). IKEv1 is the legacy key exchange with weaker negotiation and no built-in denial-of-service protection; AWS FSBP EC2.183 requires every tunnel to be restricted to IKEv2.",
	Remediation: "Restrict both tunnels to IKEv2 (the customer gateway must support it). Console: Modify VPN tunnel options > IKE version: ikev2 only. CLI: `aws ec2 modify-vpn-tunnel-options --vpn-connection-id VPN_ID --vpn-tunnel-outside-ip-address IP --tunnel-options 'IKEVersions=[{Value=ikev2}]'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "vpn_connection",
	Violates:    func(a asset.Asset) bool { return countAbove(a, "tunnels_allowing_ikev1") },
}

var awsClientVPNConnectionLoggingDisabled = Check{
	ID:          "aws-client-vpn-connection-logging-disabled",
	Title:       "Client VPN endpoint does not log client connections",
	Description: "The endpoint records no connection attempts, so who connected, from where and when cannot be reconstructed after the fact.",
	Remediation: "Enable connection logging to a CloudWatch Logs group. Console: VPC > Client VPN endpoints > Modify > Connection logging. CLI: `aws ec2 modify-client-vpn-endpoint --client-vpn-endpoint-id CVPN_ID --connection-log-options Enabled=true,CloudwatchLogGroup=GROUP`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "client_vpn_endpoint",
	Violates:    func(a asset.Asset) bool { return a.Metadata["connection_logging"] == "false" },
}

func awsVPCEdgeChecks() []Check {
	return []Check{
		awsNACLWorldOpenAdminPort,
		awsNACLUnused,
		awsVPCMissingServiceEndpoints,
		awsTGWAutoAcceptSharedAttachments,
		awsVPNTunnelDown,
		awsVPNTunnelLoggingDisabled,
		awsVPNIKEv1Allowed,
		awsClientVPNConnectionLoggingDisabled,
	}
}
