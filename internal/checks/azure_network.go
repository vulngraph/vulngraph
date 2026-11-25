package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CIS Azure Foundations v6 networking controls (7.3, 7.4, 7.10–7.13, 8.5)
// evaluable from the NSG, VNet and Application Gateway listings the collector
// already reads.

// azureNSGUDPOpenInternet is CIS 7.3. Internet-reachable UDP services (DNS,
// NTP, SSDP, memcached) are the classic reflection/amplification sources and
// rarely need to face the whole internet.
var azureNSGUDPOpenInternet = Check{
	ID:          "azure-nsg-udp-open-internet",
	Title:       "Azure NSG allows UDP from the internet",
	Description: "An inbound NSG rule admits UDP (or any protocol) from 0.0.0.0/0, ::/0, * or the Internet service tag on at least one port, after higher-priority deny rules are applied. Internet-facing UDP services are common reflection and amplification sources.",
	Remediation: "Restrict the rule's source to known address ranges or remove it. Put UDP services that must be public behind Azure DDoS Network Protection.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "security_group",
	Violates:    func(a asset.Asset) bool { return nsgAllowsWorldAnyPort(a, "udp") },
}

// azureNSGHTTPOpenInternet is CIS 7.4. Web ports are usually exposed on
// purpose, which is why this is Low: the benchmark asks that each one be
// evaluated, and the finding is the prompt to do so.
var azureNSGHTTPOpenInternet = Check{
	ID:          "azure-nsg-http-open-internet",
	Title:       "Azure NSG allows HTTP/HTTPS (80/443) from the internet",
	Description: "An inbound NSG rule admits TCP/80 or TCP/443 from the internet. Workloads serving the internet directly bypass the WAF and TLS policy an Application Gateway or Front Door would enforce.",
	Remediation: "Publish web workloads through an Application Gateway or Front Door with a WAF and restrict the NSG source to that service, or confirm the exposure is intended.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "security_group",
	Violates: func(a asset.Asset) bool {
		return nsgAllowsWorldPort(a, 80) || nsgAllowsWorldPort(a, 443)
	},
}

// nsgAllowsWorldAnyPort reports whether internet traffic of proto reaches any
// port through a port-scoped rule (all-ports rules are the rollup's).
func nsgAllowsWorldAnyPort(a asset.Asset, proto string) bool {
	return nsgVerdictAnywhere(nsgWorldRules(a), proto, nsgAllowedNarrow)
}

// nsgVerdictAnywhere reports whether some port of proto gets verdict want.
func nsgVerdictAnywhere(rules []nsgRule, proto string, want nsgVerdict) bool {
	for _, port := range nsgPortCandidates(rules) {
		if port >= 0 && port <= 65535 && nsgFirstMatch(rules, proto, port) == want {
			return true
		}
	}
	return false
}

// azureNSGAllPortsOpenInternet is the rollup for one rule that opens every
// port to the internet. It evidences CIS 7.1–7.4 at once; the per-port checks
// step aside for ports such a rule admits, so one root cause is one finding.
var azureNSGAllPortsOpenInternet = Check{
	ID:          "azure-nsg-all-ports-open-internet",
	Title:       "Azure NSG allows all ports from the internet",
	Description: "An inbound NSG rule admits every port from 0.0.0.0/0, ::/0, * or the Internet service tag (TCP, UDP or any protocol), after higher-priority deny rules are applied. That exposes RDP, SSH, WinRM, web and UDP services alike.",
	Remediation: "Replace the rule with port-scoped rules restricted to known source ranges. Reach management ports through Azure Bastion or a VPN.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   "security_group",
	Violates: func(a asset.Asset) bool {
		rules := nsgWorldRules(a)
		return nsgVerdictAnywhere(rules, "tcp", nsgAllowedAllPorts) || nsgVerdictAnywhere(rules, "udp", nsgAllowedAllPorts)
	},
}

// azureSubnetNoNSG is CIS 7.11. Platform subnets where Azure does not support
// (or manages) the NSG are exempt by their reserved names.
var azureSubnetNoNSG = Check{
	ID:          "azure-subnet-no-nsg",
	Title:       "Azure subnet has no network security group",
	Description: "The subnet has no NSG associated, so traffic between it and the rest of the VNet (and anything a NIC without its own NSG exposes) is filtered only by Azure's default rules.",
	Remediation: "Associate a network security group with the subnet: `az network vnet subnet update --vnet-name VNET --name SUBNET --resource-group RG --network-security-group NSG`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_subnet",
	Violates: func(a asset.Asset) bool {
		return observedNone(a, "nsg_id") && !azureNSGExemptSubnets[a.Name]
	},
}

// azureNSGExemptSubnets are the reserved subnet names Azure forbids or manages
// NSGs on (VPN/ExpressRoute gateway, Azure Firewall, Route Server).
var azureNSGExemptSubnets = map[string]bool{
	"GatewaySubnet":                 true,
	"AzureFirewallSubnet":           true,
	"AzureFirewallManagementSubnet": true,
	"RouteServerSubnet":             true,
}

// azureVNetNoDDoSProtection is CIS 8.5 (Level 2). DDoS Network Protection is a
// paid per-VNet plan most estates deliberately skip, so this is Info.
var azureVNetNoDDoSProtection = Check{
	ID:          "azure-vnet-no-ddos-protection",
	Title:       "Azure VNet has no DDoS Network Protection",
	Description: "DDoS Network Protection is not enabled on the virtual network, so its public IPs get only the platform's basic infrastructure protection.",
	Remediation: "Associate the VNet with a DDoS protection plan where its public endpoints justify the cost.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_vnet",
	Violates:    func(a asset.Asset) bool { return a.Metadata["ddos_protection"] == "false" },
}

// azureAppGatewayNoWAF is CIS 7.10.
var azureAppGatewayNoWAF = Check{
	ID:          "azure-appgw-no-waf",
	Title:       "Azure Application Gateway has no WAF",
	Description: "The Application Gateway has neither a WAF policy attached nor its inline web application firewall enabled, so internet traffic reaches the backends without OWASP rule inspection.",
	Remediation: "Move the gateway to the WAF_v2 SKU and attach a WAF policy in Prevention mode.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_app_gateway",
	Violates:    func(a asset.Asset) bool { return a.Metadata["waf_enabled"] == "false" },
}

// azureAppGatewayMinTLS is CIS 7.12.
var azureAppGatewayMinTLS = Check{
	ID:          "azure-appgw-min-tls-below-12",
	Title:       "Azure Application Gateway accepts TLS below 1.2",
	Description: "The gateway's SSL policy accepts TLS 1.0 or 1.1, which allow downgrade attacks and weak cipher suites on an internet-facing listener.",
	Remediation: "Set the SSL policy to AppGwSslPolicy20220101 (or a custom policy with minProtocolVersion TLSv1_2).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_app_gateway",
	Violates: func(a asset.Asset) bool {
		v := a.Metadata["min_tls_version"]
		return v == "1.0" || v == "1.1"
	},
}

// azureAppGatewayHTTP2Disabled is CIS 7.13: a performance setting, Info.
var azureAppGatewayHTTP2Disabled = Check{
	ID:          "azure-appgw-http2-disabled",
	Title:       "Azure Application Gateway has HTTP/2 disabled",
	Description: "HTTP/2 is not enabled on the Application Gateway's listeners.",
	Remediation: "Enable HTTP/2: `az network application-gateway update --name AG --resource-group RG --http2 Enabled`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_app_gateway",
	Violates:    func(a asset.Asset) bool { return a.Metadata["http2_enabled"] == "false" },
}
