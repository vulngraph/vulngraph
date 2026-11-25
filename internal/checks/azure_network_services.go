package checks

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CIS Azure Foundations v6 controls on network services: WAF policies (7.14,
// 7.15), VPN gateways (7.9), Network Watcher and flow logs (6.1.1.5, 6.1.1.6,
// 7.5, 7.6, 7.8) and Bastion (8.4.1). Flow logs, watchers and Bastion are
// visibility and access-path hygiene, Low or Info.

// flowLogMinRetentionDays is the CIS 7.5/7.8 retention floor.
const flowLogMinRetentionDays = 90

// azureWAFNoRequestBodyInspection is CIS 7.14. With body inspection off, an
// injection payload in a POST body passes the WAF untouched — a bypass of the
// very rules the gateway is there for.
var azureWAFNoRequestBodyInspection = Check{
	ID:          "azure-waf-no-request-body-inspection",
	Title:       "Azure WAF policy does not inspect request bodies",
	Description: "An Application Gateway WAF policy in use has request body inspection turned off, so SQL injection, XSS and other payloads sent in POST bodies are never matched against the managed rules.",
	Remediation: "Turn on request body inspection (portal: WAF policy → Policy settings → Request body inspection: On; CLI: `az network application-gateway waf-policy policy-setting update --policy-name POLICY --resource-group RG --request-body-check true`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_waf_policy",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["attached"] == "true" && a.Metadata["request_body_check"] == "false"
	},
}

// azureWAFNoBotProtection is CIS 7.15.
var azureWAFNoBotProtection = Check{
	ID:          "azure-waf-no-bot-protection",
	Title:       "Azure WAF policy has no bot protection rule set",
	Description: "An Application Gateway WAF policy in use does not include the Microsoft_BotManagerRuleSet managed rule set, so traffic from known malicious bots and scanners is not blocked.",
	Remediation: "Add the bot protection rule set (portal: WAF policy → Managed rules → Assign → Microsoft_BotManagerRuleSet; CLI: `az network application-gateway waf-policy managed-rule rule-set add --policy-name POLICY --resource-group RG --type Microsoft_BotManagerRuleSet --version 1.1`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_waf_policy",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["attached"] == "true" && a.Metadata["bot_protection"] == "false"
	},
}

// azureVPNP2SNonEntraAuth is CIS 7.9. Certificate and RADIUS authentication
// are not weak, but they bypass Entra Conditional Access and MFA; Low.
var azureVPNP2SNonEntraAuth = Check{
	ID:          "azure-vpn-p2s-non-entra-auth",
	Title:       "Azure VPN point-to-site accepts non-Entra authentication",
	Description: "The VPN gateway's point-to-site configuration accepts certificate or RADIUS authentication instead of only Microsoft Entra ID, so remote connections are not subject to Entra MFA, Conditional Access or account disablement.",
	Remediation: "Set the point-to-site authentication type to Azure Active Directory only (portal: VPN gateway → Point-to-site configuration → Authentication type; CLI: `az network vnet-gateway update --name GW --resource-group RG --vpn-auth-type AAD --aad-tenant ... --aad-audience ... --aad-issuer ...`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_vpn_gateway",
	Violates: func(a asset.Asset) bool {
		t, ok := a.Metadata["p2s_auth_types"]
		return ok && a.Metadata["p2s_enabled"] == "true" && t != "AAD"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"p2s_auth_types": a.Metadata["p2s_auth_types"]}
	},
}

// flowLogRetentionShort reports an enabled flow log keeping records for fewer
// than 90 days; 0 is Azure's "retain indefinitely".
func flowLogRetentionShort(a asset.Asset) bool {
	if a.Metadata["flow_log_enabled"] != "true" {
		return false
	}
	days, err := strconv.Atoi(a.Metadata["flow_log_retention_days"])
	return err == nil && days > 0 && days < flowLogMinRetentionDays
}

func flowLogEvidence(a asset.Asset) map[string]string {
	return map[string]string{"retention_days": a.Metadata["flow_log_retention_days"]}
}

// azureVNetFlowLogRetentionShort is CIS 7.8.
var azureVNetFlowLogRetentionShort = Check{
	ID:          "azure-vnet-flow-log-retention-short",
	Title:       "Azure VNet flow log retention is under 90 days",
	Description: "The virtual network's flow log deletes records after fewer than 90 days, which is shorter than most incidents take to discover.",
	Remediation: "Set retention to 90 days or more, or 0 to keep records indefinitely (portal: Network Watcher → Flow logs → the log → Retention days; CLI: `az network watcher flow-log update --location REGION --name LOG --retention 90`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_vnet",
	Violates:    flowLogRetentionShort,
	TableProbes: []string{"30"},
	EvidenceFor: flowLogEvidence,
}

// azureNSGFlowLogRetentionShort is CIS 7.5 (NSG flow logs; retiring).
var azureNSGFlowLogRetentionShort = Check{
	ID:          "azure-nsg-flow-log-retention-short",
	Title:       "Azure NSG flow log retention is under 90 days",
	Description: "The network security group's flow log deletes records after fewer than 90 days, which is shorter than most incidents take to discover.",
	Remediation: "Set retention to 90 days or more (CLI: `az network watcher flow-log update --location REGION --name LOG --retention 90`). NSG flow logs are being retired; plan the move to VNet flow logs.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "security_group",
	Violates:    flowLogRetentionShort,
	TableProbes: []string{"30"},
	EvidenceFor: flowLogEvidence,
}

// azureVNetFlowLogsNotAnalysed is CIS 6.1.1.6: the VNet has a flow log and it
// feeds Log Analytics through traffic analytics. One finding for either gap.
var azureVNetFlowLogsNotAnalysed = Check{
	ID:          "azure-vnet-flow-logs-not-analysed",
	Title:       "Azure VNet flow logs are not sent to Log Analytics",
	Description: "The virtual network has no enabled flow log, or its flow log does not feed a Log Analytics workspace through traffic analytics, so its traffic cannot be queried during an investigation.",
	Remediation: "Create a VNet flow log with traffic analytics (portal: Network Watcher → Flow logs → Create, target the VNet, enable Traffic analytics; CLI: `az network watcher flow-log create --location REGION --name LOG --vnet VNET --storage-account SA --traffic-analytics true --workspace WS`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_vnet",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["flow_log_enabled"] == "false" || a.Metadata["flow_log_traffic_analytics"] == "false"
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["flow_log_enabled"] == "false" {
			return "Azure VNet has no flow log"
		}
		return "Azure VNet flow logs are not sent to Log Analytics"
	},
}

// azureNSGFlowLogsNotAnalysed is CIS 6.1.1.5 for the NSG flow logs that exist.
// Azure stopped accepting new NSG flow logs on 30 June 2025, so an NSG with
// none is not asked to create one: its coverage is the VNet flow log
// (azure-vnet-flow-logs-not-analysed).
var azureNSGFlowLogsNotAnalysed = Check{
	ID:          "azure-nsg-flow-logs-not-analysed",
	Title:       "Azure NSG flow logs are not sent to Log Analytics",
	Description: "The network security group's flow log is enabled but does not feed a Log Analytics workspace through traffic analytics, so its traffic cannot be queried during an investigation.",
	Remediation: "Enable traffic analytics on the flow log (CLI: `az network watcher flow-log update --location REGION --name LOG --traffic-analytics true --workspace WS`), or replace it with a VNet flow log with traffic analytics.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "security_group",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["flow_log_enabled"] == "true" && a.Metadata["flow_log_traffic_analytics"] == "false"
	},
}

// azureNetworkWatcherMissingRegion is CIS 7.6, one finding per subscription.
var azureNetworkWatcherMissingRegion = Check{
	ID:          "azure-network-watcher-missing-region",
	Title:       "Azure Network Watcher missing in regions with VNets",
	Description: "One or more regions hold virtual networks but no Network Watcher, so flow logs, connection troubleshooting and packet capture are unavailable there.",
	Remediation: "Enable Network Watcher in each listed region (portal: Network Watcher → Enable; CLI: `az network watcher configure --locations REGION --enabled true --resource-group NetworkWatcherRG`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_subscription",
	Violates:    func(a asset.Asset) bool { return a.Metadata["network_watcher_missing_regions"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"regions": a.Metadata["network_watcher_missing_regions"]}
	},
}

// azureNoBastionHost is CIS 8.4.1, on subscriptions that run VMs: without one
// there is nothing to reach.
var azureNoBastionHost = Check{
	ID:          "azure-no-bastion-host",
	Title:       "Azure subscription runs VMs but has no Bastion host",
	Description: "The subscription has virtual machines and no Azure Bastion host, so RDP and SSH reach them some other way — typically a public IP or an NSG rule open to the internet.",
	Remediation: "Deploy Azure Bastion into the VNets that hold VMs (portal: Bastions → Create; CLI: `az network bastion create --name BASTION --resource-group RG --vnet-name VNET --public-ip-address PIP --location REGION`), then close direct RDP/SSH access.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_subscription",
	Violates: func(a asset.Asset) bool {
		vms, err := strconv.Atoi(a.Metadata["vm_count"])
		return err == nil && vms > 0 && a.Metadata["bastion_host_count"] == "0"
	},
	TableProbes: []string{"1"},
	EvidenceFor: func(a asset.Asset) map[string]string { return map[string]string{"vm_count": a.Metadata["vm_count"]} },
}
