package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CIS Azure Foundations v6 section 2.1 (Azure Databricks), read from the
// workspace resource.

// azureDatabricksPublicNetworkAccess is CIS 2.1.10. The workspace UI and REST
// API still need an Entra login or token, so Medium.
var azureDatabricksPublicNetworkAccess = Check{
	ID:          "azure-databricks-public-network-access",
	Title:       "Azure Databricks workspace allows public network access",
	Description: "Public network access is enabled, so the workspace's web UI and REST API answer from the internet; any leaked personal access token or session is usable from anywhere.",
	Remediation: "Set Public network access to Disabled and reach the workspace through private endpoints (portal: workspace → Networking; requires the Premium tier and VNet injection).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_databricks_workspace",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_network_access"] == "Enabled" },
}

// azureDatabricksNoPrivateEndpoint is CIS 2.1.11.
var azureDatabricksNoPrivateEndpoint = Check{
	ID:          "azure-databricks-no-private-endpoint",
	Title:       "Azure Databricks workspace has no private endpoint",
	Description: "The workspace has no approved private endpoint connection, so users and clusters reach its control plane over public endpoints.",
	Remediation: "Create a private endpoint for the workspace (sub-resource databricks_ui_api) in the VNet clients use (portal: workspace → Networking → Private endpoint connections).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_databricks_workspace",
	Violates:    func(a asset.Asset) bool { return a.Metadata["private_endpoint_count"] == "0" },
}

// azureDatabricksPublicIP is CIS 2.1.9: secure cluster connectivity off gives
// every cluster node a public IP.
var azureDatabricksPublicIP = Check{
	ID:          "azure-databricks-public-ip",
	Title:       "Azure Databricks clusters get public IP addresses",
	Description: "Secure cluster connectivity (No Public IP) is off, so every cluster node gets a public IP and the workspace opens inbound ports to it from the Databricks control plane.",
	Remediation: "Enable secure cluster connectivity (portal: workspace → Networking → Deploy with Secure Cluster Connectivity (No Public IP): Yes; CLI: `az databricks workspace update --name WS --resource-group RG --enable-no-public-ip`).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_databricks_workspace",
	Violates:    func(a asset.Asset) bool { return a.Metadata["no_public_ip"] == "false" },
}

// azureDatabricksNoVNetInjection is CIS 2.1.1.
var azureDatabricksNoVNetInjection = Check{
	ID:          "azure-databricks-no-vnet-injection",
	Title:       "Azure Databricks workspace is not deployed in a customer VNet",
	Description: "The workspace runs its clusters in a Databricks-managed virtual network, so their traffic cannot be filtered by your NSGs or routed through your firewall, and private endpoints cannot be used.",
	Remediation: "Redeploy the workspace with VNet injection into a customer-managed VNet (portal: Create workspace → Networking → Deploy in your own Virtual Network); this cannot be changed on an existing workspace.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_databricks_workspace",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "custom_vnet_id") },
}

// azureDatabricksSubnetNoNSG is CIS 2.1.2.
var azureDatabricksSubnetNoNSG = Check{
	ID:          "azure-databricks-subnet-no-nsg",
	Title:       "Azure Databricks subnet has no network security group",
	Description: "A subnet the workspace's clusters are injected into has no NSG associated, so cluster traffic is not filtered.",
	Remediation: "Associate an NSG with the workspace's public and private subnets: `az network vnet subnet update --vnet-name VNET --name SUBNET --resource-group RG --network-security-group NSG`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_databricks_workspace",
	Violates:    func(a asset.Asset) bool { return a.Metadata["subnets_without_nsg"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"subnets": a.Metadata["subnets_without_nsg"]}
	},
}

// azureDatabricksNoCMK is CIS 2.1.8 (Level 2): Microsoft-managed keys already
// encrypt everything, so a customer key is a control-over-keys choice, Info.
var azureDatabricksNoCMK = Check{
	ID:          "azure-databricks-no-cmk",
	Title:       "Azure Databricks workspace uses no customer-managed key",
	Description: "None of the workspace's managed services, managed disks or DBFS root is encrypted with a customer-managed key, so revoking access to the data means deleting the workspace rather than disabling a key.",
	Remediation: "Configure customer-managed keys from Key Vault for managed services and managed disks (portal: workspace → Encryption; Premium tier).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_databricks_workspace",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "cmk_encryption") },
}
