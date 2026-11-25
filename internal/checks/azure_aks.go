package checks

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CIS AKS Benchmark managed-service controls (section 5) and the cluster
// add-ons behind section 4, read from the managed-cluster resource. Node pool
// settings are folded into the cluster asset, so each is one finding per
// cluster.

const aksType = "azure_aks_cluster"

// aksAPIUnrestricted reports a public API server with no authorized IP range
// that excludes anyone.
func aksAPIUnrestricted(a asset.Asset) bool {
	ranges, ok := a.Metadata["authorized_ip_ranges"]
	if !ok || a.Metadata["api_public"] != "true" {
		return false
	}
	if ranges == "" {
		return true
	}
	for _, r := range strings.Split(ranges, ",") {
		if r == "0.0.0.0/0" {
			return true
		}
	}
	return false
}

// azureAKSAPIUnrestricted is CIS AKS 5.4.1: the API server answers the whole
// internet. Authentication still gates it, but every API server CVE and every
// leaked kubeconfig is reachable from anywhere — graded like the GKE and EKS
// public-endpoint checks.
var azureAKSAPIUnrestricted = Check{
	ID:          "azure-aks-api-unrestricted",
	Title:       "AKS API server is reachable from the whole internet",
	Description: "The cluster's API server has a public endpoint and no authorized IP ranges (or a range of 0.0.0.0/0), so anyone on the internet can reach it and try credentials or API server vulnerabilities.",
	Remediation: "Restrict the API server to known ranges (`az aks update --name CLUSTER --resource-group RG --api-server-authorized-ip-ranges CIDR,...`) or make the cluster private.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    aksAPIUnrestricted,
}

// azureAKSAPIPublic is the remainder of CIS AKS 5.4.2: a public endpoint
// restricted by authorized ranges. Steps aside for the unrestricted case,
// azure-aks-api-unrestricted's finding.
var azureAKSAPIPublic = Check{
	ID:          "azure-aks-api-public",
	Title:       "AKS API server has a public endpoint",
	Description: "The cluster is not private: its API server has a public endpoint, restricted by authorized IP ranges. The allowlist narrows who can connect, but the endpoint is still on the internet.",
	Remediation: "Use a private cluster (`az aks create ... --enable-private-cluster`) or API Server VNet Integration with public access disabled.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates: func(a asset.Asset) bool {
		_, ok := a.Metadata["authorized_ip_ranges"]
		return ok && a.Metadata["api_public"] == "true" && !aksAPIUnrestricted(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"authorized_ip_ranges": a.Metadata["authorized_ip_ranges"]}
	},
}

// azureAKSNodePublicIP is CIS AKS 5.4.3.
var azureAKSNodePublicIP = Check{
	ID:          "azure-aks-node-public-ip",
	Title:       "AKS node pools give nodes public IP addresses",
	Description: "One or more node pools assign a public IP to every node, so the nodes are directly addressable from the internet and only NSG rules stand in front of the kubelet, NodePorts and host ports.",
	Remediation: "Recreate the node pools without node public IPs (`az aks nodepool add ... ` without --enable-node-public-ip) and give egress through a load balancer or NAT gateway.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_public_ip"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_public_ip"),
}

// azureAKSNoNetworkPolicy is CIS AKS 5.4.4. Low, as for GKE: NetworkPolicy
// objects do nothing without an engine, but with one the policies still have
// to be written.
var azureAKSNoNetworkPolicy = Check{
	ID:          "azure-aks-no-network-policy",
	Title:       "AKS cluster has no network policy engine",
	Description: "The cluster runs no NetworkPolicy engine (Azure, Calico or Cilium), so Kubernetes NetworkPolicy objects are accepted but not enforced and every pod can reach every other pod.",
	Remediation: "Enable a network policy engine: `az aks update --name CLUSTER --resource-group RG --network-policy cilium` (with the Cilium dataplane) or calico/azure.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["network_policy"] == "none" },
}

// azureAKSRBACDisabled: a cluster without Kubernetes RBAC authorizes every
// authenticated request for everything (CIS AKS 5.5.1/5.5.2 presuppose RBAC).
var azureAKSRBACDisabled = Check{
	ID:          "azure-aks-rbac-disabled",
	Title:       "AKS cluster has Kubernetes RBAC disabled",
	Description: "Kubernetes RBAC is off, so every authenticated user and service account can do anything in the cluster. RBAC can only be chosen at creation.",
	Remediation: "Recreate the cluster with RBAC enabled (the default; `az aks create` without --disable-rbac) and migrate workloads.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["rbac_enabled"] == "false" },
}

// azureAKSNoEntraIntegration is CIS AKS 5.5.1: without Entra integration the
// only way in is a local certificate credential.
var azureAKSNoEntraIntegration = Check{
	ID:          "azure-aks-no-entra-integration",
	Title:       "AKS cluster is not integrated with Microsoft Entra ID",
	Description: "The cluster has no Microsoft Entra integration, so users authenticate with the cluster's local client certificates: shared, long-lived credentials that MFA, Conditional Access and account disablement do not reach.",
	Remediation: "Enable AKS-managed Entra integration (`az aks update --name CLUSTER --resource-group RG --enable-aad --aad-admin-group-object-ids GROUP`), then disable local accounts.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["entra_integration"] == "false" },
}

// azureAKSLocalAccountsEnabled is the rest of CIS AKS 5.5.1: with Entra
// integration on, local accounts are a back door around it. Steps aside
// without Entra, where they are the only way in (azure-aks-no-entra-integration).
var azureAKSLocalAccountsEnabled = Check{
	ID:          "azure-aks-local-accounts-enabled",
	Title:       "AKS cluster still allows local accounts",
	Description: "Local accounts are enabled on an Entra-integrated cluster, so anyone allowed listClusterAdminCredential gets a static cluster-admin certificate that bypasses Entra, MFA and Kubernetes RBAC review.",
	Remediation: "Disable local accounts: `az aks update --name CLUSTER --resource-group RG --disable-local-accounts`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["entra_integration"] == "true" && a.Metadata["local_accounts_disabled"] == "false"
	},
}

// azureAKSNoAzureRBAC is CIS AKS 5.5.2.
var azureAKSNoAzureRBAC = Check{
	ID:          "azure-aks-no-azure-rbac",
	Title:       "AKS cluster does not use Azure RBAC for Kubernetes authorization",
	Description: "The Entra-integrated cluster authorizes users only through in-cluster Kubernetes RBAC bindings, so cluster access is not governed, reviewed or PIM-gated alongside the rest of the Azure role assignments.",
	Remediation: "Enable Azure RBAC for Kubernetes authorization: `az aks update --name CLUSTER --resource-group RG --enable-azure-rbac`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["entra_integration"] == "true" && a.Metadata["azure_rbac"] == "false"
	},
}

// azureAKSDefenderDisabled is CIS AKS 5.1.1 (Defender's runtime and image
// scanning profile); "enable service X", Low.
var azureAKSDefenderDisabled = Check{
	ID:          "azure-aks-defender-disabled",
	Title:       "AKS cluster has the Defender profile disabled",
	Description: "Microsoft Defender for Containers' security profile is off on the cluster, so its runtime threat detection and image vulnerability assessment do not cover it. A third-party scanner also satisfies the benchmark.",
	Remediation: "Enable the Defender profile (`az aks update --name CLUSTER --resource-group RG --enable-defender`) with the Defender for Containers plan on the subscription, or confirm a third-party image scanner covers the cluster.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["defender"] == "false" },
}

// azureAKSNoAzurePolicyAddon covers the admission side of CIS AKS 4.2: the
// Azure Policy add-on is AKS's managed admission controller for pod security.
var azureAKSNoAzurePolicyAddon = Check{
	ID:          "azure-aks-no-azure-policy-addon",
	Title:       "AKS cluster has no Azure Policy add-on",
	Description: "The Azure Policy add-on (managed Gatekeeper) is not enabled, so no Azure-managed admission policy can stop privileged, host-namespace or privilege-escalating pods from being created.",
	Remediation: "Enable the add-on (`az aks enable-addons --addons azure-policy --name CLUSTER --resource-group RG`) and assign the Kubernetes pod security baseline or restricted initiative.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["azure_policy_addon"] == "false" },
}

// azureAKSWorkloadIdentityDisabled is CIS AKS 5.2.1: without workload
// identity, pods that call Azure use the node's kubelet identity or a stored
// secret. Low: many clusters never call Azure from pods.
var azureAKSWorkloadIdentityDisabled = Check{
	ID:          "azure-aks-workload-identity-disabled",
	Title:       "AKS cluster does not use workload identity",
	Description: "Microsoft Entra Workload ID is off, so a pod that calls Azure APIs must use the node's managed identity — shared by every pod on the node — or a stored client secret.",
	Remediation: "Enable the OIDC issuer and workload identity (`az aks update --name CLUSTER --resource-group RG --enable-oidc-issuer --enable-workload-identity`) and federate a dedicated identity per workload.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["workload_identity"] == "false" },
}

// azureAKSSecretsNoKMS is CIS AKS 5.3.1. etcd is encrypted at rest with
// platform keys regardless; KMS adds a customer-controlled key, so Info.
var azureAKSSecretsNoKMS = Check{
	ID:          "azure-aks-secrets-no-kms",
	Title:       "AKS Secrets are not encrypted with a Key Vault key",
	Description: "KMS etcd encryption is off, so Kubernetes Secrets are protected only by the platform-managed encryption of the etcd disks, not by a key you control and can revoke.",
	Remediation: "Enable KMS with a Key Vault key: `az aks update --name CLUSTER --resource-group RG --enable-azure-keyvault-kms --azure-keyvault-kms-key-id KEY_ID`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["kms_secrets"] == "false" },
}

// azureAKSNoAutoUpgrade: Kubernetes minor and patch versions are only picked
// up by hand. The node-image channel counts as none: it refreshes node images
// but never moves the Kubernetes version. Not a CIS AKS control; the GKE
// benchmark's auto-upgrade twin.
var azureAKSNoAutoUpgrade = Check{
	ID:          "azure-aks-no-auto-upgrade",
	Title:       "AKS cluster does not upgrade Kubernetes automatically",
	Description: "The cluster's auto-upgrade channel is none or node-image (which only refreshes node images), so Kubernetes patch releases and their security fixes are applied only when someone upgrades by hand, and an unattended cluster drifts out of support.",
	Remediation: "Set a channel that upgrades Kubernetes, with a maintenance window: `az aks update --name CLUSTER --resource-group RG --auto-upgrade-channel patch` (or stable).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates: func(a asset.Asset) bool {
		c := a.Metadata["upgrade_channel"]
		return c == "none" || c == "node-image"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"upgrade_channel": a.Metadata["upgrade_channel"]}
	},
}

// azureAKSNodeOSUpgradeOff: node OS security patches are not applied by AKS.
var azureAKSNodeOSUpgradeOff = Check{
	ID:          "azure-aks-node-os-upgrade-off",
	Title:       "AKS node OS security updates are not managed",
	Description: "The node OS upgrade channel is None or Unmanaged, so AKS does not roll out node image or OS security updates; nodes run with whatever kernel and package CVEs they had at creation unless someone patches them.",
	Remediation: "Set the node OS upgrade channel to NodeImage or SecurityPatch: `az aks update --name CLUSTER --resource-group RG --node-os-upgrade-channel NodeImage`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   aksType,
	Violates: func(a asset.Asset) bool {
		c := a.Metadata["node_os_upgrade_channel"]
		return c == "None" || c == "Unmanaged"
	},
}

// azureResourceChecks are the CIS Azure Foundations v6 storage-service,
// network-service and Databricks checks and the CIS AKS cluster checks.
func azureResourceChecks() []Check {
	return []Check{
		azureStorageBlobSoftDeleteOff,
		azureStorageContainerSoftDeleteOff,
		azureStorageBlobVersioningOff,
		azureStorageFileSoftDeleteOff,
		azureStorageSMBLegacyVersion,
		azureStorageSMBWeakChannelEncryption,
		azureStorageNoDeleteLock,
		azureStorageNotGeoRedundant,
		azureWAFNoRequestBodyInspection,
		azureWAFNoBotProtection,
		azureVPNP2SNonEntraAuth,
		azureVNetFlowLogRetentionShort,
		azureNSGFlowLogRetentionShort,
		azureVNetFlowLogsNotAnalysed,
		azureNSGFlowLogsNotAnalysed,
		azureNetworkWatcherMissingRegion,
		azureNoBastionHost,
		azureDatabricksPublicNetworkAccess,
		azureDatabricksNoPrivateEndpoint,
		azureDatabricksPublicIP,
		azureDatabricksNoVNetInjection,
		azureDatabricksSubnetNoNSG,
		azureDatabricksNoCMK,
		azureAKSAPIUnrestricted,
		azureAKSAPIPublic,
		azureAKSNodePublicIP,
		azureAKSNoNetworkPolicy,
		azureAKSRBACDisabled,
		azureAKSNoEntraIntegration,
		azureAKSLocalAccountsEnabled,
		azureAKSNoAzureRBAC,
		azureAKSDefenderDisabled,
		azureAKSNoAzurePolicyAddon,
		azureAKSWorkloadIdentityDisabled,
		azureAKSSecretsNoKMS,
		azureAKSNoAutoUpgrade,
		azureAKSNodeOSUpgradeOff,
	}
}
