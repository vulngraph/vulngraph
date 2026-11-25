package checks

import (
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CIS Azure Foundations v6 storage-account controls (9.3.x) read from the
// storage account list response. Values the collector writes for an unset
// ARM field are that field's documented interpretation (see storagePosture in
// internal/collect/azure); anything ambiguous is absent and never fires.

// azureStorageDefaultNetworkAllow is CIS 9.3.2.3 — and the stronger half of
// 9.3.2.2: public network access left on with no firewall restriction means
// the account endpoint answers the whole internet. Still credential-gated, so
// Medium rather than High.
var azureStorageDefaultNetworkAllow = Check{
	ID:          "azure-storage-default-network-allow",
	Title:       "Azure storage account accepts traffic from all networks",
	Description: "Public network access is enabled and the storage firewall's default action is Allow, so the account's endpoints accept connections from any internet address. Access still needs a key, SAS or Entra token, but any leaked credential is usable from anywhere.",
	Remediation: "Set the firewall default action to Deny and allow only the required VNets and IP ranges, or disable public network access and use private endpoints.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_network_access"] == "Enabled" && a.Metadata["network_default_action"] == "Allow"
	},
}

// azureStoragePublicNetworkAccess is the remaining half of CIS 9.3.2.2: the
// public endpoint is on but firewalled to selected networks. It steps aside
// when the firewall default is Allow, which azure-storage-default-network-allow
// already reports as the worse condition — one finding per account.
var azureStoragePublicNetworkAccess = Check{
	ID:          "azure-storage-public-network-access",
	Title:       "Azure storage account public endpoint enabled (selected networks)",
	Description: "Public network access is enabled on the storage account. The firewall restricts it to selected networks, but the endpoint is still on the internet rather than reachable only through private endpoints.",
	Remediation: "Set Public network access to Disabled and reach the account through private endpoints.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_network_access"] == "Enabled" && a.Metadata["network_default_action"] == "Deny"
	},
}

// azureStorageMinTLS is CIS 9.3.6. Low: since 3 February 2026 Azure Storage
// refuses TLS 1.0/1.1 on every account whatever this setting says, so the
// setting is now a statement of intent rather than an open downgrade path.
var azureStorageMinTLS = Check{
	ID:          "azure-storage-min-tls-below-12",
	Title:       "Azure storage account minimum TLS version is below 1.2",
	Description: "The account's minimum TLS version is TLS 1.0 or 1.1 (an unset value is interpreted as TLS 1.0). Azure Storage has refused TLS below 1.2 platform-wide since February 2026, so the remaining risk is configuration drift, not live downgrade.",
	Remediation: "Set the minimum TLS version to TLS1_2: `az storage account update --name ACCT --resource-group RG --min-tls-version TLS1_2`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		v := a.Metadata["minimum_tls_version"]
		return v == "TLS1_0" || v == "TLS1_1"
	},
}

// azureStorageSharedKeyAccess is CIS 9.3.1.3. Shared Key is allowed by default
// on nearly every account, so this is Low hygiene; the concrete credential
// risk is a stale key, graded by azure-storage-key-not-rotated.
var azureStorageSharedKeyAccess = Check{
	ID:          "azure-storage-shared-key-access",
	Title:       "Azure storage account allows Shared Key authorization",
	Description: "The account accepts requests signed with its account access keys (and SAS tokens derived from them). Account keys grant full data-plane access, never expire and are not tied to an identity.",
	Remediation: "Move clients to Entra ID authorization, then set AllowSharedKeyAccess=false.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["allow_shared_key_access"] == "true" },
}

// storageKeyMaxAge is the CIS 9.3.1.2 rotation period.
const storageKeyMaxAge = 90 * 24 * time.Hour

// azureStorageKeyNotRotated is CIS 9.3.1.2. Steps aside when Shared Key
// authorization is disabled: a key that cannot authenticate is not a
// credential.
var azureStorageKeyNotRotated = Check{
	ID:          "azure-storage-key-not-rotated",
	Title:       "Azure storage account key not rotated in 90 days",
	Description: "An account access key was created more than 90 days ago (or its creation time is still unset, which Azure only fills in once the key is rotated) and Shared Key authorization is still enabled. Account keys grant full data-plane access, so a long-lived key widens the window in which a leaked copy stays usable.",
	Remediation: "Move clients to the other key, then regenerate this one (portal: storage account → Access keys → Rotate key; CLI: `az storage account keys renew --account-name ACCT --resource-group RG --key primary`), or disable Shared Key authorization.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["allow_shared_key_access"] != "true" {
			return false
		}
		return storageKeyStale(a.Metadata["key1_created"]) || storageKeyStale(a.Metadata["key2_created"])
	},
	// The key timestamps are RFC 3339 values the predicate's literals cannot
	// probe; an old one lets Evaluable see that an absent key could have fired.
	TableProbes: []string{"2000-01-01T00:00:00Z"},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"key1_created": a.Metadata["key1_created"], "key2_created": a.Metadata["key2_created"]}
	},
}

// storageKeyUntracked is the collector's value for a key whose creation time
// ARM reports as "not yet set": rotating sets it, so the key has gone
// unrotated since key-creation tracking began, years before any 90-day window.
const storageKeyUntracked = "untracked"

// storageKeyStale reports whether a key-creation time is older than
// storageKeyMaxAge. An untracked key is stale; unparseable or missing is not:
// it is unknown.
func storageKeyStale(created string) bool {
	if created == storageKeyUntracked {
		return true
	}
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return false
	}
	return time.Since(t) > storageKeyMaxAge
}

// azureStorageNoKeyExpiryPolicy is CIS 9.3.1.1. Steps aside when Shared Key
// is disabled, as azure-storage-key-not-rotated does.
var azureStorageNoKeyExpiryPolicy = Check{
	ID:          "azure-storage-no-key-expiry-policy",
	Title:       "Azure storage account has no key expiration policy",
	Description: "No key expiration period is set, so Azure raises no reminder when account access keys are due for rotation.",
	Remediation: "Set a key expiration period (90 days): `az storage account update --name ACCT --resource-group RG --key-exp-days 90`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["allow_shared_key_access"] == "true" && observedNone(a, "key_expiration_days")
	},
}

// azureStorageCrossTenantReplication is CIS 9.3.7. Exfiltration through it
// still needs someone able to write an object replication policy, so Low.
var azureStorageCrossTenantReplication = Check{
	ID:          "azure-storage-cross-tenant-replication",
	Title:       "Azure storage account allows cross-tenant object replication",
	Description: "AllowCrossTenantReplication is true (or unset on an account created before 15 December 2023, which Azure treats as true), so an object replication policy can copy this account's blobs to a storage account in another Entra tenant.",
	Remediation: "Unless replication to another tenant is required, disallow it (portal: storage account → Object replication → Advanced settings → uncheck Allow cross-tenant replication; CLI: `az storage account update --name ACCT --resource-group RG --allow-cross-tenant-replication false`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["allow_cross_tenant_replication"] == "true" },
}

// azureStorageNoPrivateEndpoint is CIS 9.3.2.1. Private endpoints are an
// architecture choice most accounts never make, so Info.
var azureStorageNoPrivateEndpoint = Check{
	ID:          "azure-storage-no-private-endpoint",
	Title:       "Azure storage account has no private endpoint",
	Description: "The storage account has no approved private endpoint connection, so every client reaches it over its public endpoint.",
	Remediation: "Create a private endpoint for the account in the VNet its clients use, then disable public network access.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["private_endpoint_count"] == "0" },
}

// azureStorageTrustedServicesBypassOff is CIS 9.3.5. Only meaningful when the
// firewall restricts anything (default action Deny); an availability setting,
// so Info.
var azureStorageTrustedServicesBypassOff = Check{
	ID:          "azure-storage-trusted-services-bypass-off",
	Title:       "Azure storage firewall blocks trusted Azure services",
	Description: "The storage firewall denies by default and does not let trusted Microsoft services (Backup, Monitor, Defender, Event Grid) through, which breaks diagnostics and backup delivery into the account.",
	Remediation: "Add AzureServices to the firewall bypass list: `az storage account update --name ACCT --resource-group RG --bypass AzureServices`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		bypass, ok := a.Metadata["network_bypass"]
		return ok && a.Metadata["network_default_action"] == "Deny" && !strings.Contains(bypass, "AzureServices")
	},
}

// azureStoragePortalNotEntraAuth is CIS 9.3.3.1: a portal default, Info.
var azureStoragePortalNotEntraAuth = Check{
	ID:          "azure-storage-portal-not-entra-auth",
	Title:       "Azure storage account does not default to Entra authorization",
	Description: "DefaultToOAuthAuthentication is off, so the Azure portal reaches blob, queue and table data with the account key rather than the signed-in user's Entra identity.",
	Remediation: "Enable 'Default to Microsoft Entra authorization in the Azure portal' on the account.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["default_to_oauth"] == "false" },
}
