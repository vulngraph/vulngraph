package checks

// azure_keyvault.go — Key Vault posture (CIS Azure Foundations 8.3.1–8.3.9,
// 8.3.11, 6.1.1.4), one finding per vault on the azure_key_vault asset
// (internal/collect/azure/keyvault.go). Key and secret findings carry the
// names of the offending items as evidence rather than one finding per item:
// the vault is the unit an owner manages.

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const keyVaultType = "azure_key_vault"

func azureKeyVaultChecks() []Check {
	return []Check{
		azureKeyVaultNoPurgeProtection,
		azureKeyVaultPublicNetworkAccess,
		azureKeyVaultNoPrivateEndpoint,
		azureKeyVaultAccessPolicyModel,
		azureKeyVaultRBACKeyNoExpiry,
		azureKeyVaultPolicyKeyNoExpiry,
		azureKeyVaultRBACSecretNoExpiry,
		azureKeyVaultPolicySecretNoExpiry,
		azureKeyVaultKeyNoRotation,
		azureKeyVaultCertValidityLong,
		azureKeyVaultAuditLoggingOff,
	}
}

// countAbove reports whether a count key was observed and is positive.
func countAbove(a asset.Asset, key string) bool {
	n, err := strconv.Atoi(a.Metadata[key])
	return err == nil && n > 0
}

// azureKeyVaultNoPurgeProtection is CIS 8.3.5. Medium: without purge
// protection one compromised administrator can permanently destroy the keys
// that encrypt other data — unrecoverable data loss, not just exposure.
var azureKeyVaultNoPurgeProtection = Check{
	ID:          "azure-keyvault-no-purge-protection",
	Title:       "Key Vault purge protection is off",
	Description: "The vault does not have purge protection (or soft delete) enabled, so a deleted vault, key or secret can be purged immediately and permanently. Data encrypted with a purged customer-managed key is unrecoverable.",
	Remediation: "Key Vault → Properties → Purge protection: Enable (irreversible). CLI: `az keyvault update --name <vault> --enable-purge-protection true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["purge_protection"] == "false" || a.Metadata["soft_delete"] == "false"
	},
}

// azureKeyVaultPublicNetworkAccess is CIS 8.3.7. Graded: accepting traffic
// from any network is Medium; public access narrowed by the vault firewall
// (default action Deny) is Low.
var azureKeyVaultPublicNetworkAccess = Check{
	ID:          "azure-keyvault-public-network-access",
	Title:       "Key Vault accepts public network traffic",
	Description: "The vault's public network access is enabled, so its data plane is reachable from the internet (gated by Entra authentication and, if set, the vault firewall). CIS asks for public access disabled with private endpoints.",
	Remediation: "Key Vault → Networking → Firewalls and virtual networks: \"Disable public access\" and connect through a private endpoint. CLI: `az keyvault update --name <vault> --public-network-access Disabled`.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_network_access"] == "Enabled" },
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["network_default_action"] == "Deny" {
			return finding.SeverityLow
		}
		return finding.SeverityMedium
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["network_default_action"] == "Deny" {
			return "Key Vault public access is enabled, restricted by its firewall"
		}
		return "Key Vault accepts traffic from all networks"
	},
}

var azureKeyVaultNoPrivateEndpoint = Check{
	ID:          "azure-keyvault-no-private-endpoint",
	Title:       "Key Vault has no private endpoint",
	Description: "The vault has no approved private endpoint connection (CIS 8.3.8), so clients reach it over its public endpoint rather than a private address in a virtual network.",
	Remediation: "Key Vault → Networking → Private endpoint connections → Create, in the virtual network of the workloads that use the vault, then disable public access.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["private_endpoint_count"] == "0" },
}

var azureKeyVaultAccessPolicyModel = Check{
	ID:          "azure-keyvault-access-policy-model",
	Title:       "Key Vault uses access policies instead of Azure RBAC",
	Description: "The vault authorizes data-plane access with vault access policies (CIS 8.3.6). Access policies are not visible to Azure RBAC reviews, PIM or deny assignments, and anyone with Contributor on the vault can grant themselves data access.",
	Remediation: "Grant the equivalent Key Vault built-in roles, then Key Vault → Access configuration → Permission model: Azure role-based access control. CLI: `az keyvault update --name <vault> --enable-rbac-authorization true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["rbac_authorization"] == "false" },
}

// Key and secret expiry are split by the vault's permission model because CIS
// splits them (8.3.1/8.3.3 RBAC vaults, 8.3.2/8.3.4 access-policy vaults); a
// vault has one model, so it still gets at most one key and one secret finding.
const (
	keyExpiryRemediation    = "Set an expiration date on each listed key (Key Vault → Keys → key → current version → Expiration date), or add a rotation policy that sets one. CLI: `az keyvault key set-attributes --vault-name <vault> --name <key> --expires <date>`."
	secretExpiryRemediation = "Set an expiration date on each listed secret (Key Vault → Secrets → secret → current version → Expiration date) and rotate it before then. CLI: `az keyvault secret set-attributes --vault-name <vault> --name <secret> --expires <date>`."
)

func keyExpiryEvidence(a asset.Asset) map[string]string {
	return map[string]string{"count": a.Metadata["keys_without_expiry_count"], "keys": a.Metadata["keys_without_expiry"]}
}

func secretExpiryEvidence(a asset.Asset) map[string]string {
	return map[string]string{"count": a.Metadata["secrets_without_expiry_count"], "secrets": a.Metadata["secrets_without_expiry"]}
}

var azureKeyVaultRBACKeyNoExpiry = Check{
	ID:          "azure-keyvault-rbac-key-no-expiry",
	Title:       "Key Vault keys have no expiration date (RBAC vault)",
	Description: "Enabled keys in this RBAC-authorized vault have no expiration date set (CIS 8.3.1), so nothing forces them to be rotated or retired.",
	Remediation: keyExpiryRemediation,
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["rbac_authorization"] == "true" && countAbove(a, "keys_without_expiry_count")
	},
	EvidenceFor: keyExpiryEvidence,
}

var azureKeyVaultPolicyKeyNoExpiry = Check{
	ID:          "azure-keyvault-policy-key-no-expiry",
	Title:       "Key Vault keys have no expiration date (access-policy vault)",
	Description: "Enabled keys in this access-policy vault have no expiration date set (CIS 8.3.2), so nothing forces them to be rotated or retired.",
	Remediation: keyExpiryRemediation,
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["rbac_authorization"] == "false" && countAbove(a, "keys_without_expiry_count")
	},
	EvidenceFor: keyExpiryEvidence,
}

var azureKeyVaultRBACSecretNoExpiry = Check{
	ID:          "azure-keyvault-rbac-secret-no-expiry",
	Title:       "Key Vault secrets have no expiration date (RBAC vault)",
	Description: "Enabled secrets in this RBAC-authorized vault have no expiration date set (CIS 8.3.3), so a leaked secret stays valid until someone remembers to rotate it.",
	Remediation: secretExpiryRemediation,
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["rbac_authorization"] == "true" && countAbove(a, "secrets_without_expiry_count")
	},
	EvidenceFor: secretExpiryEvidence,
}

var azureKeyVaultPolicySecretNoExpiry = Check{
	ID:          "azure-keyvault-policy-secret-no-expiry",
	Title:       "Key Vault secrets have no expiration date (access-policy vault)",
	Description: "Enabled secrets in this access-policy vault have no expiration date set (CIS 8.3.4), so a leaked secret stays valid until someone remembers to rotate it.",
	Remediation: secretExpiryRemediation,
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["rbac_authorization"] == "false" && countAbove(a, "secrets_without_expiry_count")
	},
	EvidenceFor: secretExpiryEvidence,
}

var azureKeyVaultKeyNoRotation = Check{
	ID:          "azure-keyvault-key-no-rotation",
	Title:       "Key Vault keys do not rotate automatically",
	Description: "Enabled keys in the vault have no rotation policy with a Rotate action (CIS 8.3.9), so new key versions depend on someone rotating by hand.",
	Remediation: "Key Vault → Keys → key → Rotation policy: enable auto-rotation (e.g. rotate 90 days after creation). CLI: `az keyvault key rotation-policy update --vault-name <vault> --name <key> --value policy.json`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates:    func(a asset.Asset) bool { return countAbove(a, "keys_without_rotation_count") },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"count": a.Metadata["keys_without_rotation_count"], "keys": a.Metadata["keys_without_rotation"]}
	},
}

var azureKeyVaultCertValidityLong = Check{
	ID:          "azure-keyvault-cert-validity-long",
	Title:       "Key Vault certificates are valid for more than 12 months",
	Description: "Current certificates in the vault were issued with a validity longer than 12 months (CIS 8.3.11), read from each certificate's not-before and expiry dates on the data-plane certificate list. Long-lived certificates stay usable long after a key compromise and are outside the public-CA maximum.",
	Remediation: "Set the certificate policy's validity to 12 months or less (Key Vault → Certificates → certificate → Issuance policy → Validity period) and renew. CLI: `az keyvault certificate set-attributes --vault-name <vault> --name <cert> --policy @policy.json`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates:    func(a asset.Asset) bool { return countAbove(a, "certs_validity_over_12_months_count") },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"count": a.Metadata["certs_validity_over_12_months_count"], "certificates": a.Metadata["certs_validity_over_12_months"]}
	},
}

var azureKeyVaultAuditLoggingOff = Check{
	ID:          "azure-keyvault-audit-logging-off",
	Title:       "Key Vault audit logging is not exported",
	Description: "No diagnostic setting exports the vault's AuditEvent log (CIS 6.1.1.4), so reads of keys and secrets — the first thing to check after a credential leak — are not recorded.",
	Remediation: "Key Vault → Diagnostic settings → Add: the audit category group (AuditEvent) to a Log Analytics workspace or storage account. CLI: `az monitor diagnostic-settings create --resource <vault-id> --logs '[{\"categoryGroup\":\"audit\",\"enabled\":true}]' --workspace <id>`.",
	Type:        "logging",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   keyVaultType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["audit_logging_enabled"] == "false" },
}
