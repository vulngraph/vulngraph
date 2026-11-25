package checks

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const platformKeyDiskEncryption = "EncryptionAtRestWithPlatformKey"

// diskUsesPlatformKey reports a disk whose encryption type was read and is the
// Microsoft-managed platform key. An unread encryption type stays silent.
func diskUsesPlatformKey(a asset.Asset) bool {
	return a.Metadata["encryption_type"] == platformKeyDiskEncryption
}

var azureAttachedDiskNoCMK = Check{
	ID:          "azure-disk-attached-not-cmk",
	Title:       "Attached managed disk is not encrypted with a customer-managed key",
	Description: "This managed disk is attached to a virtual machine but encrypted only with a Microsoft-managed platform key, so you cannot rotate, revoke or audit the key that protects the VM's data at rest. Severity is medium: the data is still encrypted, but key control sits with the platform.",
	Remediation: "Create a disk encryption set backed by a Key Vault key, then switch the disk to it: portal Disks → Encryption → Key management: customer-managed key, or `az disk update --name DISK --resource-group RG --disk-encryption-set DES --encryption-type EncryptionAtRestWithCustomerKey` (deallocate the VM first).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_disk",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["vm_attached"] == "true" && diskUsesPlatformKey(a)
	},
}

var azureUnattachedDiskNoCMK = Check{
	ID:          "azure-disk-unattached-not-cmk",
	Title:       "Unattached managed disk is not encrypted with a customer-managed key",
	Description: "This managed disk is not attached to any virtual machine and is encrypted only with a Microsoft-managed platform key. Orphaned disks keep their data indefinitely and without a customer-managed key you cannot revoke access to it. Severity is medium: the data is still encrypted.",
	Remediation: "Create a disk encryption set backed by a Key Vault key and apply it: portal Disks → Encryption → Key management: customer-managed key, or `az disk update --name DISK --resource-group RG --disk-encryption-set DES --encryption-type EncryptionAtRestWithCustomerKey`. Delete the disk if it is no longer needed.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_disk",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["vm_attached"] == "false" && diskUsesPlatformKey(a)
	},
}

var azureWebAppClientCertNotRequired = Check{
	ID:          "azure-webapp-client-cert-not-required",
	Title:       "App Service does not require client certificates",
	Description: "This App Service accepts requests without a client certificate (certificates are disabled, optional or only allowed), so callers are not mutually authenticated at the TLS layer. Severity is medium.",
	Remediation: "Require certificates: portal App Service → Configuration → General settings → Client certificate mode: Require, or `az webapp update --name APP --resource-group RG --client-cert-enabled true --client-cert-mode Required`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_webapp",
	Violates:    func(a asset.Asset) bool { return a.Metadata["client_cert_required"] == "false" },
}

var azureNoLockAdminCustomRole = Check{
	ID:          "azure-no-custom-role-for-resource-locks",
	Title:       "No custom role can administer resource locks",
	Description: "The subscription has custom roles but none grants Microsoft.Authorization/locks actions, so lock management can only be delegated through broad built-in roles such as Owner. Severity is medium: it is a least-privilege gap, not an exposure.",
	Remediation: "Create a custom role limited to lock administration: portal Subscriptions → Access control (IAM) → Add custom role, or `az role definition create --role-definition '{\"Name\":\"Lock Administrator\",\"Actions\":[\"Microsoft.Authorization/locks/*\"],\"AssignableScopes\":[\"/subscriptions/SUB\"]}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_subscription",
	Violates: func(a asset.Asset) bool {
		roles, errRoles := strconv.Atoi(a.Metadata["custom_role_count"])
		lockRoles, errLock := strconv.Atoi(a.Metadata["custom_lock_admin_roles"])
		return errRoles == nil && errLock == nil && roles > 0 && lockRoles == 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"custom_roles": a.Metadata["custom_role_count"]}
	},
}
