package checks

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CIS Azure Foundations v6 storage controls read from the blob and file
// service properties (9.1.x, 9.2.x), the subscription's management locks
// (9.3.9) and the account SKU (9.3.11). Recovery and resilience settings:
// they decide how bad a mistake or a ransomware run gets, not whether an
// attacker gets in, so they grade Low or Info.

// azureStorageBlobSoftDeleteOff is CIS 9.2.1.
var azureStorageBlobSoftDeleteOff = Check{
	ID:          "azure-storage-blob-soft-delete-off",
	Title:       "Azure storage blob soft delete is disabled",
	Description: "Blob soft delete is off, so a deleted or overwritten blob is gone immediately — by mistake, by a script, or by anyone holding a key or SAS with delete rights.",
	Remediation: "Enable blob soft delete with a retention period (portal: storage account → Data protection → Enable soft delete for blobs; CLI: `az storage account blob-service-properties update --account-name ACCT --resource-group RG --enable-delete-retention true --delete-retention-days 7`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["blob_soft_delete"] == "false" },
}

// storageKindGPv1 is the legacy general-purpose v1 account kind. Azure offers
// neither container soft delete nor blob versioning on it, so those checks
// skip it: the fix is the upgrade to GPv2, not the setting.
const storageKindGPv1 = "Storage"

// azureStorageContainerSoftDeleteOff is CIS 9.2.2; GPv1 accounts cannot comply.
var azureStorageContainerSoftDeleteOff = Check{
	ID:          "azure-storage-container-soft-delete-off",
	Title:       "Azure storage container soft delete is disabled",
	Description: "Container soft delete is off, so deleting a container permanently removes every blob in it at once.",
	Remediation: "Enable container soft delete (portal: storage account → Data protection → Enable soft delete for containers; CLI: `az storage account blob-service-properties update --account-name ACCT --resource-group RG --enable-container-delete-retention true --container-delete-retention-days 7`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["container_soft_delete"] == "false" && a.Metadata["kind"] != storageKindGPv1
	},
}

// azureStorageBlobVersioningOff is CIS 9.2.3 (Level 2). Azure does not support
// versioning on hierarchical-namespace (Data Lake Gen2) or GPv1 accounts, so
// those cannot comply and do not fire.
var azureStorageBlobVersioningOff = Check{
	ID:          "azure-storage-blob-versioning-off",
	Title:       "Azure storage blob versioning is disabled",
	Description: "Blob versioning is off, so an overwritten blob keeps no previous version to restore.",
	Remediation: "Enable versioning (portal: storage account → Data protection → Enable versioning for blobs; CLI: `az storage account blob-service-properties update --account-name ACCT --resource-group RG --enable-versioning true`), with a lifecycle rule to expire old versions.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["blob_versioning"] == "false" && a.Metadata["hns_enabled"] == "false" &&
			a.Metadata["kind"] != storageKindGPv1
	},
}

// azureStorageFileSoftDeleteOff is CIS 9.1.1, on accounts that hold shares.
var azureStorageFileSoftDeleteOff = Check{
	ID:          "azure-storage-file-soft-delete-off",
	Title:       "Azure file share soft delete is disabled",
	Description: "The account holds file shares and share soft delete is off, so a deleted share and all its files are unrecoverable.",
	Remediation: "Enable soft delete for file shares (portal: storage account → Data protection → Enable soft delete for file shares; CLI: `az storage account file-service-properties update --account-name ACCT --resource-group RG --enable-delete-retention true --delete-retention-days 7`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["file_shares"] == "true" && a.Metadata["file_soft_delete"] == "false"
	},
}

// azureStorageSMBLegacyVersion is CIS 9.1.2: SMB 3.1.1 only. SMB 2.1 has no
// encryption and SMB 3.0 lacks 3.1.1's pre-authentication integrity.
var azureStorageSMBLegacyVersion = Check{
	ID:          "azure-storage-smb-legacy-version",
	Title:       "Azure file shares accept SMB versions older than 3.1.1",
	Description: "The account holds SMB file shares and its SMB settings accept SMB 2.1 or 3.0 (an unset list accepts every version). Older dialects lack SMB 3.1.1's pre-authentication integrity protection against downgrade and man-in-the-middle attacks.",
	Remediation: "Limit SMB to 3.1.1 (portal: storage account → File shares → Security: Maximum security; CLI: `az storage account file-service-properties update --account-name ACCT --resource-group RG --versions SMB3.1.1`) once clients support it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["smb_versions"]
		return ok && a.Metadata["smb_shares"] == "true" && !onlyListed(v, "SMB3.1.1")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"smb_versions": a.Metadata["smb_versions"]}
	},
}

// azureStorageSMBWeakChannelEncryption is CIS 9.1.3: AES-256-GCM only.
var azureStorageSMBWeakChannelEncryption = Check{
	ID:          "azure-storage-smb-weak-channel-encryption",
	Title:       "Azure file shares allow SMB channel encryption below AES-256-GCM",
	Description: "The account holds SMB file shares and accepts AES-128-CCM or AES-128-GCM for SMB channel encryption (an unset list accepts all three ciphers), not only AES-256-GCM.",
	Remediation: "Limit SMB channel encryption to AES-256-GCM: `az storage account file-service-properties update --account-name ACCT --resource-group RG --channel-encryption AES-256-GCM`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["smb_channel_encryption"]
		return ok && a.Metadata["smb_shares"] == "true" && !onlyListed(v, "AES-256-GCM")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"smb_channel_encryption": a.Metadata["smb_channel_encryption"]}
	},
}

// onlyListed reports whether a ';'-separated Azure setting list names want
// and nothing else.
func onlyListed(list, want string) bool {
	seen := false
	for _, v := range strings.Split(list, ";") {
		switch v = strings.TrimSpace(v); {
		case v == "":
		case strings.EqualFold(v, want):
			seen = true
		default:
			return false
		}
	}
	return seen
}

// azureStorageNoDeleteLock is CIS 9.3.9. A lock is an organisational guard
// against accidental deletion, so Info.
var azureStorageNoDeleteLock = Check{
	ID:          "azure-storage-no-delete-lock",
	Title:       "Azure storage account has no delete lock",
	Description: "No CanNotDelete or ReadOnly lock sits on the storage account, its resource group or its subscription, so anyone with delete rights on the account can remove it and every container, share, queue and table in it in one call.",
	Remediation: "Add a delete lock (portal: storage account → Locks → Add, type Delete; CLI: `az lock create --name no-delete --lock-type CanNotDelete --resource-group RG --resource ACCT --resource-type Microsoft.Storage/storageAccounts`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["delete_lock"] == "false" },
}

// azureStorageNotGeoRedundant is CIS 9.3.11. The benchmark scopes it to
// critical accounts, which no API marks, so it fires on every Standard LRS/ZRS
// account at Info. Premium accounts offer no geo-redundant SKU and cannot
// comply, so they are exempt.
var azureStorageNotGeoRedundant = Check{
	ID:          "azure-storage-not-geo-redundant",
	Title:       "Azure storage account is not geo-redundant",
	Description: "The account replicates only within one region (LRS or ZRS), so a regional outage or disaster makes its data unavailable or lost. CIS asks for geo-redundant storage on critical accounts; whether this one is critical is the owner's call.",
	Remediation: "For a critical account, change redundancy to GRS, RA-GRS, GZRS or RA-GZRS (portal: storage account → Redundancy; CLI: `az storage account update --name ACCT --resource-group RG --sku Standard_GZRS`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_storage_account",
	Violates: func(a asset.Asset) bool {
		sku := a.Metadata["sku"]
		return sku == "Standard_LRS" || sku == "Standard_ZRS"
	},
	EvidenceFor: func(a asset.Asset) map[string]string { return map[string]string{"sku": a.Metadata["sku"]} },
}
