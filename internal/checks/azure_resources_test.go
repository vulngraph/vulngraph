package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// The TestChecksNeverFireOnAbsentData contract for the Azure resource-service
// and AKS checks: the confirmed negative fires, the compliant state and absent
// data stay silent.
func TestAzureResourceChecksNeverFireOnAbsentData(t *testing.T) {
	tests := []struct {
		check     Check
		violating map[string]string
		compliant map[string]string
		unknown   map[string]string
	}{
		{azureStorageBlobSoftDeleteOff,
			map[string]string{"blob_soft_delete": "false"}, map[string]string{"blob_soft_delete": "true"}, map[string]string{"kind": "StorageV2"}},
		{azureStorageContainerSoftDeleteOff,
			map[string]string{"container_soft_delete": "false"}, map[string]string{"container_soft_delete": "true"}, map[string]string{}},
		{azureStorageBlobVersioningOff,
			map[string]string{"blob_versioning": "false", "hns_enabled": "false"},
			map[string]string{"blob_versioning": "false", "hns_enabled": "true"},
			map[string]string{"blob_versioning": "false"}},
		{azureStorageFileSoftDeleteOff,
			map[string]string{"file_shares": "true", "file_soft_delete": "false"},
			map[string]string{"file_shares": "false", "file_soft_delete": "false"},
			map[string]string{"file_soft_delete": "false"}},
		{azureStorageSMBLegacyVersion,
			map[string]string{"smb_shares": "true", "smb_versions": "SMB2.1;SMB3.0;SMB3.1.1"},
			map[string]string{"smb_shares": "false", "file_shares": "true", "smb_versions": "SMB2.1;SMB3.0;SMB3.1.1"},
			map[string]string{"smb_shares": "true"}},
		{azureStorageSMBWeakChannelEncryption,
			map[string]string{"smb_shares": "true", "smb_channel_encryption": "AES-128-GCM;AES-256-GCM"},
			map[string]string{"smb_shares": "true", "smb_channel_encryption": "AES-256-GCM"},
			map[string]string{"smb_channel_encryption": "AES-128-GCM"}},
		{azureStorageNoDeleteLock,
			map[string]string{"delete_lock": "false"}, map[string]string{"delete_lock": "true"}, map[string]string{}},
		{azureStorageNotGeoRedundant,
			map[string]string{"sku": "Standard_LRS"}, map[string]string{"sku": "Standard_RAGZRS"}, map[string]string{}},
		{azureWAFNoRequestBodyInspection,
			map[string]string{"attached": "true", "request_body_check": "false"},
			map[string]string{"attached": "true", "request_body_check": "true"},
			map[string]string{"attached": "true"}},
		{azureWAFNoBotProtection,
			map[string]string{"attached": "true", "bot_protection": "false"},
			map[string]string{"attached": "false", "bot_protection": "false"},
			map[string]string{"attached": "true"}},
		{azureVPNP2SNonEntraAuth,
			map[string]string{"p2s_enabled": "true", "p2s_auth_types": "AAD,Certificate"},
			map[string]string{"p2s_enabled": "true", "p2s_auth_types": "AAD"},
			map[string]string{"p2s_enabled": "true"}},
		{azureVNetFlowLogRetentionShort,
			map[string]string{"flow_log_enabled": "true", "flow_log_retention_days": "30"},
			map[string]string{"flow_log_enabled": "true", "flow_log_retention_days": "0"},
			map[string]string{"flow_log_enabled": "true"}},
		{azureNSGFlowLogRetentionShort,
			map[string]string{"flow_log_enabled": "true", "flow_log_retention_days": "7"},
			map[string]string{"flow_log_enabled": "true", "flow_log_retention_days": "365"},
			map[string]string{}},
		{azureVNetFlowLogsNotAnalysed,
			map[string]string{"flow_log_enabled": "false"},
			map[string]string{"flow_log_enabled": "true", "flow_log_traffic_analytics": "true"},
			map[string]string{"address_space": "10.0.0.0/16"}},
		{azureNSGFlowLogsNotAnalysed,
			map[string]string{"flow_log_enabled": "true", "flow_log_traffic_analytics": "false"},
			map[string]string{"flow_log_enabled": "false"},
			map[string]string{"ingress": "[]"}},
		{azureNetworkWatcherMissingRegion,
			map[string]string{"network_watcher_missing_regions": "westeurope"},
			map[string]string{"network_watcher_missing_regions": ""}, map[string]string{"owner_count": "2"}},
		{azureNoBastionHost,
			map[string]string{"vm_count": "4", "bastion_host_count": "0"},
			map[string]string{"vm_count": "0", "bastion_host_count": "0"},
			map[string]string{"vm_count": "4"}},
		{azureDatabricksPublicNetworkAccess,
			map[string]string{"public_network_access": "Enabled"}, map[string]string{"public_network_access": "Disabled"}, map[string]string{}},
		{azureDatabricksNoPrivateEndpoint,
			map[string]string{"private_endpoint_count": "0"}, map[string]string{"private_endpoint_count": "1"}, map[string]string{}},
		{azureDatabricksPublicIP,
			map[string]string{"no_public_ip": "false"}, map[string]string{"no_public_ip": "true"}, map[string]string{"sku": "premium"}},
		{azureDatabricksNoVNetInjection,
			map[string]string{"custom_vnet_id": ""}, map[string]string{"custom_vnet_id": "/subscriptions/s/vnet"}, map[string]string{}},
		{azureDatabricksSubnetNoNSG,
			map[string]string{"subnets_without_nsg": "priv"}, map[string]string{"subnets_without_nsg": ""},
			map[string]string{"custom_vnet_id": "/subscriptions/s/vnet"}},
		{azureDatabricksNoCMK,
			map[string]string{"cmk_encryption": ""}, map[string]string{"cmk_encryption": "managed_services"}, map[string]string{}},
		{azureAKSAPIUnrestricted,
			map[string]string{"api_public": "true", "authorized_ip_ranges": ""},
			map[string]string{"api_public": "true", "authorized_ip_ranges": "203.0.113.0/24"},
			map[string]string{"api_public": "true"}},
		{azureAKSAPIPublic,
			map[string]string{"api_public": "true", "authorized_ip_ranges": "203.0.113.0/24"},
			map[string]string{"api_public": "false", "authorized_ip_ranges": ""},
			map[string]string{"api_public": "true"}},
		{azureAKSNodePublicIP,
			map[string]string{"node_pools_public_ip": "web"}, map[string]string{"node_pools_public_ip": ""}, map[string]string{}},
		{azureAKSNoNetworkPolicy,
			map[string]string{"network_policy": "none"}, map[string]string{"network_policy": "cilium"}, map[string]string{}},
		{azureAKSRBACDisabled,
			map[string]string{"rbac_enabled": "false"}, map[string]string{"rbac_enabled": "true"}, map[string]string{"entra_integration": "true"}},
		{azureAKSNoEntraIntegration,
			map[string]string{"entra_integration": "false"}, map[string]string{"entra_integration": "true"}, map[string]string{}},
		{azureAKSLocalAccountsEnabled,
			map[string]string{"entra_integration": "true", "local_accounts_disabled": "false"},
			map[string]string{"entra_integration": "false", "local_accounts_disabled": "false"},
			map[string]string{"entra_integration": "true"}},
		{azureAKSNoAzureRBAC,
			map[string]string{"entra_integration": "true", "azure_rbac": "false"},
			map[string]string{"entra_integration": "true", "azure_rbac": "true"},
			map[string]string{"azure_rbac": "false"}},
		{azureAKSDefenderDisabled,
			map[string]string{"defender": "false"}, map[string]string{"defender": "true"}, map[string]string{}},
		{azureAKSNoAzurePolicyAddon,
			map[string]string{"azure_policy_addon": "false"}, map[string]string{"azure_policy_addon": "true"}, map[string]string{}},
		{azureAKSWorkloadIdentityDisabled,
			map[string]string{"workload_identity": "false"}, map[string]string{"workload_identity": "true"}, map[string]string{}},
		{azureAKSSecretsNoKMS,
			map[string]string{"kms_secrets": "false"}, map[string]string{"kms_secrets": "true"}, map[string]string{}},
		{azureAKSNoAutoUpgrade,
			map[string]string{"upgrade_channel": "none"}, map[string]string{"upgrade_channel": "stable"}, map[string]string{}},
		{azureAKSNodeOSUpgradeOff,
			map[string]string{"node_os_upgrade_channel": "Unmanaged"}, map[string]string{"node_os_upgrade_channel": "NodeImage"}, map[string]string{}},
	}
	require.Len(t, tests, len(azureResourceChecks()), "every Azure resource check needs a row")
	for _, tt := range tests {
		t.Run(tt.check.ID, func(t *testing.T) {
			build := func(md map[string]string) asset.Asset {
				return asset.Asset{ID: "res-1", Name: "res", Type: tt.check.AssetType, Provider: tt.check.Provider, Metadata: md}
			}
			require.True(t, tt.check.Violates(build(tt.violating)), "the confirmed negative must fire")
			require.False(t, tt.check.Violates(build(tt.compliant)), "the compliant state must not fire")
			require.False(t, tt.check.Violates(build(tt.unknown)), "absent data is not a violation")
			require.False(t, tt.check.Violates(build(nil)), "a nil metadata map is absent data too")
		})
	}
}

// A check silent only because its keys are absent must not read as evaluated:
// the lifecycle would close its finding as fixed.
func TestAzureResourceChecks_AbsentKeysNotEvaluable(t *testing.T) {
	reg := Default()
	tests := []struct {
		id string
		md map[string]string
	}{
		{"azure-storage-smb-legacy-version", map[string]string{"smb_shares": "true"}},
		{"azure-vnet-flow-log-retention-short", map[string]string{"flow_log_enabled": "true"}},
		{"azure-no-bastion-host", map[string]string{"vm_count": "3"}},
		{"azure-aks-api-unrestricted", map[string]string{"api_public": "true"}},
		{"azure-vpn-p2s-non-entra-auth", map[string]string{"p2s_enabled": "true"}},
		{"azure-storage-no-delete-lock", map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			c, ok := reg.ByID(tt.id)
			require.True(t, ok)
			a := asset.Asset{ID: "r", Name: "res", Type: c.AssetType, Provider: c.Provider, Metadata: tt.md}
			require.False(t, c.Violates(a))
			require.False(t, c.Evaluable(a))
		})
	}
}

// One root cause, one finding: the AKS public-endpoint pair and the
// Entra/local-account pair each split a single condition.
func TestAzureAKSChecks_OneFindingPerRootCause(t *testing.T) {
	aks := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "azure_aks_cluster", Provider: asset.ProviderAzure, Metadata: md}
	}
	open := aks(map[string]string{"api_public": "true", "authorized_ip_ranges": ""})
	require.True(t, azureAKSAPIUnrestricted.Violates(open))
	require.False(t, azureAKSAPIPublic.Violates(open))
	world := aks(map[string]string{"api_public": "true", "authorized_ip_ranges": "0.0.0.0/0,10.0.0.0/8"})
	require.True(t, azureAKSAPIUnrestricted.Violates(world), "0.0.0.0/0 restricts nothing")
	require.False(t, azureAKSAPIPublic.Violates(world))
	private := aks(map[string]string{"api_public": "false", "authorized_ip_ranges": ""})
	require.False(t, azureAKSAPIUnrestricted.Violates(private))
	require.False(t, azureAKSAPIPublic.Violates(private))

	noEntra := aks(map[string]string{"entra_integration": "false", "local_accounts_disabled": "false", "azure_rbac": "false"})
	require.True(t, azureAKSNoEntraIntegration.Violates(noEntra))
	require.False(t, azureAKSLocalAccountsEnabled.Violates(noEntra), "local accounts are the only way in without Entra")
	require.False(t, azureAKSNoAzureRBAC.Violates(noEntra), "Azure RBAC needs Entra; the Entra finding covers it")
}

// The node-image channel refreshes node images only; it never upgrades
// Kubernetes, so it is no auto-upgrade for the cluster version.
func TestAzureAKSNoAutoUpgrade_Channels(t *testing.T) {
	for ch, fires := range map[string]bool{"none": true, "node-image": true, "patch": false, "stable": false, "rapid": false} {
		a := asset.Asset{Type: "azure_aks_cluster", Provider: asset.ProviderAzure, Metadata: map[string]string{"upgrade_channel": ch}}
		require.Equal(t, fires, azureAKSNoAutoUpgrade.Violates(a), ch)
	}
}

// Settings a legacy GPv1 account cannot have are not reported on it, and SMB
// settings are not reported on an account whose only shares are NFS.
func TestAzureStorageChecks_SkipWhatCannotComply(t *testing.T) {
	sa := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "azure_storage_account", Provider: asset.ProviderAzure, Metadata: md}
	}
	gpv1 := sa(map[string]string{"kind": "Storage", "container_soft_delete": "false", "blob_versioning": "false", "hns_enabled": "false"})
	require.False(t, azureStorageContainerSoftDeleteOff.Violates(gpv1))
	require.False(t, azureStorageBlobVersioningOff.Violates(gpv1))
	gpv2 := sa(map[string]string{"kind": "StorageV2", "container_soft_delete": "false", "blob_versioning": "false", "hns_enabled": "false"})
	require.True(t, azureStorageContainerSoftDeleteOff.Violates(gpv2))
	require.True(t, azureStorageBlobVersioningOff.Violates(gpv2))

	nfsOnly := sa(map[string]string{"file_shares": "true", "smb_shares": "false", "smb_versions": "SMB2.1;SMB3.0;SMB3.1.1",
		"smb_channel_encryption": "AES-128-CCM;AES-128-GCM;AES-256-GCM", "file_soft_delete": "false"})
	require.False(t, azureStorageSMBLegacyVersion.Violates(nfsOnly))
	require.False(t, azureStorageSMBWeakChannelEncryption.Violates(nfsOnly))
	require.True(t, azureStorageFileSoftDeleteOff.Violates(nfsOnly), "share soft delete covers NFS shares too")
}

func TestOnlyListed(t *testing.T) {
	require.True(t, onlyListed("SMB3.1.1", "SMB3.1.1"))
	require.True(t, onlyListed(" smb3.1.1 ;", "SMB3.1.1"))
	require.False(t, onlyListed("SMB3.0;SMB3.1.1", "SMB3.1.1"))
	require.False(t, onlyListed("", "SMB3.1.1"), "an empty list names nothing")
}

func TestStorageKeyUntrackedIsStale(t *testing.T) {
	a := asset.Asset{Type: "azure_storage_account", Provider: asset.ProviderAzure, Metadata: map[string]string{
		"allow_shared_key_access": "true", "key1_created": storageKeyUntracked, "key2_created": "2999-01-01T00:00:00Z"}}
	require.True(t, azureStorageKeyNotRotated.Violates(a), "a key never regenerated since tracking began is older than 90 days")
	a.Metadata["allow_shared_key_access"] = "false"
	require.False(t, azureStorageKeyNotRotated.Violates(a))
}
