package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v8"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAKSMetadata(t *testing.T) {
	build := func(p *armcontainerservice.ManagedClusterProperties) map[string]string {
		return aksMetadata(&armcontainerservice.ManagedCluster{Properties: p})
	}
	require.Empty(t, build(nil), "no properties block records nothing")

	t.Run("documented defaults for an unset cluster", func(t *testing.T) {
		md := build(&armcontainerservice.ManagedClusterProperties{})
		require.NotContains(t, md, "rbac_enabled", "ARM always returns enableRBAC; unset is unknown")
		require.Equal(t, "false", md["entra_integration"])
		require.Equal(t, "false", md["azure_rbac"])
		require.Equal(t, "false", md["local_accounts_disabled"])
		require.Equal(t, "true", md["api_public"])
		require.Equal(t, "", md["authorized_ip_ranges"])
		require.Equal(t, "none", md["network_policy"])
		require.Equal(t, "false", md["defender"])
		require.Equal(t, "false", md["kms_secrets"])
		require.Equal(t, "false", md["workload_identity"])
		require.Equal(t, "false", md["azure_policy_addon"])
		require.Equal(t, "none", md["upgrade_channel"])
		require.NotContains(t, md, "node_os_upgrade_channel", "its default changed by API version")
		require.Equal(t, "", md["node_pools_public_ip"])
	})

	t.Run("hardened cluster", func(t *testing.T) {
		md := build(&armcontainerservice.ManagedClusterProperties{
			EnableRBAC:           to.Ptr(true),
			AADProfile:           &armcontainerservice.ManagedClusterAADProfile{Managed: to.Ptr(true), EnableAzureRBAC: to.Ptr(true)},
			DisableLocalAccounts: to.Ptr(true),
			APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
				EnablePrivateCluster: to.Ptr(true)},
			NetworkProfile: &armcontainerservice.NetworkProfile{NetworkPolicy: to.Ptr(armcontainerservice.NetworkPolicyCalico)},
			SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{
				Defender:         &armcontainerservice.ManagedClusterSecurityProfileDefender{SecurityMonitoring: &armcontainerservice.ManagedClusterSecurityProfileDefenderSecurityMonitoring{Enabled: to.Ptr(true)}},
				AzureKeyVaultKms: &armcontainerservice.AzureKeyVaultKms{Enabled: to.Ptr(true)},
				WorkloadIdentity: &armcontainerservice.ManagedClusterSecurityProfileWorkloadIdentity{Enabled: to.Ptr(true)},
			},
			AddonProfiles: map[string]*armcontainerservice.ManagedClusterAddonProfile{"azurePolicy": {Enabled: to.Ptr(true)}},
			AutoUpgradeProfile: &armcontainerservice.ManagedClusterAutoUpgradeProfile{
				UpgradeChannel:       to.Ptr(armcontainerservice.UpgradeChannelPatch),
				NodeOSUpgradeChannel: to.Ptr(armcontainerservice.NodeOSUpgradeChannelSecurityPatch)},
			AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{{Name: to.Ptr("sys"), EnableNodePublicIP: to.Ptr(false)}},
		})
		require.Equal(t, "true", md["rbac_enabled"])
		require.Equal(t, "true", md["entra_integration"])
		require.Equal(t, "true", md["azure_rbac"])
		require.Equal(t, "true", md["local_accounts_disabled"])
		require.Equal(t, "false", md["api_public"])
		require.Equal(t, "calico", md["network_policy"])
		require.Equal(t, "true", md["defender"])
		require.Equal(t, "true", md["kms_secrets"])
		require.Equal(t, "true", md["workload_identity"])
		require.Equal(t, "true", md["azure_policy_addon"], "add-on keys match case-insensitively")
		require.Equal(t, "patch", md["upgrade_channel"])
		require.Equal(t, "SecurityPatch", md["node_os_upgrade_channel"])
		require.Equal(t, "", md["node_pools_public_ip"])
	})

	t.Run("exposure details", func(t *testing.T) {
		md := build(&armcontainerservice.ManagedClusterProperties{
			APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
				AuthorizedIPRanges: []*string{to.Ptr("203.0.113.0/24"), to.Ptr("198.51.100.7/32"), nil}},
			NetworkProfile: &armcontainerservice.NetworkProfile{NetworkDataplane: to.Ptr(armcontainerservice.NetworkDataplaneCilium)},
			AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{
				{Name: to.Ptr("web"), EnableNodePublicIP: to.Ptr(true)}, {Name: to.Ptr("app"), EnableNodePublicIP: to.Ptr(true)}, nil},
		})
		require.Equal(t, "198.51.100.7/32,203.0.113.0/24", md["authorized_ip_ranges"])
		require.Equal(t, "cilium", md["network_policy"], "the Cilium dataplane enforces NetworkPolicy")
		require.Equal(t, "app,web", md["node_pools_public_ip"])

		off := build(&armcontainerservice.ManagedClusterProperties{PublicNetworkAccess: to.Ptr(armcontainerservice.PublicNetworkAccessDisabled)})
		require.Equal(t, "false", off["api_public"])

		legacy := build(&armcontainerservice.ManagedClusterProperties{AADProfile: &armcontainerservice.ManagedClusterAADProfile{ServerAppID: to.Ptr("app")}})
		require.Equal(t, "true", legacy["entra_integration"], "legacy server-app integration still authenticates through Entra")
	})
}

func TestDatabricksMetadata(t *testing.T) {
	build := func(p *armdatabricks.WorkspaceProperties) map[string]string {
		return databricksMetadata(&armdatabricks.Workspace{Properties: p})
	}
	bare := build(&armdatabricks.WorkspaceProperties{})
	require.Equal(t, "Enabled", bare["public_network_access"])
	require.Equal(t, "0", bare["private_endpoint_count"])
	require.Equal(t, "", bare["cmk_encryption"])
	require.NotContains(t, bare, "no_public_ip", "the default changed by API version")
	require.NotContains(t, bare, "custom_vnet_id", "no parameters block: VNet placement unknown")

	vnet := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/dbx"
	md := build(&armdatabricks.WorkspaceProperties{
		PublicNetworkAccess: to.Ptr(armdatabricks.PublicNetworkAccessDisabled),
		PrivateEndpointConnections: []*armdatabricks.PrivateEndpointConnection{{Properties: &armdatabricks.PrivateEndpointConnectionProperties{
			PrivateLinkServiceConnectionState: &armdatabricks.PrivateLinkServiceConnectionState{Status: to.Ptr(armdatabricks.PrivateLinkServiceConnectionStatusApproved)}}}},
		Encryption: &armdatabricks.WorkspacePropertiesEncryption{Entities: &armdatabricks.EncryptionEntitiesDefinition{
			ManagedServices: &armdatabricks.EncryptionV2{KeySource: to.Ptr(armdatabricks.EncryptionKeySourceMicrosoftKeyvault)}}},
		Parameters: &armdatabricks.WorkspaceCustomParameters{
			EnableNoPublicIP:        &armdatabricks.WorkspaceCustomBooleanParameter{Value: to.Ptr(true)},
			CustomVirtualNetworkID:  &armdatabricks.WorkspaceCustomStringParameter{Value: to.Ptr(vnet)},
			CustomPublicSubnetName:  &armdatabricks.WorkspaceCustomStringParameter{Value: to.Ptr("pub")},
			CustomPrivateSubnetName: &armdatabricks.WorkspaceCustomStringParameter{Value: to.Ptr("priv")},
		},
	})
	require.Equal(t, "Disabled", md["public_network_access"])
	require.Equal(t, "1", md["private_endpoint_count"])
	require.Equal(t, "managed_services", md["cmk_encryption"])
	require.Equal(t, "true", md["no_public_ip"])
	require.Equal(t, vnet, md["custom_vnet_id"])

	ws := asset.Asset{ID: "ws", Type: "azure_databricks_workspace", Provider: asset.ProviderAzure, Metadata: md}
	subnet := func(name, nsg string) asset.Asset {
		return asset.Asset{ID: vnet + "/subnets/" + name, Type: "azure_subnet", Provider: asset.ProviderAzure, Metadata: map[string]string{"nsg_id": nsg}}
	}
	assets := []asset.Asset{ws, subnet("pub", "nsg1"), subnet("priv", "")}
	applyDatabricksSubnetNSGs(assets)
	require.Equal(t, "priv", assets[0].Metadata["subnets_without_nsg"])

	ws2 := asset.Asset{ID: "ws2", Type: "azure_databricks_workspace", Provider: asset.ProviderAzure,
		Metadata: map[string]string{"custom_vnet_id": vnet, "public_subnet": "pub", "private_subnet": "gone"}}
	assets = []asset.Asset{ws2, subnet("pub", "nsg1")}
	applyDatabricksSubnetNSGs(assets)
	require.NotContains(t, assets[0].Metadata, "subnets_without_nsg", "a subnet not in this sweep cannot be judged")
}
