package azure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

const acctID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"

type fakeStorageServices struct {
	blob      *armstorage.BlobServicePropertiesProperties
	file      *armstorage.FileServicePropertiesProperties
	shares    shareKinds
	blobErr   error
	fileErr   error
	sharesErr error
	calls     []string
}

func (f *fakeStorageServices) blobService(_ context.Context, rg, acct string) (*armstorage.BlobServicePropertiesProperties, error) {
	f.calls = append(f.calls, "blob:"+rg+"/"+acct)
	return f.blob, f.blobErr
}

func (f *fakeStorageServices) fileService(_ context.Context, rg, acct string) (*armstorage.FileServicePropertiesProperties, error) {
	f.calls = append(f.calls, "file:"+rg+"/"+acct)
	return f.file, f.fileErr
}

func (f *fakeStorageServices) fileShares(_ context.Context, rg, acct string) (shareKinds, error) {
	f.calls = append(f.calls, "shares:"+rg+"/"+acct)
	return f.shares, f.sharesErr
}

func TestStorageServiceMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("unset settings on a read service are the documented defaults", func(t *testing.T) {
		api := &fakeStorageServices{blob: &armstorage.BlobServicePropertiesProperties{}, file: &armstorage.FileServicePropertiesProperties{}, shares: shareKinds{any: true, smb: true}}
		md := storageServiceMetadata(ctx, api, acctID, "acct", "StorageV2")
		require.Equal(t, "false", md["blob_soft_delete"])
		require.Equal(t, "false", md["container_soft_delete"])
		require.Equal(t, "false", md["blob_versioning"])
		require.Equal(t, "false", md["file_soft_delete"])
		require.Equal(t, "true", md["file_shares"])
		require.Equal(t, "true", md["smb_shares"])
		require.Equal(t, smbDefaultVersions, md["smb_versions"], "no SMB settings accept every version")
		require.Equal(t, smbDefaultChannelEncryption, md["smb_channel_encryption"])
		require.Equal(t, []string{"blob:rg/acct", "shares:rg/acct", "file:rg/acct"}, api.calls)
	})

	t.Run("explicit settings", func(t *testing.T) {
		on := &armstorage.DeleteRetentionPolicy{Enabled: to.Ptr(true), Days: to.Ptr[int32](7)}
		api := &fakeStorageServices{
			blob: &armstorage.BlobServicePropertiesProperties{DeleteRetentionPolicy: on, ContainerDeleteRetentionPolicy: on, IsVersioningEnabled: to.Ptr(true)},
			file: &armstorage.FileServicePropertiesProperties{ShareDeleteRetentionPolicy: on, ProtocolSettings: &armstorage.ProtocolSettings{
				Smb: &armstorage.SmbSetting{Versions: to.Ptr("SMB3.1.1"), ChannelEncryption: to.Ptr("AES-256-GCM")}}},
		}
		md := storageServiceMetadata(ctx, api, acctID, "acct", "StorageV2")
		require.Equal(t, "true", md["blob_soft_delete"])
		require.Equal(t, "true", md["container_soft_delete"])
		require.Equal(t, "true", md["blob_versioning"])
		require.Equal(t, "true", md["file_soft_delete"])
		require.Equal(t, "false", md["file_shares"])
		require.Equal(t, "false", md["smb_shares"])
		require.Equal(t, "SMB3.1.1", md["smb_versions"])
		require.Equal(t, "AES-256-GCM", md["smb_channel_encryption"])
	})

	t.Run("a failed read leaves that service unknown", func(t *testing.T) {
		api := &fakeStorageServices{blobErr: errors.New("403"), fileErr: errors.New("throttled"), shares: shareKinds{any: true, smb: true}}
		md := storageServiceMetadata(ctx, api, acctID, "acct", "StorageV2")
		require.Empty(t, md, "neither service read, so nothing is observed — not 'soft delete off'")

		api = &fakeStorageServices{blob: &armstorage.BlobServicePropertiesProperties{}, sharesErr: errors.New("403")}
		md = storageServiceMetadata(ctx, api, acctID, "acct", "StorageV2")
		require.Equal(t, "false", md["blob_soft_delete"])
		require.NotContains(t, md, "file_shares", "an unread share list cannot gate the SMB checks")
		require.NotContains(t, md, "smb_versions")
	})

	t.Run("services the account kind lacks are not read", func(t *testing.T) {
		api := &fakeStorageServices{blob: &armstorage.BlobServicePropertiesProperties{}, file: &armstorage.FileServicePropertiesProperties{}}
		md := storageServiceMetadata(ctx, api, acctID, "acct", "BlockBlobStorage")
		require.NotContains(t, md, "file_soft_delete")
		require.Equal(t, []string{"blob:rg/acct"}, api.calls)

		api = &fakeStorageServices{blob: &armstorage.BlobServicePropertiesProperties{}, file: &armstorage.FileServicePropertiesProperties{}}
		md = storageServiceMetadata(ctx, api, acctID, "acct", "FileStorage")
		require.NotContains(t, md, "blob_soft_delete")
		require.Equal(t, []string{"shares:rg/acct", "file:rg/acct"}, api.calls)
	})
}

func TestReadStorageServices_AnnotatesEveryAccount(t *testing.T) {
	assets := make([]asset.Asset, 20)
	for i := range assets {
		assets[i] = asset.Asset{ID: acctID, Name: "acct", Metadata: map[string]string{"kind": "BlobStorage"}}
	}
	readStorageServices(context.Background(), &lockedFake{}, assets)
	for _, a := range assets {
		require.Equal(t, "false", a.Metadata["blob_soft_delete"])
	}
}

// lockedFake is a stateless storageServiceAPI safe for concurrent use.
type lockedFake struct{}

func (lockedFake) blobService(context.Context, string, string) (*armstorage.BlobServicePropertiesProperties, error) {
	return &armstorage.BlobServicePropertiesProperties{}, nil
}

func (lockedFake) fileService(context.Context, string, string) (*armstorage.FileServicePropertiesProperties, error) {
	return &armstorage.FileServicePropertiesProperties{}, nil
}

func (lockedFake) fileShares(context.Context, string, string) (shareKinds, error) {
	return shareKinds{}, nil
}

func TestStorageLocks(t *testing.T) {
	lock := func(scope string, lvl armlocks.LockLevel) *armlocks.ManagementLockObject {
		return &armlocks.ManagementLockObject{
			ID:         to.Ptr(scope + "/providers/Microsoft.Authorization/locks/l1"),
			Properties: &armlocks.ManagementLockProperties{Level: to.Ptr(lvl)},
		}
	}
	scope, ok := deleteLockScope(lock(acctID, armlocks.LockLevelCanNotDelete))
	require.True(t, ok)
	require.Equal(t, "/subscriptions/sub/resourcegroups/rg/providers/microsoft.storage/storageaccounts/acct", scope)
	_, ok = deleteLockScope(lock(acctID, armlocks.LockLevelNotSpecified))
	require.False(t, ok, "only CanNotDelete and ReadOnly block deletion")

	tests := []struct {
		name   string
		scopes map[string]bool
		want   string
	}{
		{"no locks", map[string]bool{}, "false"},
		{"on the account", map[string]bool{"/subscriptions/sub/resourcegroups/rg/providers/microsoft.storage/storageaccounts/acct": true}, "true"},
		{"on the resource group", map[string]bool{"/subscriptions/sub/resourcegroups/rg": true}, "true"},
		{"on the subscription", map[string]bool{"/subscriptions/sub": true}, "true"},
		{"on another group", map[string]bool{"/subscriptions/sub/resourcegroups/other": true}, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := []asset.Asset{{ID: acctID, Type: "azure_storage_account", Provider: asset.ProviderAzure, Metadata: map[string]string{}}}
			applyStorageLocks(assets, tt.scopes, "sub")
			require.Equal(t, tt.want, assets[0].Metadata["delete_lock"])
		})
	}
}

func TestFlowLogsAndWatchers(t *testing.T) {
	vnetID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v1"
	nsgID := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n1"
	nw := networkWatchers{regions: map[string]bool{"eastus": true}, flowLogs: map[string]flowLog{}}
	nw.addFlowLog(&armnetwork.FlowLog{Properties: &armnetwork.FlowLogPropertiesFormat{
		TargetResourceID: to.Ptr("/subscriptions/sub/resourceGroups/RG/providers/Microsoft.Network/virtualNetworks/v1"),
		Enabled:          to.Ptr(true),
		RetentionPolicy:  &armnetwork.RetentionPolicyParameters{Enabled: to.Ptr(true), Days: to.Ptr[int32](30)},
		FlowAnalyticsConfiguration: &armnetwork.TrafficAnalyticsProperties{NetworkWatcherFlowAnalyticsConfiguration: &armnetwork.TrafficAnalyticsConfigurationProperties{
			Enabled: to.Ptr(true), WorkspaceResourceID: to.Ptr("ws")}},
	}})
	// A disabled duplicate must not hide the working log.
	nw.addFlowLog(&armnetwork.FlowLog{Properties: &armnetwork.FlowLogPropertiesFormat{TargetResourceID: to.Ptr(vnetID), Enabled: to.Ptr(false)}})
	nw.addFlowLog(&armnetwork.FlowLog{Properties: &armnetwork.FlowLogPropertiesFormat{
		TargetResourceID: to.Ptr(nsgID), Enabled: to.Ptr(true),
		RetentionPolicy: &armnetwork.RetentionPolicyParameters{Enabled: to.Ptr(false), Days: to.Ptr[int32](7)},
	}})

	assets := []asset.Asset{
		{ID: vnetID, Type: "azure_vnet", Provider: asset.ProviderAzure, Region: "eastus", Metadata: map[string]string{}},
		{ID: nsgID, Type: "security_group", Provider: asset.ProviderAzure, Region: "eastus", Metadata: map[string]string{}},
		{ID: "v2", Type: "azure_vnet", Provider: asset.ProviderAzure, Region: "West Europe", Metadata: map[string]string{}},
		{ID: "v3", Type: "azure_vnet", Provider: asset.ProviderAzure, Region: "westeurope", Metadata: map[string]string{}},
	}
	applyFlowLogs(assets, nw)
	require.Equal(t, "true", assets[0].Metadata["flow_log_enabled"], "ARM ID case differences must still match")
	require.Equal(t, "30", assets[0].Metadata["flow_log_retention_days"])
	require.Equal(t, "true", assets[0].Metadata["flow_log_traffic_analytics"])
	require.Equal(t, "0", assets[1].Metadata["flow_log_retention_days"], "a disabled retention policy keeps records indefinitely")
	require.Equal(t, "false", assets[1].Metadata["flow_log_traffic_analytics"])
	require.Equal(t, "false", assets[2].Metadata["flow_log_enabled"])
	require.NotContains(t, assets[2].Metadata, "flow_log_retention_days", "no log, no retention to grade")
	require.Equal(t, "westeurope", watcherMissingRegions(assets, nw), "display-form regions fold together")
}

func TestWAFPolicies(t *testing.T) {
	attached := &armnetwork.WebApplicationFirewallPolicy{Properties: &armnetwork.WebApplicationFirewallPolicyPropertiesFormat{
		ApplicationGateways: []*armnetwork.ApplicationGateway{{ID: to.Ptr("ag")}},
		PolicySettings: &armnetwork.PolicySettings{State: to.Ptr(armnetwork.WebApplicationFirewallEnabledStateDisabled),
			Mode: to.Ptr(armnetwork.WebApplicationFirewallModeDetection), RequestBodyCheck: to.Ptr(false)},
		ManagedRules: &armnetwork.ManagedRulesDefinition{ManagedRuleSets: []*armnetwork.ManagedRuleSet{{RuleSetType: to.Ptr("OWASP")}}},
	}}
	md := wafPolicyMetadata(attached)
	require.Equal(t, "true", md["attached"])
	require.Equal(t, "Disabled", md["state"])
	require.Equal(t, "false", md["request_body_check"])
	require.Equal(t, "false", md["bot_protection"])

	bare := wafPolicyMetadata(&armnetwork.WebApplicationFirewallPolicy{Properties: &armnetwork.WebApplicationFirewallPolicyPropertiesFormat{
		ManagedRules: &armnetwork.ManagedRulesDefinition{ManagedRuleSets: []*armnetwork.ManagedRuleSet{{RuleSetType: to.Ptr("microsoft_botmanagerruleset")}}},
	}})
	require.Equal(t, "false", bare["attached"])
	require.Equal(t, "true", bare["bot_protection"])
	require.NotContains(t, bare, "request_body_check", "no documented default: unknown")
	require.NotContains(t, bare, "state")

	gw := func(policy string) asset.Asset {
		return asset.Asset{Type: "azure_app_gateway", Provider: asset.ProviderAzure,
			Metadata: map[string]string{"waf_inline": "false", "waf_policy_id": policy, "waf_enabled": boolStr(policy != "")}}
	}
	policies := []asset.Asset{
		{ID: "/P/Off", Metadata: map[string]string{"state": "Disabled", "mode": "Prevention"}},
		{ID: "/p/on", Metadata: map[string]string{"state": "Enabled", "mode": "Detection"}},
		{ID: "/p/nostate", Metadata: map[string]string{}},
	}
	assets := []asset.Asset{gw("/p/off"), gw("/p/on"), gw("/p/missing"), gw("/p/nostate"), gw("")}
	applyWAFPolicies(assets, policies)
	require.Equal(t, "false", assets[0].Metadata["waf_enabled"], "a Disabled policy is no WAF")
	require.Equal(t, "true", assets[1].Metadata["waf_enabled"])
	require.Equal(t, "Detection", assets[1].Metadata["waf_mode"])
	require.NotContains(t, assets[2].Metadata, "waf_enabled", "an unlisted policy's state is unknown")
	require.NotContains(t, assets[3].Metadata, "waf_enabled")
	require.Equal(t, "false", assets[4].Metadata["waf_enabled"], "no policy and no inline WAF stays an observation")

	failed := []asset.Asset{gw("/p/on")}
	applyWAFPolicies(failed, nil)
	require.NotContains(t, failed[0].Metadata, "waf_enabled", "a failed policy listing must not leave attached reading as protected")
}

func TestVPNGatewayMetadata(t *testing.T) {
	pool := &armnetwork.AddressSpace{AddressPrefixes: []*string{to.Ptr("172.16.0.0/24")}}
	gw := func(cfg *armnetwork.VPNClientConfiguration) map[string]string {
		return vpnGatewayMetadata(&armnetwork.VirtualNetworkGateway{Properties: &armnetwork.VirtualNetworkGatewayPropertiesFormat{VPNClientConfiguration: cfg}})
	}
	require.Equal(t, "false", gw(nil)["p2s_enabled"])
	require.Equal(t, "false", gw(&armnetwork.VPNClientConfiguration{})["p2s_enabled"], "no client address pool: P2S off")

	explicit := gw(&armnetwork.VPNClientConfiguration{VPNClientAddressPool: pool, VPNAuthenticationTypes: []*armnetwork.VPNAuthenticationType{
		to.Ptr(armnetwork.VPNAuthenticationTypeCertificate), to.Ptr(armnetwork.VPNAuthenticationTypeAAD)}})
	require.Equal(t, "true", explicit["p2s_enabled"])
	require.Equal(t, "AAD,Certificate", explicit["p2s_auth_types"])

	implied := gw(&armnetwork.VPNClientConfiguration{VPNClientAddressPool: pool,
		VPNClientRootCertificates: []*armnetwork.VPNClientRootCertificate{{}}})
	require.Equal(t, "Certificate", implied["p2s_auth_types"], "older gateways imply the type from root certificates")

	unknown := gw(&armnetwork.VPNClientConfiguration{VPNClientAddressPool: pool})
	require.NotContains(t, unknown, "p2s_auth_types")
}

func TestMergeSubscriptionFacts(t *testing.T) {
	now := time.Now()
	res := collect.Result{Assets: []asset.Asset{{ID: "/subscriptions/sub", Type: "azure_subscription", Provider: asset.ProviderAzure,
		Metadata: map[string]string{"owner_count": "2"}}}}
	mergeSubscriptionFacts(&res, "sub", map[string]string{"bastion_host_count": "0"}, now)
	require.Len(t, res.Assets, 1, "extends the identities collector's asset rather than duplicating it")
	require.Equal(t, map[string]string{"owner_count": "2", "bastion_host_count": "0"}, res.Assets[0].Metadata)

	empty := collect.Result{}
	mergeSubscriptionFacts(&empty, "sub", map[string]string{"vm_count": "3"}, now)
	require.Len(t, empty.Assets, 1)
	require.Equal(t, "azure_subscription", empty.Assets[0].Type)
	require.NotContains(t, empty.Assets[0].Metadata, "owner_count", "RBAC facts it did not read stay absent")
}
