package azure

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stretchr/testify/require"
)

func TestStorageAccountAsset_Posture(t *testing.T) {
	id := "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
	build := func(props *armstorage.AccountProperties) map[string]string {
		return storageAccountAsset(&armstorage.Account{ID: &id, Properties: props}, "sub", time.Now()).Metadata
	}

	t.Run("no properties block records nothing", func(t *testing.T) {
		md := build(nil)
		for _, k := range []string{"allow_shared_key_access", "default_to_oauth", "minimum_tls_version",
			"public_network_access", "network_default_action", "key_expiration_days", "private_endpoint_count",
			"key1_created", "hns_enabled"} {
			require.NotContains(t, md, k)
		}
	})

	t.Run("documented null interpretations", func(t *testing.T) {
		md := build(&armstorage.AccountProperties{})
		require.Equal(t, "true", md["allow_shared_key_access"], "ARM: null is equivalent to true")
		require.Equal(t, "false", md["default_to_oauth"], "ARM: default interpretation is false")
		require.Equal(t, "TLS1_0", md["minimum_tls_version"], "ARM: default interpretation is TLS 1.0")
		require.Equal(t, "Enabled", md["public_network_access"], "Disabled is only ever set explicitly")
		require.Equal(t, "", md["key_expiration_days"], "no key policy is an observation")
		require.NotContains(t, md, "private_endpoint_count", "a nil connection list means ARM omitted it")
		empty := build(&armstorage.AccountProperties{PrivateEndpointConnections: []*armstorage.PrivateEndpointConnection{}})
		require.Equal(t, "0", empty["private_endpoint_count"], "a returned empty list is an observed zero")
	})

	t.Run("ambiguous nils stay unknown", func(t *testing.T) {
		md := build(&armstorage.AccountProperties{NetworkRuleSet: &armstorage.NetworkRuleSet{}})
		require.NotContains(t, md, "allow_cross_tenant_replication", "the default flipped for new accounts; no creation time, unknown")
		old := build(&armstorage.AccountProperties{CreationTime: to.Ptr(time.Date(2021, 3, 1, 0, 0, 0, 0, time.UTC))})
		require.Equal(t, "true", old["allow_cross_tenant_replication"], "null allows it on accounts created before 2023-12-15")
		recent := build(&armstorage.AccountProperties{CreationTime: to.Ptr(time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC))})
		require.Equal(t, "false", recent["allow_cross_tenant_replication"])
		require.NotContains(t, md, "network_default_action")
		require.NotContains(t, md, "network_bypass")
	})

	t.Run("key creation times", func(t *testing.T) {
		md := build(&armstorage.AccountProperties{})
		require.NotContains(t, md, "key1_created", "no keyCreationTime object: unknown")
		require.NotContains(t, md, "key2_created")
		require.Equal(t, "false", md["hns_enabled"])
		md = build(&armstorage.AccountProperties{KeyCreationTime: &armstorage.KeyCreationTime{}})
		require.Equal(t, keyUntracked, md["key1_created"], "a returned object with a null key time: not yet set, untracked")
		require.Equal(t, keyUntracked, md["key2_created"])
	})

	t.Run("explicit values", func(t *testing.T) {
		k1 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
		md := build(&armstorage.AccountProperties{
			AllowSharedKeyAccess:         to.Ptr(false),
			DefaultToOAuthAuthentication: to.Ptr(true),
			MinimumTLSVersion:            to.Ptr(armstorage.MinimumTLSVersionTLS12),
			PublicNetworkAccess:          to.Ptr(armstorage.PublicNetworkAccessDisabled),
			AllowCrossTenantReplication:  to.Ptr(true),
			NetworkRuleSet: &armstorage.NetworkRuleSet{
				DefaultAction: to.Ptr(armstorage.DefaultActionDeny),
				Bypass:        to.Ptr(armstorage.Bypass("Logging, AzureServices")),
			},
			KeyPolicy:       &armstorage.KeyPolicy{KeyExpirationPeriodInDays: to.Ptr[int32](90)},
			KeyCreationTime: &armstorage.KeyCreationTime{Key1: &k1},
			PrivateEndpointConnections: []*armstorage.PrivateEndpointConnection{
				{Properties: &armstorage.PrivateEndpointConnectionProperties{PrivateLinkServiceConnectionState: &armstorage.PrivateLinkServiceConnectionState{
					Status: to.Ptr(armstorage.PrivateEndpointServiceConnectionStatusApproved)}}},
				{Properties: &armstorage.PrivateEndpointConnectionProperties{PrivateLinkServiceConnectionState: &armstorage.PrivateLinkServiceConnectionState{
					Status: to.Ptr(armstorage.PrivateEndpointServiceConnectionStatusPending)}}},
				nil,
			},
		})
		require.Equal(t, "false", md["allow_shared_key_access"])
		require.Equal(t, "true", md["default_to_oauth"])
		require.Equal(t, "TLS1_2", md["minimum_tls_version"])
		require.Equal(t, "Disabled", md["public_network_access"])
		require.Equal(t, "true", md["allow_cross_tenant_replication"])
		require.Equal(t, "Deny", md["network_default_action"])
		require.Equal(t, "Logging, AzureServices", md["network_bypass"])
		require.Equal(t, "90", md["key_expiration_days"])
		require.Equal(t, "2026-01-02T03:04:05Z", md["key1_created"])
		require.Equal(t, keyUntracked, md["key2_created"], "a key with no timestamp predates tracking")
		require.Equal(t, "1", md["private_endpoint_count"], "only approved connections count")
	})
}

func TestVNetAndSubnetMetadata(t *testing.T) {
	require.NotContains(t, vnetMetadata(&armnetwork.VirtualNetwork{}), "ddos_protection")
	require.Equal(t, "false", vnetMetadata(&armnetwork.VirtualNetwork{
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{}})["ddos_protection"])
	require.Equal(t, "true", vnetMetadata(&armnetwork.VirtualNetwork{
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{EnableDdosProtection: to.Ptr(true)}})["ddos_protection"])

	require.NotContains(t, subnetMetadata(&armnetwork.Subnet{}), "nsg_id", "no properties: association unknown")
	bare := subnetMetadata(&armnetwork.Subnet{Properties: &armnetwork.SubnetPropertiesFormat{AddressPrefix: to.Ptr("10.0.1.0/24")}})
	require.Equal(t, "", bare["nsg_id"])
	require.Contains(t, bare, "nsg_id", "properties returned without an NSG is an observed none")
	require.Equal(t, "10.0.1.0/24", bare["address_prefix"])
	guarded := subnetMetadata(&armnetwork.Subnet{Properties: &armnetwork.SubnetPropertiesFormat{
		NetworkSecurityGroup: &armnetwork.SecurityGroup{ID: to.Ptr("nsg-1")}}})
	require.Equal(t, "nsg-1", guarded["nsg_id"])
}

func TestAppGatewayMetadata(t *testing.T) {
	require.Equal(t, map[string]string{"public": "true"}, appGatewayMetadata(&armnetwork.ApplicationGateway{}))

	bare := appGatewayMetadata(&armnetwork.ApplicationGateway{Properties: &armnetwork.ApplicationGatewayPropertiesFormat{}})
	require.Equal(t, "false", bare["waf_enabled"])
	require.Equal(t, "false", bare["http2_enabled"])
	require.NotContains(t, bare, "min_tls_version", "no SSL policy and no SKU: the default cannot be told")
	v2 := appGatewayMetadata(&armnetwork.ApplicationGateway{Properties: &armnetwork.ApplicationGatewayPropertiesFormat{
		SKU: &armnetwork.ApplicationGatewaySKU{Tier: to.Ptr(armnetwork.ApplicationGatewayTierWAFV2)}}})
	require.Equal(t, "1.2", v2["min_tls_version"], "v2 default after the TLS 1.0/1.1 retirement")
	v1 := appGatewayMetadata(&armnetwork.ApplicationGateway{Properties: &armnetwork.ApplicationGatewayPropertiesFormat{
		SKU: &armnetwork.ApplicationGatewaySKU{Tier: to.Ptr(armnetwork.ApplicationGatewayTierStandard)}, SSLPolicy: &armnetwork.ApplicationGatewaySSLPolicy{}}})
	require.Equal(t, "1.0", v1["min_tls_version"], "v1 keeps AppGwSslPolicy20150501 as its default")
	profiled := appGatewayMetadata(&armnetwork.ApplicationGateway{Properties: &armnetwork.ApplicationGatewayPropertiesFormat{
		SKU: &armnetwork.ApplicationGatewaySKU{Tier: to.Ptr(armnetwork.ApplicationGatewayTierStandardV2)}, SSLProfiles: []*armnetwork.ApplicationGatewaySSLProfile{{Properties: &armnetwork.ApplicationGatewaySSLProfilePropertiesFormat{
			SSLPolicy: &armnetwork.ApplicationGatewaySSLPolicy{PolicyName: to.Ptr(armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20170401)}}}}}})
	require.Equal(t, "1.1", profiled["min_tls_version"], "a listener SSL profile can lower the floor")
	require.Equal(t, "false", bare["waf_inline"])
	require.Equal(t, "", bare["waf_policy_id"])

	policy := appGatewayMetadata(&armnetwork.ApplicationGateway{Properties: &armnetwork.ApplicationGatewayPropertiesFormat{
		FirewallPolicy: &armnetwork.SubResource{ID: to.Ptr("wafpol")},
		EnableHTTP2:    to.Ptr(true),
	}})
	require.Equal(t, "true", policy["waf_enabled"], "provisional until applyWAFPolicies reads the policy")
	require.Equal(t, "wafpol", policy["waf_policy_id"])
	require.Equal(t, "true", policy["http2_enabled"])

	inline := appGatewayMetadata(&armnetwork.ApplicationGateway{Properties: &armnetwork.ApplicationGatewayPropertiesFormat{
		WebApplicationFirewallConfiguration: &armnetwork.ApplicationGatewayWebApplicationFirewallConfiguration{Enabled: to.Ptr(true)},
	}})
	require.Equal(t, "true", inline["waf_enabled"])

	tests := []struct {
		name string
		sp   *armnetwork.ApplicationGatewaySSLPolicy
		want string
	}{
		{"nil policy", nil, ""},
		{"empty policy", &armnetwork.ApplicationGatewaySSLPolicy{}, ""},
		{"custom ciphers only", &armnetwork.ApplicationGatewaySSLPolicy{PolicyType: to.Ptr(armnetwork.ApplicationGatewaySSLPolicyTypeCustom),
			CipherSuites: []*armnetwork.ApplicationGatewaySSLCipherSuite{to.Ptr(armnetwork.ApplicationGatewaySSLCipherSuiteTLSECDHERSAWITHAES256GCMSHA384)}}, ""},
		{"explicit min", &armnetwork.ApplicationGatewaySSLPolicy{MinProtocolVersion: to.Ptr(armnetwork.ApplicationGatewaySSLProtocolTLSv11)}, "1.1"},
		{"legacy predefined", &armnetwork.ApplicationGatewaySSLPolicy{PolicyName: to.Ptr(armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20150501)}, "1.0"},
		{"2017 predefined", &armnetwork.ApplicationGatewaySSLPolicy{PolicyName: to.Ptr(armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20170401)}, "1.1"},
		{"2017S predefined", &armnetwork.ApplicationGatewaySSLPolicy{PolicyName: to.Ptr(armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20170401S)}, "1.2"},
		{"2022 predefined", &armnetwork.ApplicationGatewaySSLPolicy{PolicyName: to.Ptr(armnetwork.ApplicationGatewaySSLPolicyNameAppGwSSLPolicy20220101)}, "1.2"},
		{"unknown predefined", &armnetwork.ApplicationGatewaySSLPolicy{PolicyName: to.Ptr(armnetwork.ApplicationGatewaySSLPolicyName("Future"))}, ""},
		{"disabled list", &armnetwork.ApplicationGatewaySSLPolicy{DisabledSSLProtocols: []*armnetwork.ApplicationGatewaySSLProtocol{
			to.Ptr(armnetwork.ApplicationGatewaySSLProtocolTLSv10)}}, "1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, appGatewayMinTLS(tt.sp))
		})
	}
}

func TestSubscriptionRBACAsset(t *testing.T) {
	const sub = "0000-sub"
	subScope := "/subscriptions/" + sub
	ownerDef := subScope + "/providers/Microsoft.Authorization/roleDefinitions/" + ownerRoleGUID
	uaaDef := subScope + "/providers/Microsoft.Authorization/roleDefinitions/" + userAccessAdministratorRoleGUID
	customID := subScope + "/providers/Microsoft.Authorization/roleDefinitions/custom-1"
	defs := map[string]roleDef{
		ownerDef: {name: "Owner", roleType: "BuiltInRole", actions: []string{"*"}, assignableScopes: []string{"/"}},
		customID: {name: "Super Admin", roleType: "CustomRole", actions: []string{"*"}, assignableScopes: []string{subScope}},
		subScope + "/providers/Microsoft.Authorization/roleDefinitions/custom-rg": {
			name: "RG Admin", roleType: "CustomRole", actions: []string{"*"},
			assignableScopes: []string{subScope + "/resourceGroups/rg"},
		},
		subScope + "/providers/Microsoft.Authorization/roleDefinitions/custom-narrow": {
			name: "Reader Plus", roleType: "CustomRole", actions: []string{"Microsoft.Compute/*/read"},
			assignableScopes: []string{"/"},
		},
	}
	assignments := []roleAssignment{
		{principalID: "u1", principalType: "User", roleDefID: ownerDef, scope: subScope},
		{principalID: "u1", principalType: "User", roleDefID: ownerDef, scope: subScope}, // duplicate counts once
		{principalID: "g1", principalType: "Group", roleDefID: ownerDef, scope: "/providers/Microsoft.Management/managementGroups/mg"},
		{principalID: "u2", principalType: "User", roleDefID: ownerDef, scope: subScope + "/resourceGroups/rg"}, // below: not a subscription owner
		{principalID: "u3", principalType: "User", roleDefID: uaaDef, scope: "/"},
		{principalID: "u4", principalType: "User", roleDefID: uaaDef, scope: subScope}, // not elevated access
	}

	md := subscriptionRBACSettings(rbacListing{assignments: assignments, defs: defs}, sub)
	require.Equal(t, "2", md["owner_count"])
	require.Equal(t, "Group:g1,User:u1", md["owners"])
	require.Equal(t, "User:u3", md["root_user_access_admins"])
	require.Equal(t, "Super Admin", md["custom_owner_roles"])

	empty := subscriptionRBACSettings(rbacListing{}, sub)
	require.Equal(t, "0", empty["owner_count"])
	require.Contains(t, empty, "root_user_access_admins", "a fully read listing with none is an observation")
	require.Equal(t, "", empty["custom_owner_roles"])

	s := newSettingsAsset()
	s.set(md)
	a := s.subscriptionAsset(sub, time.Now())
	require.Equal(t, subScope, a.ID)
	require.Equal(t, "azure_subscription", a.Type)
	require.Equal(t, "2", a.Metadata["owner_count"])
}

func TestSubscriptionRBACAsset_LockAdminRoles(t *testing.T) {
	const sub = "0000-sub"
	subScope := "/subscriptions/" + sub
	role := func(name, typ string, scopes []string, actions ...string) roleDef {
		return roleDef{name: name, roleType: typ, assignableScopes: scopes, actions: actions}
	}
	defs := map[string]roleDef{
		"a": role("Lock Admin", "CustomRole", []string{subScope}, "Microsoft.Authorization/locks/*"),
		"b": role("Reader Plus", "CustomRole", []string{"/"}, "Microsoft.Compute/*/read"),
		"c": role("Wildcard", "CustomRole", []string{subScope}, "Microsoft.Authorization/*"),
		"d": role("Other Sub", "CustomRole", []string{"/subscriptions/other"}, "Microsoft.Authorization/locks/read"),
		"e": role("Built-in", "BuiltInRole", []string{"/"}, "Microsoft.Authorization/locks/*"),
	}
	md := subscriptionRBACSettings(rbacListing{defs: defs}, sub)
	require.Equal(t, "3", md["custom_role_count"])
	require.Equal(t, "1", md["custom_lock_admin_roles"])

	none := subscriptionRBACSettings(rbacListing{}, sub)
	require.Equal(t, "0", none["custom_role_count"])
	require.Equal(t, "0", none["custom_lock_admin_roles"])
}
