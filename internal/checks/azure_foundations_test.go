package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// The TestChecksNeverFireOnAbsentData contract for the CIS Azure Foundations
// checks: the confirmed negative fires, the compliant state and absent data
// stay silent.
func TestAzureFoundationsChecksNeverFireOnAbsentData(t *testing.T) {
	old := time.Now().Add(-200 * 24 * time.Hour).UTC().Format(time.RFC3339)
	fresh := time.Now().Add(-10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	tests := []struct {
		check     Check
		violating map[string]string
		compliant map[string]string
		unknown   map[string]string
	}{
		{
			check:     azureNSGAllPortsOpenInternet,
			violating: map[string]string{"ingress": `[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["Internet"],"access":"allow","priority":100}]`},
			compliant: map[string]string{"ingress": `[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["10.0.0.0/8"],"access":"allow","priority":100}]`},
			unknown:   map[string]string{},
		},
		{
			check:     azureNSGUDPOpenInternet,
			violating: map[string]string{"ingress": `[{"protocol":"udp","from_port":53,"to_port":53,"cidrs":["Internet"],"access":"allow","priority":100}]`},
			compliant: map[string]string{"ingress": `[{"protocol":"udp","from_port":53,"to_port":53,"cidrs":["10.0.0.0/8"],"access":"allow","priority":100}]`},
			unknown:   map[string]string{},
		},
		{
			check:     azureNSGHTTPOpenInternet,
			violating: map[string]string{"ingress": `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["0.0.0.0/0"],"access":"allow","priority":100}]`},
			compliant: map[string]string{"ingress": `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["AzureFrontDoor.Backend"],"access":"allow","priority":100}]`},
			unknown:   map[string]string{},
		},
		{
			check:     azureSubnetNoNSG,
			violating: map[string]string{"nsg_id": ""},
			compliant: map[string]string{"nsg_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/web"},
			unknown:   map[string]string{"address_prefix": "10.0.1.0/24"},
		},
		{
			check:     azureVNetNoDDoSProtection,
			violating: map[string]string{"ddos_protection": "false"},
			compliant: map[string]string{"ddos_protection": "true"},
			unknown:   map[string]string{"address_space": "10.0.0.0/16"},
		},
		{
			check:     azureAppGatewayNoWAF,
			violating: map[string]string{"waf_enabled": "false"},
			compliant: map[string]string{"waf_enabled": "true"},
			unknown:   map[string]string{"public": "true"},
		},
		{
			check:     azureAppGatewayMinTLS,
			violating: map[string]string{"min_tls_version": "1.0"},
			compliant: map[string]string{"min_tls_version": "1.2"},
			unknown:   map[string]string{"public": "true"},
		},
		{
			check:     azureAppGatewayHTTP2Disabled,
			violating: map[string]string{"http2_enabled": "false"},
			compliant: map[string]string{"http2_enabled": "true"},
			unknown:   map[string]string{"public": "true"},
		},
		{
			check:     azureStorageDefaultNetworkAllow,
			violating: map[string]string{"public_network_access": "Enabled", "network_default_action": "Allow"},
			compliant: map[string]string{"public_network_access": "Disabled", "network_default_action": "Allow"},
			unknown:   map[string]string{"public_network_access": "Enabled"},
		},
		{
			check:     azureStoragePublicNetworkAccess,
			violating: map[string]string{"public_network_access": "Enabled", "network_default_action": "Deny"},
			compliant: map[string]string{"public_network_access": "Disabled", "network_default_action": "Deny"},
			unknown:   map[string]string{"network_default_action": "Deny"},
		},
		{
			check:     azureStorageMinTLS,
			violating: map[string]string{"minimum_tls_version": "TLS1_0"},
			compliant: map[string]string{"minimum_tls_version": "TLS1_2"},
			unknown:   map[string]string{},
		},
		{
			check:     azureStorageSharedKeyAccess,
			violating: map[string]string{"allow_shared_key_access": "true"},
			compliant: map[string]string{"allow_shared_key_access": "false"},
			unknown:   map[string]string{},
		},
		{
			check:     azureStorageKeyNotRotated,
			violating: map[string]string{"allow_shared_key_access": "true", "key1_created": old, "key2_created": fresh},
			compliant: map[string]string{"allow_shared_key_access": "true", "key1_created": fresh, "key2_created": fresh},
			// Accounts older than key-creation tracking carry no timestamps.
			unknown: map[string]string{"allow_shared_key_access": "true"},
		},
		{
			check:     azureStorageNoKeyExpiryPolicy,
			violating: map[string]string{"allow_shared_key_access": "true", "key_expiration_days": ""},
			compliant: map[string]string{"allow_shared_key_access": "true", "key_expiration_days": "90"},
			unknown:   map[string]string{"allow_shared_key_access": "true"},
		},
		{
			check:     azureStorageCrossTenantReplication,
			violating: map[string]string{"allow_cross_tenant_replication": "true"},
			compliant: map[string]string{"allow_cross_tenant_replication": "false"},
			// The default flipped for new accounts, so the collector leaves nil unknown.
			unknown: map[string]string{},
		},
		{
			check:     azureStorageNoPrivateEndpoint,
			violating: map[string]string{"private_endpoint_count": "0"},
			compliant: map[string]string{"private_endpoint_count": "1"},
			unknown:   map[string]string{},
		},
		{
			check:     azureStorageTrustedServicesBypassOff,
			violating: map[string]string{"network_default_action": "Deny", "network_bypass": "None"},
			compliant: map[string]string{"network_default_action": "Deny", "network_bypass": "Logging, AzureServices"},
			unknown:   map[string]string{"network_default_action": "Deny"},
		},
		{
			check:     azureStoragePortalNotEntraAuth,
			violating: map[string]string{"default_to_oauth": "false"},
			compliant: map[string]string{"default_to_oauth": "true"},
			unknown:   map[string]string{},
		},
		{
			check:     azureRootUserAccessAdmin,
			violating: map[string]string{"root_user_access_admins": "User:u1"},
			compliant: map[string]string{"root_user_access_admins": ""},
			unknown:   map[string]string{},
		},
		{
			check:     azureCustomOwnerRole,
			violating: map[string]string{"custom_owner_roles": "Super Admin"},
			compliant: map[string]string{"custom_owner_roles": ""},
			unknown:   map[string]string{},
		},
		{
			check:     azureSubscriptionOwnerCount,
			violating: map[string]string{"owner_count": "5"},
			compliant: map[string]string{"owner_count": "2"},
			unknown:   map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.check.ID, func(t *testing.T) {
			build := func(md map[string]string) asset.Asset {
				return asset.Asset{ID: "res-1", Name: "app", Type: tt.check.AssetType, Provider: tt.check.Provider, Metadata: md}
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
func TestAzureFoundationsChecks_AbsentKeysNotEvaluable(t *testing.T) {
	reg := Default()
	tests := []struct {
		id string
		md map[string]string
	}{
		{"azure-storage-key-not-rotated", map[string]string{"allow_shared_key_access": "true"}},
		{"azure-storage-default-network-allow", map[string]string{"public_network_access": "Enabled"}},
		{"azure-subscription-owner-count", map[string]string{}},
		{"azure-subnet-no-nsg", map[string]string{"address_prefix": "10.0.0.0/24"}},
		{"azure-root-user-access-admin", map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			c, ok := reg.ByID(tt.id)
			require.True(t, ok)
			a := asset.Asset{ID: "r", Name: "app", Type: c.AssetType, Provider: c.Provider, Metadata: tt.md}
			require.False(t, c.Violates(a))
			require.False(t, c.Evaluable(a))
		})
	}
}

func TestNSGAllowsWorldAnyPort_UDP(t *testing.T) {
	nsg := func(ingress string) asset.Asset {
		return asset.Asset{Type: "security_group", Provider: asset.ProviderAzure, Metadata: map[string]string{"ingress": ingress}}
	}
	tests := []struct {
		name    string
		ingress string
		fires   bool
	}{
		{"udp from internet", `[{"protocol":"udp","from_port":123,"to_port":123,"cidrs":["Internet"],"access":"allow","priority":200}]`, true},
		{"any protocol any port is the rollup's", `[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["*"],"access":"allow","priority":200}]`, false},
		{"any protocol, port-scoped", `[{"protocol":"*","from_port":500,"to_port":500,"cidrs":["*"],"access":"allow","priority":200}]`, true},
		{"tcp only", `[{"protocol":"tcp","from_port":0,"to_port":65535,"cidrs":["*"],"access":"allow","priority":200}]`, false},
		{"narrow source", `[{"protocol":"udp","from_port":53,"to_port":53,"cidrs":["203.0.113.0/24"],"access":"allow","priority":200}]`, false},
		{"fully shadowed by a higher-priority deny",
			`[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["Internet"],"destinations":["*"],"access":"deny","priority":100},` +
				`{"protocol":"udp","from_port":53,"to_port":53,"cidrs":["Internet"],"access":"allow","priority":200}]`, false},
		{"deny covers only part of the allowed range",
			`[{"protocol":"udp","from_port":1000,"to_port":1999,"cidrs":["Internet"],"destinations":["*"],"access":"deny","priority":100},` +
				`{"protocol":"udp","from_port":1000,"to_port":2000,"cidrs":["Internet"],"access":"allow","priority":200}]`, true},
		{"deny after allow does not close it",
			`[{"protocol":"udp","from_port":53,"to_port":53,"cidrs":["Internet"],"access":"allow","priority":100},` +
				`{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["*"],"destinations":["*"],"access":"deny","priority":4000}]`, true},
		{"no custom rules", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, azureNSGUDPOpenInternet.Violates(nsg(tt.ingress)))
		})
	}
}

func TestNSGHTTPOpenInternet(t *testing.T) {
	nsg := func(ingress string) asset.Asset {
		return asset.Asset{Type: "security_group", Provider: asset.ProviderAzure, Metadata: map[string]string{"ingress": ingress}}
	}
	require.True(t, azureNSGHTTPOpenInternet.Violates(nsg(
		`[{"protocol":"tcp","from_port":80,"to_port":80,"cidrs":["Internet"],"destinations":["*"],"access":"deny","priority":100},`+
			`{"protocol":"tcp","from_port":1,"to_port":1024,"cidrs":["Internet"],"access":"allow","priority":200}]`)),
		"80 is denied but 443 still falls through to the allow")
	require.False(t, azureNSGHTTPOpenInternet.Violates(nsg(
		`[{"protocol":"tcp","from_port":8080,"to_port":8080,"cidrs":["Internet"],"access":"allow","priority":100}]`)))
	require.False(t, azureNSGHTTPOpenInternet.Violates(nsg(
		`[{"protocol":"udp","from_port":443,"to_port":443,"cidrs":["Internet"],"access":"allow","priority":100}]`)),
		"QUIC-only rules are UDP, covered by azure-nsg-udp-open-internet")
}

func TestSubnetNoNSG_PlatformSubnetsExempt(t *testing.T) {
	for name, fires := range map[string]bool{
		"app": true, "GatewaySubnet": false, "AzureFirewallSubnet": false,
		"AzureFirewallManagementSubnet": false, "RouteServerSubnet": false,
	} {
		a := asset.Asset{Name: name, Type: "azure_subnet", Provider: asset.ProviderAzure, Metadata: map[string]string{"nsg_id": ""}}
		require.Equal(t, fires, azureSubnetNoNSG.Violates(a), name)
	}
}

func TestStorageNetworkChecks_OneFindingPerAccount(t *testing.T) {
	for _, tt := range []struct {
		access, action        string
		allNetworks, selected bool
	}{
		{"Enabled", "Allow", true, false},
		{"Enabled", "Deny", false, true},
		{"Disabled", "Allow", false, false},
		{"SecuredByPerimeter", "Allow", false, false},
	} {
		a := asset.Asset{Type: "azure_storage_account", Provider: asset.ProviderAzure, Metadata: map[string]string{
			"public_network_access": tt.access, "network_default_action": tt.action,
		}}
		require.Equal(t, tt.allNetworks, azureStorageDefaultNetworkAllow.Violates(a), "%s/%s", tt.access, tt.action)
		require.Equal(t, tt.selected, azureStoragePublicNetworkAccess.Violates(a), "%s/%s", tt.access, tt.action)
	}
}

func TestStorageKeyChecks_StepAsideWhenSharedKeyDisabled(t *testing.T) {
	old := time.Now().Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339)
	a := asset.Asset{Type: "azure_storage_account", Provider: asset.ProviderAzure, Metadata: map[string]string{
		"allow_shared_key_access": "false", "key1_created": old, "key2_created": old, "key_expiration_days": "",
	}}
	require.False(t, azureStorageKeyNotRotated.Violates(a), "a key that cannot authenticate is not a credential")
	require.False(t, azureStorageNoKeyExpiryPolicy.Violates(a))
}

func TestSubscriptionOwnerCount_Grading(t *testing.T) {
	tests := []struct {
		count    string
		fires    bool
		severity finding.Severity
		title    string
	}{
		{"0", true, finding.SeverityLow, "Subscription has fewer than two owners"},
		{"1", true, finding.SeverityLow, "Subscription has fewer than two owners"},
		{"2", false, "", ""},
		{"3", false, "", ""},
		{"4", true, finding.SeverityMedium, "Subscription has more than three owners"},
		{"not-a-number", false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.count, func(t *testing.T) {
			a := asset.Asset{Type: "azure_subscription", Provider: asset.ProviderAzure, Metadata: map[string]string{"owner_count": tt.count}}
			require.Equal(t, tt.fires, azureSubscriptionOwnerCount.Violates(a))
			if tt.fires {
				require.Equal(t, tt.severity, azureSubscriptionOwnerCount.SeverityFor(a))
				require.Equal(t, tt.title, azureSubscriptionOwnerCount.TitleFor(a))
			}
		})
	}
}

// One allow-everything rule is one root cause: the rollup fires and every
// per-port check steps aside. A narrow rule beside it keeps its own finding.
func TestNSGAllPortsRollup_OneFindingPerRule(t *testing.T) {
	all := []Check{azureNSGAllPortsOpenInternet, azureNSGRDPOpenInternet, azureNSGSSHOpenInternet,
		azureNSGWinRMOpenInternet, azureNSGUDPOpenInternet, azureNSGHTTPOpenInternet}
	fired := func(ingress string) []string {
		a := asset.Asset{Type: "security_group", Provider: asset.ProviderAzure, Metadata: map[string]string{"ingress": ingress}}
		var out []string
		for _, c := range all {
			if c.Violates(a) {
				out = append(out, c.ID)
			}
		}
		return out
	}
	tests := []struct {
		name    string
		ingress string
		want    []string
	}{
		{"allow * any port", `[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["Internet"],"access":"allow","priority":100}]`,
			[]string{"azure-nsg-all-ports-open-internet"}},
		{"legacy 0-0 any port", `[{"protocol":"tcp","from_port":0,"to_port":0,"cidrs":["*"],"access":"allow","priority":100}]`,
			[]string{"azure-nsg-all-ports-open-internet"}},
		{"narrow RDP above the wide rule keeps its finding",
			`[{"protocol":"tcp","from_port":3389,"to_port":3389,"cidrs":["*"],"access":"allow","priority":100},` +
				`{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["*"],"access":"allow","priority":200}]`,
			[]string{"azure-nsg-all-ports-open-internet", "azure-nsg-rdp-not-open-internet"}},
		{"wide rule fully shadowed by a deny",
			`[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["*"],"destinations":["*"],"access":"deny","priority":100},` +
				`{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["*"],"access":"allow","priority":200}]`, nil},
		{"wide rule from a private range", `[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["10.0.0.0/8"],"access":"allow","priority":100}]`, nil},
		{"narrow rules only", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["*"],"access":"allow","priority":100}]`,
			[]string{"azure-nsg-ssh-not-open-internet"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, fired(tt.ingress))
		})
	}
}
