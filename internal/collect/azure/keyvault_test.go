package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/stretchr/testify/require"
)

func TestKeyVaultAsset_DocumentedDefaults(t *testing.T) {
	// The Vaults - List By Subscription sample response: optional properties
	// omitted, as ARM returns a vault that never set them.
	var l armkeyvault.VaultListResult
	require.NoError(t, json.Unmarshal([]byte(`{"value":[{
		"id":"/subscriptions/s1/resourceGroups/sample-group/providers/Microsoft.KeyVault/vaults/sample-vault",
		"name":"sample-vault","type":"Microsoft.KeyVault/vaults","location":"westus","tags":{},
		"properties":{"sku":{"family":"A","name":"premium"},"tenantId":"00000000-0000-0000-0000-000000000000",
			"accessPolicies":[],"enabledForDeployment":true,"enableSoftDelete":true,
			"vaultUri":"https://sample-vault.vault.azure.net/","provisioningState":"Succeeded"}}]}`), &l))
	md := keyVaultAsset(l.Value[0], "s1", time.Now()).Metadata
	require.Equal(t, "false", md["rbac_authorization"], "documented default: access policies")
	require.Equal(t, "false", md["purge_protection"], "omitted: never enabled")
	require.Equal(t, "true", md["soft_delete"])
	require.Equal(t, "Enabled", md["public_network_access"], "documented default: enabled")
	require.Equal(t, "Allow", md["network_default_action"], "no ACLs: allow all")
	require.Equal(t, "0", md["private_endpoint_count"])

	var hardened armkeyvault.Vault
	require.NoError(t, json.Unmarshal([]byte(`{"id":"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv","name":"kv",
		"properties":{"tenantId":"t","sku":{"family":"A","name":"standard"},"enableRbacAuthorization":true,"enablePurgeProtection":true,
			"publicNetworkAccess":"Disabled","networkAcls":{"defaultAction":"Deny","bypass":"AzureServices"},
			"privateEndpointConnections":[
				{"properties":{"privateLinkServiceConnectionState":{"status":"Approved"}}},
				{"properties":{"privateLinkServiceConnectionState":{"status":"Pending"}}}]}}`), &hardened))
	md = keyVaultAsset(&hardened, "s1", time.Now()).Metadata
	require.Equal(t, "true", md["rbac_authorization"])
	require.Equal(t, "true", md["purge_protection"])
	require.Equal(t, "Disabled", md["public_network_access"])
	require.Equal(t, "Deny", md["network_default_action"])
	require.Equal(t, "1", md["private_endpoint_count"], "only approved connections count")

	require.Empty(t, keyVaultAsset(&armkeyvault.Vault{ID: hardened.ID}, "s1", time.Now()).Metadata, "no properties block records nothing")
}

func keys(t *testing.T, raw string) []*armkeyvault.Key {
	t.Helper()
	var l armkeyvault.KeyListResult
	require.NoError(t, json.Unmarshal([]byte(raw), &l))
	return l.Value
}

func TestKeySettings(t *testing.T) {
	ks := keys(t, `{"value":[
		{"name":"expiring-rotating","properties":{"attributes":{"enabled":true,"exp":1893456000},
			"rotationPolicy":{"lifetimeActions":[{"action":{"type":"rotate"},"trigger":{"timeAfterCreate":"P90D"}}]}}},
		{"name":"no-expiry","properties":{"attributes":{"enabled":true},
			"rotationPolicy":{"lifetimeActions":[{"action":{"type":"notify"},"trigger":{"timeBeforeExpiry":"P30D"}}]}}},
		{"name":"disabled","properties":{"attributes":{"enabled":false}}}]}`)
	md := keySettings(context.Background(), ks, nil)
	require.Equal(t, "1", md["keys_without_expiry_count"])
	require.Equal(t, "no-expiry", md["keys_without_expiry"])
	require.Equal(t, "1", md["keys_without_rotation_count"], "a notify-only policy does not rotate")
	require.Equal(t, "no-expiry", md["keys_without_rotation"])

	bare := keys(t, `{"value":[{"name":"bare","properties":{"attributes":{"enabled":true,"exp":1893456000}}}]}`)
	md = keySettings(context.Background(), bare, nil)
	require.NotContains(t, md, "keys_without_rotation_count", "no ARM policy and no data plane: rotation unknown")
	require.Equal(t, "0", md["keys_without_expiry_count"])

	dataPlane := func(status int, body string) *restClient {
		pl := runtime.NewPipeline("t", "v1.0.0", runtime.PipelineOptions{}, &policy.ClientOptions{
			Transport: &fakeREST{responses: map[string]fakeResponse{"/keys/bare/rotationpolicy": {status: status, body: body}}},
			Retry:     policy.RetryOptions{MaxRetries: -1},
		})
		return &restClient{pl: pl, base: "https://kv.vault.azure.net"}
	}
	md = keySettings(context.Background(), bare, dataPlane(http.StatusOK, `{"id":"x","lifetimeActions":[{"trigger":{"timeAfterCreate":"P90D"},"action":{"type":"Rotate"}}]}`))
	require.Equal(t, "0", md["keys_without_rotation_count"], "the data-plane policy decides when ARM omits it")
	md = keySettings(context.Background(), bare, dataPlane(http.StatusNotFound, `{"error":{"code":"KeyNotFound"}}`))
	require.Equal(t, "1", md["keys_without_rotation_count"], "no policy on the key")
	md = keySettings(context.Background(), bare, dataPlane(http.StatusForbidden, `{"error":{"code":"Forbidden"}}`))
	require.NotContains(t, md, "keys_without_rotation_count", "an unreadable data plane is unknown")

	md = keySettings(context.Background(), nil, nil)
	require.Equal(t, "0", md["keys_without_expiry_count"], "a vault with no keys has none without expiry")
	require.Equal(t, "0", md["keys_without_rotation_count"])
}

func TestSecretSettings(t *testing.T) {
	var l armkeyvault.SecretListResult
	require.NoError(t, json.Unmarshal([]byte(`{"value":[
		{"name":"db-password","properties":{"attributes":{"enabled":true,"nbf":1767225600}}},
		{"name":"api-key","properties":{"attributes":{"enabled":true,"exp":1798761600}}},
		{"name":"old-disabled","properties":{"attributes":{"enabled":false}}}]}`), &l))
	md := secretSettings(l.Value)
	require.Equal(t, "1", md["secrets_without_expiry_count"])
	require.Equal(t, "db-password", md["secrets_without_expiry"])
}

func TestCertificateSettings(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// Data-plane GET /certificates (api 7.4) wire shape.
	page := `{"value":[
		{"id":"https://kv.vault.azure.net/certificates/tls-2y","x5t":"x","attributes":{"enabled":true,"nbf":1767225600,"exp":1830297600,"created":1767225600}},
		{"id":"https://kv.vault.azure.net/certificates/tls-1y","x5t":"x","attributes":{"enabled":true,"nbf":1767225600,"exp":1798761600}},
		{"id":"https://kv.vault.azure.net/certificates/expired-5y","attributes":{"enabled":true,"nbf":1500000000,"exp":1650000000}},
		{"id":"https://kv.vault.azure.net/certificates/off","attributes":{"enabled":false,"nbf":1767225600,"exp":1893456000}}],"nextLink":null}`
	data := func(status int, body string) *restClient {
		pl := runtime.NewPipeline("t", "v1.0.0", runtime.PipelineOptions{}, &policy.ClientOptions{
			Transport: &fakeREST{responses: map[string]fakeResponse{"/certificates": {status: status, body: body}}},
			Retry:     policy.RetryOptions{MaxRetries: -1},
		})
		return &restClient{pl: pl, base: "https://kv.vault.azure.net"}
	}
	certs, err := listAll[vaultCertificate](context.Background(), data(http.StatusOK, page), "/certificates?api-version=7.4", nil)
	require.NoError(t, err)
	md := certificateSettings(certs, now)
	require.Equal(t, "1", md["certs_validity_over_12_months_count"], "expired and disabled certificates are not current")
	require.Equal(t, "tls-2y", md["certs_validity_over_12_months"])

	_, err = listAll[vaultCertificate](context.Background(), data(http.StatusForbidden, `{"error":{"code":"Forbidden"}}`), "/certificates?api-version=7.4", nil)
	require.Error(t, err, "a refused data-plane read is an error (keys absent), never an empty certificate list")
	require.Equal(t, "0", certificateSettings(nil, now)["certs_validity_over_12_months_count"])
}
