package azure

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/stretchr/testify/require"
)

const unregistered = `{"error":{"code":"MissingSubscriptionRegistration","message":"The subscription is not registered to use namespace 'Microsoft.KeyVault'."}}`

func TestReadOnlyARM_UnregisteredProviderListIsEmpty(t *testing.T) {
	o := readOnlyARM()
	f := &fakeREST{responses: map[string]fakeResponse{
		"/subscriptions/s1/providers/Microsoft.KeyVault/vaults":                      {status: http.StatusConflict, body: unregistered},
		"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv": {status: http.StatusConflict, body: unregistered},
		"/subscriptions/s2/providers/Microsoft.KeyVault/vaults":                      {status: http.StatusForbidden, body: `{"error":{"code":"AuthorizationFailed","message":"no"}}`},
	}}
	o.Transport = f
	o.Retry = policy.RetryOptions{MaxRetries: -1}
	ctx := context.Background()

	c, err := armkeyvault.NewVaultsClient("s1", fakeCred{}, o)
	require.NoError(t, err)
	pager := c.NewListBySubscriptionPager(nil)
	page, err := pager.NextPage(ctx)
	require.NoError(t, err, "an unregistered provider is an observed empty listing")
	require.Empty(t, page.Value)
	require.False(t, pager.More())
	_, err = c.Get(ctx, "rg", "kv", nil)
	require.Error(t, err, "a single-resource GET is not rewritten")
	for _, u := range f.seen {
		require.NotContains(t, u, "/register", "the SDK must never register a provider")
	}

	denied, err := armkeyvault.NewVaultsClient("s2", fakeCred{}, o)
	require.NoError(t, err)
	_, err = denied.NewListBySubscriptionPager(nil).NextPage(ctx)
	require.Error(t, err, "other errors stay errors")
}

func TestIsCollectionPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/subscriptions/s/providers/Microsoft.KeyVault/vaults":                                                                      true,
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv":                                                 false,
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv/keys":                                            true,
		"/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv/providers/Microsoft.Insights/diagnosticSettings": true,
		"/subscriptions/s": false,
	} {
		require.Equal(t, want, isCollectionPath(path), path)
	}
}

// armClientNilOptions matches an ARM SDK client constructed with nil options,
// which leaves the SDK's automatic resource-provider registration (a write) on.
var armClientNilOptions = regexp.MustCompile(`arm[a-z]+(/v\d+)?\.New\w*Client\([^)]*,\s*nil\)`)

// TestARMClientsDisableProviderRegistration: every ARM SDK client in the Azure
// collector, the executor and cmd/graph passes options that disable provider
// auto-registration.
func TestARMClientsDisableProviderRegistration(t *testing.T) {
	var files []string
	for _, glob := range []string{"*.go", "../../app/executor/*.go", "../../../cmd/graph/*.go"} {
		m, err := filepath.Glob(glob)
		require.NoError(t, err)
		files = append(files, m...)
	}
	require.NotEmpty(t, files)
	checked := 0
	for _, f := range files {
		if filepath.Ext(f) != ".go" || regexp.MustCompile(`_test\.go$`).MatchString(f) {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		checked++
		require.Empty(t, armClientNilOptions.FindAllString(string(src), -1), "%s: pass readOnlyARM() / DisableRPRegistration", f)
	}
	require.Greater(t, checked, 20)
}
