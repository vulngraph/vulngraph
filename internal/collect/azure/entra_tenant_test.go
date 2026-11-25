package azure

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/require"
)

type jwtCred struct{ token string }

func (c jwtCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: c.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func jwtWith(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(claims)) + ".sig"
}

func TestTenantSettingsKey_PerTenantAndApp(t *testing.T) {
	ctx := context.Background()
	id, err := resolveAppID(ctx, jwtCred{token: jwtWith(`{"appid":"wi-app"}`)}, map[string]string{"client_id": "sp-app"})
	require.NoError(t, err)
	require.Equal(t, "sp-app", id, "the configured client_id wins")
	id, err = resolveAppID(ctx, jwtCred{token: jwtWith(`{"appid":"wi-app","tid":"t"}`)}, map[string]string{})
	require.NoError(t, err)
	require.Equal(t, "wi-app", id, "ambient credentials: the token's appid")
	id, err = resolveAppID(ctx, jwtCred{token: jwtWith(`{"azp":"v2-app"}`)}, nil)
	require.NoError(t, err)
	require.Equal(t, "v2-app", id)
	_, err = resolveAppID(ctx, jwtCred{token: "not-a-jwt"}, nil)
	require.Error(t, err, "no app identity: no tenant asset rather than a shared, contended one")

	key := tenantSettingsKey("Tenant-1", "App-A")
	require.Equal(t, "azure-tenant:tenant-1:app-a", key)
	require.NotEqual(t, key, tenantSettingsKey("tenant-1", "app-b"), "connectors on different apps (different consent) never share an asset")

	a := newSettingsAsset().tenantAsset(key, "tenant-1", time.Now())
	require.Equal(t, key, a.ID)
	require.Equal(t, key, a.AccountID, "the account is the tenant+app key, so a purge can remove exactly this asset")
}
