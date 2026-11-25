package main

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/apikey"
	"github.com/vulngraph/vulngraph/internal/app/auth"
)

func TestEnvRate(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	require.Equal(t, 7.0, envRate(env(""), "K", 7), "unset takes the default")
	require.Equal(t, 7.0, envRate(env("nope"), "K", 7), "malformed takes the default")
	require.Equal(t, 7.0, envRate(env("-3"), "K", 7), "negative takes the default")
	require.Equal(t, 0.0, envRate(env("0"), "K", 7), "0 explicitly disables")
	require.Equal(t, 2.5, envRate(env(" 2.5 "), "K", 7))
}

// Configurations that would leave a credential path forgeable stop serve
// rather than log a warning nobody reads.
func TestNewAuthHandler_RefusesForgeableConfig(t *testing.T) {
	secret := strings.Repeat("s", minProxySecretLen)
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"defaults", map[string]string{}, ""},
		{"oauth2-proxy with no verification", map[string]string{"OAUTH2_PROXY": "true", "OAUTH2_PROXY_ALLOWED_DOMAINS": "corp.example"}, "OAUTH2_PROXY_OIDC_ISSUER"},
		{"oauth2-proxy with a short secret", map[string]string{"OAUTH2_PROXY": "true", "OAUTH2_PROXY_SHARED_SECRET": "short"}, "OAUTH2_PROXY_SHARED_SECRET"},
		{"oauth2-proxy with a secret", map[string]string{"OAUTH2_PROXY": "true", "OAUTH2_PROXY_SHARED_SECRET": secret}, ""},
		{"oauth2-proxy with an issuer but no audience", map[string]string{"OAUTH2_PROXY": "true", "OAUTH2_PROXY_OIDC_ISSUER": "https://idp.example"}, "OAUTH2_PROXY_OIDC_AUDIENCE"},
		{"oauth2-proxy with ID-token verification only", map[string]string{"OAUTH2_PROXY": "true", "OAUTH2_PROXY_OIDC_ISSUER": "https://idp.example", "OAUTH2_PROXY_OIDC_AUDIENCE": "client"}, ""},
		{"oauth2-proxy with a plain-http issuer", map[string]string{"OAUTH2_PROXY": "true", "OAUTH2_PROXY_OIDC_ISSUER": "http://idp.example", "OAUTH2_PROXY_OIDC_AUDIENCE": "client"}, "https"},
		{"malformed trusted proxies", map[string]string{"CLIENT_IP_HEADER": "X-Forwarded-For", "TRUSTED_PROXY_CIDRS": "10.0.0/8"}, "TRUSTED_PROXY_CIDRS"},
		{"client-ip header with trusted proxies", map[string]string{"CLIENT_IP_HEADER": "X-Forwarded-For", "TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}, ""},
		{"google without a redirect URL", map[string]string{"GOOGLE_CLIENT_ID": "id", "GOOGLE_ALLOWED_DOMAINS": "corp.example"}, "GOOGLE_REDIRECT_URL"},
		{"google with a redirect URL", map[string]string{"GOOGLE_CLIENT_ID": "id", "GOOGLE_ALLOWED_DOMAINS": "corp.example", "GOOGLE_REDIRECT_URL": "https://graph.corp.example/api/auth/google/callback"}, ""},
		{"google with host derivation for dev", map[string]string{"GOOGLE_CLIENT_ID": "id", "GOOGLE_ALLOWED_DOMAINS": "corp.example", "OAUTH_REDIRECT_FROM_HOST": "true"}, ""},
		{"okta without a redirect URL", map[string]string{"OKTA_CLIENT_ID": "id", "OKTA_DOMAIN": "corp.okta.com", "OKTA_ALLOWED_DOMAINS": "corp.example"}, "OKTA_REDIRECT_URL"},
		{"okta with a relative redirect URL", map[string]string{"OKTA_CLIENT_ID": "id", "OKTA_DOMAIN": "corp.okta.com", "OKTA_ALLOWED_DOMAINS": "corp.example", "OKTA_REDIRECT_URL": "/api/auth/okta/callback"}, "OKTA_REDIRECT_URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newAuthHandler(context.Background(), func(k string) string { return tc.env[k] },
				auth.NewService(nil), apikey.NewService(nil), false)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
