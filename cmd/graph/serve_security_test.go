package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecurityConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	ctx := context.Background()

	cfg, err := securityConfigFromEnv(ctx, env(nil), ":8080", false)
	require.NoError(t, err)
	require.Empty(t, cfg.AllowedHosts, "no host allowlist without BYPASS_AUTH")
	require.False(t, cfg.TLSProxy)

	cfg, err = securityConfigFromEnv(ctx, env(map[string]string{
		"ALLOWED_ORIGINS": "https://ui.example.com, https://b.example.com",
		"TLS_PROXY":       "true",
	}), ":8080", false)
	require.NoError(t, err)
	require.Equal(t, []string{"https://ui.example.com", "https://b.example.com"}, cfg.AllowedOrigins)
	require.True(t, cfg.TLSProxy)

	_, err = securityConfigFromEnv(ctx, env(map[string]string{"ALLOWED_ORIGINS": "not a url/path"}), ":8080", false)
	require.Error(t, err)

	cfg, err = securityConfigFromEnv(ctx, env(map[string]string{"BYPASS_AUTH_ALLOWED_HOSTS": "graph.corp"}), "10.1.2.3:8080", true)
	require.NoError(t, err)
	require.Equal(t, []string{"localhost", "127.0.0.1", "::1", "10.1.2.3", "graph.corp"}, cfg.AllowedHosts)

	cfg, err = securityConfigFromEnv(ctx, env(nil), ":8080", true)
	require.NoError(t, err)
	require.Equal(t, []string{"localhost", "127.0.0.1", "::1"}, cfg.AllowedHosts, "a wildcard ADDR adds no host")
}

// An approval handoff is refused unsigned unless that is said out loud.
func TestApprovalWebhookFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	ctx := context.Background()

	n, err := approvalWebhookFromEnv(ctx, env(nil))
	require.NoError(t, err)
	require.Nil(t, n, "no URL, no notifier")

	_, err = approvalWebhookFromEnv(ctx, env(map[string]string{"APPROVAL_WEBHOOK_URL": "https://hooks.example.com/a"}))
	require.ErrorContains(t, err, "APPROVAL_WEBHOOK_SECRET")

	n, err = approvalWebhookFromEnv(ctx, env(map[string]string{"APPROVAL_WEBHOOK_URL": "https://hooks.example.com/a",
		"APPROVAL_WEBHOOK_ALLOW_UNSIGNED": "true"}))
	require.NoError(t, err)
	require.NotNil(t, n)

	n, err = approvalWebhookFromEnv(ctx, env(map[string]string{"APPROVAL_WEBHOOK_URL": "https://hooks.example.com/a",
		"APPROVAL_WEBHOOK_SECRET": "whsec"}))
	require.NoError(t, err)
	require.NotNil(t, n)
}
