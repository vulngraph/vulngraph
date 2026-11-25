package main

import (
	"context"
	"fmt"
	"net"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/httpsrv"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// bypassDefaultHosts are always accepted under BYPASS_AUTH: a browser on the
// operator's machine reaching a port-forward or local run.
var bypassDefaultHosts = []string{"localhost", "127.0.0.1", "::1"}

// securityConfigFromEnv builds the request-hardening config:
//
//   - ALLOWED_ORIGINS: comma-separated extra origins trusted for state-changing
//     /api requests (same-origin never needs listing);
//   - TLS_PROXY=true: TLS terminates at a proxy, so send HSTS on plain-HTTP hops;
//   - LLM_RATE_LIMIT_PER_USER: LLM-backed calls per user per minute (0 disables);
//   - ALERT_CONTEXT_RATE_LIMIT_PER_USER: alert-context lookups per user per
//     minute, REST and MCP (0 disables);
//   - CYPHER_RATE_LIMIT_PER_USER: caller-Cypher calls per user per minute, REST and
//     MCP run_cypher (0 disables);
//   - BYPASS_AUTH_ALLOWED_HOSTS: under BYPASS_AUTH, extra Host values accepted on
//     top of localhost/127.0.0.1/::1 and the ADDR host. Without a Host allowlist
//     a DNS-rebinding page in the operator's browser can drive the
//     unauthenticated admin API.
func securityConfigFromEnv(ctx context.Context, getenv func(string) string, addr string, bypass bool) (httpsrv.SecurityConfig, error) {
	llmPerUser := envRate(getenv, "LLM_RATE_LIMIT_PER_USER", auth.DefaultLLMPerUserPerMinute)
	alertPerUser := envRate(getenv, "ALERT_CONTEXT_RATE_LIMIT_PER_USER", httpsrv.DefaultAlertContextPerUserPerMinute)
	cypherPerUser := envRate(getenv, "CYPHER_RATE_LIMIT_PER_USER", httpsrv.DefaultCypherPerUserPerMinute)
	cfg := httpsrv.SecurityConfig{
		AllowedOrigins:      splitCSV(getenv("ALLOWED_ORIGINS")),
		TLSProxy:            getenv("TLS_PROXY") == "true",
		LLMLimiter:          auth.NewKeyedLimiter(llmPerUser, max(int(llmPerUser), 1)),
		AlertContextLimiter: auth.NewKeyedLimiter(alertPerUser, max(int(alertPerUser), 1)),
		CypherLimiter:       auth.NewKeyedLimiter(cypherPerUser, max(int(cypherPerUser), 1)),
	}
	if err := cfg.Validate(); err != nil {
		return httpsrv.SecurityConfig{}, fmt.Errorf("ALLOWED_ORIGINS: %w", err)
	}
	if bypass {
		hosts := append([]string{}, bypassDefaultHosts...)
		if host, _, err := net.SplitHostPort(addr); err == nil && host != "" && host != "0.0.0.0" && host != "::" {
			hosts = append(hosts, host)
		}
		hosts = append(hosts, splitCSV(getenv("BYPASS_AUTH_ALLOWED_HOSTS"))...)
		cfg.AllowedHosts = hosts
		log.FromContext(ctx).Warn().Strs("allowed_hosts", hosts).Msg(
			"BYPASS_AUTH: requests whose Host is not listed are rejected (DNS-rebinding guard); " +
				"add the proxy-facing hostname to BYPASS_AUTH_ALLOWED_HOSTS")
	}
	return cfg, nil
}

// approvalWebhookFromEnv builds the APPROVAL_WEBHOOK_URL notifier, or nil
// when it is unset. Each POST is signed with APPROVAL_WEBHOOK_SECRET (the
// decision webhook's scheme, its own key: the two receivers are often
// different systems, and one leaked key must not forge the other's posts). A
// receiver may act on "a human approved this", so an unsigned approval is a
// startup error unless APPROVAL_WEBHOOK_ALLOW_UNSIGNED=true says the receiver
// authenticates some other way.
func approvalWebhookFromEnv(ctx context.Context, getenv func(string) string) (*govern.HTTPApprovalNotifier, error) {
	url := getenv("APPROVAL_WEBHOOK_URL")
	if url == "" {
		return nil, nil
	}
	secret := getenv("APPROVAL_WEBHOOK_SECRET")
	if secret == "" {
		if getenv("APPROVAL_WEBHOOK_ALLOW_UNSIGNED") != "true" {
			return nil, fmt.Errorf("APPROVAL_WEBHOOK_URL is set without APPROVAL_WEBHOOK_SECRET; " +
				"set the secret, or APPROVAL_WEBHOOK_ALLOW_UNSIGNED=true to send unsigned approvals")
		}
		log.FromContext(ctx).Warn().Msg("SECURITY: APPROVAL_WEBHOOK_ALLOW_UNSIGNED=true — approval webhooks are sent " +
			"UNSIGNED and the receiver cannot tell them from forgeries")
	}
	return govern.NewHTTPApprovalNotifier(url, secret), nil
}
