package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsSvcAsset(typ string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "r", Type: typ, Provider: asset.ProviderAWS, Metadata: md}
}

// One API, one root cause: once the route read proves routes with no
// authorization, the reachability finding steps aside for the route finding.
func TestAPIGatewayPublicEndpointStepsAsideForUnauthenticatedRoutes(t *testing.T) {
	open := awsSvcAsset("api_gateway", map[string]string{"public": "true", "unauthenticated_routes": "$default"})
	require.True(t, awsAPIGatewayV2RouteNoAuthorization.Violates(open))
	require.False(t, awsAPIGatewayPublic.Violates(open))

	for name, md := range map[string]map[string]string{
		"REST API (routes never read)":  {"public": "true", "api_type": "REST"},
		"v2 API, routes all authorized": {"public": "true", "unauthenticated_routes": ""},
		"v2 API, route read failed":     {"public": "true"},
	} {
		a := awsSvcAsset("api_gateway", md)
		require.True(t, awsAPIGatewayPublic.Violates(a), name)
		require.False(t, awsAPIGatewayV2RouteNoAuthorization.Violates(a), name)
	}
	require.Equal(t, finding.SeverityMedium, awsAPIGatewayV2RouteNoAuthorization.Severity, "the AWS FSBP APIGateway.8 grade")

	// Default endpoint disabled and no custom domain mapped: no URL answers,
	// so neither reachability nor open routes are reported.
	unreachable := awsSvcAsset("api_gateway", map[string]string{"public": "false", "custom_domain_mapped": "false", "unauthenticated_routes": "$default"})
	require.False(t, awsAPIGatewayPublic.Violates(unreachable))
	require.False(t, awsAPIGatewayV2RouteNoAuthorization.Violates(unreachable))
}

// The REST-only stage checks must not grade HTTP or WebSocket stages, which
// have no client certificate, X-Ray, WAF or cache setting to set.
func TestAPIGatewayRESTStageChecksSkipV2Stages(t *testing.T) {
	v2 := awsSvcAsset("api_gateway_stage", map[string]string{
		"api_type": "HTTP", "client_certificate_id": "", "tracing_enabled": "false", "waf_web_acl_arn": "",
		"cache_cluster_enabled": "true", "cache_unencrypted_methods": "*/*",
	})
	for _, c := range []Check{awsAPIGatewayStageNoClientCertificate, awsAPIGatewayStageXRayDisabled, awsAPIGatewayStageNoWAF, awsAPIGatewayStageCacheUnencrypted} {
		require.False(t, c.Violates(v2), c.ID)
	}
	// Caching methods without a cache cluster cache nothing.
	require.False(t, awsAPIGatewayStageCacheUnencrypted.Violates(awsSvcAsset("api_gateway_stage", map[string]string{
		"api_type": "REST", "cache_cluster_enabled": "false", "cache_unencrypted_methods": "*/*",
	})))
}

func TestAPIGatewayDomainTLSPolicyGrades(t *testing.T) {
	tests := []struct {
		policy string
		fires  bool
		sev    finding.Severity
	}{
		{"TLS_1_0", true, finding.SeverityMedium},
		{"TLS_1_2", true, finding.SeverityLow},
		{"SecurityPolicy_TLS13_1_2_2021_06", true, finding.SeverityLow},
		{"SecurityPolicy_TLS13_1_3_2025_09", false, ""},
		{"SecurityPolicy_TLS13_1_3_FIPS_2025_09", false, ""},
		{"SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09", false, ""},
		{"SecurityPolicy_TLS13_2025_EDGE", false, ""},
		{"SecurityPolicy_TLS12_PFS_2025_EDGE", false, ""},
	}
	for _, tt := range tests {
		a := awsSvcAsset("api_gateway_domain", map[string]string{"security_policy": tt.policy})
		require.Equal(t, tt.fires, awsAPIGatewayDomainWeakTLSPolicy.Violates(a), tt.policy)
		if tt.fires {
			require.Equal(t, tt.sev, awsAPIGatewayDomainWeakTLSPolicy.SeverityFor(a), tt.policy)
		}
	}
}

func TestNetworkFirewallStatelessDefaultActions(t *testing.T) {
	tests := []struct {
		actions string
		fires   bool
	}{
		{"aws:pass", true},
		{"MyCustomMetric,aws:pass", true}, // a custom action rides alongside the standard one
		{"aws:drop", false},
		{"aws:forward_to_sfe", false},
		{"MyCustomMetric,aws:forward_to_sfe", false},
		{"aws:passthrough", false}, // whole-token match only
	}
	for _, tt := range tests {
		a := awsSvcAsset("network_firewall_policy", map[string]string{
			"stateless_default_actions": tt.actions, "stateless_fragment_default_actions": tt.actions,
		})
		require.Equal(t, tt.fires, awsNetworkFirewallPolicyStatelessDefaultPass.Violates(a), tt.actions)
		require.Equal(t, tt.fires, awsNetworkFirewallPolicyFragmentDefaultPass.Violates(a), tt.actions)
	}
	// A policy with only stateless groups still has a rule group.
	require.False(t, awsNetworkFirewallPolicyNoRuleGroups.Violates(awsSvcAsset("network_firewall_policy",
		map[string]string{"stateful_rule_group_count": "0", "stateless_rule_group_count": "2"})))
}

func TestRoute53QueryLoggingGradesPublicZonesOnly(t *testing.T) {
	require.False(t, awsRoute53ZoneQueryLoggingDisabled.Violates(awsSvcAsset("dns_zone",
		map[string]string{"private_zone": "true", "query_logging": "false"})), "private zones are not graded")
	gcp := asset.Asset{Type: "dns_zone", Provider: asset.ProviderGCP}
	require.False(t, awsRoute53ZoneQueryLoggingDisabled.AppliesTo(gcp), "GCP dns_zone assets are not Route 53 zones")
}

func TestSSMAutomationLoggingAcceptsOnlyCloudWatch(t *testing.T) {
	require.True(t, awsSSMAutomationLoggingDisabled.Violates(awsSvcAsset("aws_region_settings",
		map[string]string{"ssm_automation_log_destination": "None"})))
	require.False(t, awsSSMAutomationLoggingDisabled.Violates(awsSvcAsset("aws_region_settings",
		map[string]string{"ssm_automation_log_destination": "CloudWatch"})))
}
