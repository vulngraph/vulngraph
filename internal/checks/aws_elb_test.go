package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func lbAsset(md map[string]string) asset.Asset {
	return asset.Asset{ID: "lb", Type: "load_balancer", Provider: asset.ProviderAWS, Metadata: md}
}

func tgAsset(md map[string]string) asset.Asset {
	return asset.Asset{ID: "tg", Type: "lb_target_group", Provider: asset.ProviderAWS, Metadata: md}
}

func TestELBWeakTLSPolicy(t *testing.T) {
	tests := []struct {
		name string
		md   map[string]string
		fire bool
		sev  finding.Severity
	}{
		{"ALB on a recommended policy", map[string]string{"type": "application", "tls_listener_policies": "HTTPS:443=ELBSecurityPolicy-TLS13-1-3-2021-06"}, false, ""},
		{"NLB on a recommended FIPS PQ policy", map[string]string{"type": "network", "tls_listener_policies": "TLS:443=ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09"}, false, ""},
		{"no TLS listener", map[string]string{"type": "application", "tls_listener_policies": ""}, false, ""},
		// The console default for new listeners: TLS 1.2 floor, not on the list.
		{"TLS 1.2 default is Info", map[string]string{"type": "application", "scheme": "internet-facing",
			"tls_listener_policies": "HTTPS:443=ELBSecurityPolicy-TLS13-1-2-2021-06"}, true, finding.SeverityInfo},
		{"TLS 1.0 policy on an internet-facing ALB is Medium", map[string]string{"type": "application", "scheme": "internet-facing",
			"tls_listener_policies": "HTTPS:443=ELBSecurityPolicy-TLS13-1-2-Res-2021-06,HTTPS:8443=ELBSecurityPolicy-2016-08"}, true, finding.SeverityMedium},
		{"TLS 1.1 policy on an internal NLB is Low", map[string]string{"type": "network", "scheme": "internal",
			"tls_listener_policies": "TLS:443=ELBSecurityPolicy-TLS-1-1-2017-01"}, true, finding.SeverityLow},
		{"Classic on the ELB.8 policy", map[string]string{"type": "classic", "tls_listener_policies": "HTTPS:443=ELBSecurityPolicy-TLS-1-2-2017-01"}, false, ""},
		// ELB.8 accepts exactly one policy: an ELBv2 recommended name on a Classic listener does not count.
		{"Classic on an ELBv2 policy name", map[string]string{"type": "classic", "tls_listener_policies": "HTTPS:443=ELBSecurityPolicy-TLS13-1-3-2021-06"}, true, finding.SeverityInfo},
		{"Classic custom policy is graded as unconfirmed", map[string]string{"type": "classic", "scheme": "internet-facing",
			"tls_listener_policies": "SSL:443=custom:mine"}, true, finding.SeverityMedium},
		{"Classic listener with no negotiation policy", map[string]string{"type": "classic", "scheme": "internal",
			"tls_listener_policies": "HTTPS:443="}, true, finding.SeverityLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := lbAsset(tt.md)
			require.Equal(t, tt.fire, awsELBWeakTLSPolicy.Violates(a))
			if tt.fire {
				require.Equal(t, tt.sev, awsELBWeakTLSPolicy.SeverityFor(a))
			}
		})
	}
}

func TestELBTransportSeverity(t *testing.T) {
	public := map[string]string{"type": "application", "scheme": "internet-facing", "http_listeners_without_https_redirect": "80"}
	require.Equal(t, finding.SeverityMedium, awsELBHTTPNoHTTPSRedirect.SeverityFor(lbAsset(public)))
	public["scheme"] = "internal"
	require.Equal(t, finding.SeverityLow, awsELBHTTPNoHTTPSRedirect.SeverityFor(lbAsset(public)))

	classicHTTP := lbAsset(map[string]string{"type": "classic", "scheme": "internet-facing", "plaintext_listeners": "HTTP:80,TCP:22"})
	require.True(t, awsELBPlaintextListener.Violates(classicHTTP))
	require.Equal(t, finding.SeverityMedium, awsELBPlaintextListener.SeverityFor(classicHTTP))
	// TCP may be TLS passthrough: Low even when public.
	nlbTCP := lbAsset(map[string]string{"type": "network", "scheme": "internet-facing", "plaintext_listeners": "TCP:443"})
	require.Equal(t, finding.SeverityLow, awsELBPlaintextListener.SeverityFor(nlbTCP))
}

// One root cause, one finding: an ALB HTTP listener is the redirect check's,
// and a redirect-only HTTP listener is reported by neither.
func TestELBListenerChecksDoNotOverlap(t *testing.T) {
	redirectOnly := lbAsset(map[string]string{"type": "application", "plaintext_listeners": "HTTP:80", "http_listeners_without_https_redirect": ""})
	require.False(t, awsELBPlaintextListener.Violates(redirectOnly), "ELB.18's ALB half is folded into the redirect check")
	require.False(t, awsELBHTTPNoHTTPSRedirect.Violates(redirectOnly))

	forwards := lbAsset(map[string]string{"type": "application", "plaintext_listeners": "HTTP:80", "http_listeners_without_https_redirect": "80"})
	require.True(t, awsELBHTTPNoHTTPSRedirect.Violates(forwards))
	require.False(t, awsELBPlaintextListener.Violates(forwards))

	// Network/Classic balancers have no redirect verdict; the redirect check never applies to them.
	require.False(t, awsELBHTTPNoHTTPSRedirect.Violates(lbAsset(map[string]string{"type": "network", "http_listeners_without_https_redirect": "80"})))
}

func TestELBDesyncAndInvalidHeaderStepAside(t *testing.T) {
	monitor := lbAsset(map[string]string{"type": "application", "desync_mitigation_mode": "monitor", "drop_invalid_header_fields": "false"})
	require.True(t, awsELBDesyncMitigationWeak.Violates(monitor))
	require.False(t, awsELBInvalidHeadersAllowed.Violates(monitor), "a monitor-mode balancer is reported once, by the desync check")

	defensive := lbAsset(map[string]string{"type": "application", "desync_mitigation_mode": "defensive", "drop_invalid_header_fields": "false"})
	require.False(t, awsELBDesyncMitigationWeak.Violates(defensive))
	require.True(t, awsELBInvalidHeadersAllowed.Violates(defensive))

	strictest := lbAsset(map[string]string{"type": "classic", "desync_mitigation_mode": "strictest"})
	require.False(t, awsELBDesyncMitigationWeak.Violates(strictest))
	// NLBs have no HTTP desync setting.
	require.False(t, awsELBDesyncMitigationWeak.Violates(lbAsset(map[string]string{"type": "network", "desync_mitigation_mode": "monitor"})))
}

func TestELBAttributeChecksScopeByType(t *testing.T) {
	for _, typ := range []string{"application", "network", "gateway"} {
		require.True(t, awsELBNoDeletionProtection.Violates(lbAsset(map[string]string{"type": typ, "deletion_protection": "false"})), typ)
	}
	require.False(t, awsELBNoDeletionProtection.Violates(lbAsset(map[string]string{"type": "classic", "deletion_protection": "false"})))
	require.False(t, awsELBClassicCrossZoneDisabled.Violates(lbAsset(map[string]string{"type": "network", "cross_zone_load_balancing": "false"})))
	require.False(t, awsELBClassicConnectionDraining.Violates(lbAsset(map[string]string{"type": "application", "connection_draining": "false"})))
}

func TestELBTargetGroupChecks(t *testing.T) {
	tests := []struct {
		name               string
		md                 map[string]string
		unencrypted, hcFin bool
	}{
		{"HTTP group: one finding, the traffic one", map[string]string{"target_type": "instance", "protocol": "HTTP", "health_check_protocol": "HTTP"}, true, false},
		{"TLS group with a TCP health check", map[string]string{"target_type": "ip", "protocol": "TLS", "health_check_protocol": "TCP"}, false, true},
		{"HTTPS group, HTTPS health check", map[string]string{"target_type": "instance", "protocol": "HTTPS", "health_check_protocol": "HTTPS"}, false, false},
		{"QUIC group", map[string]string{"target_type": "instance", "protocol": "QUIC", "health_check_protocol": "HTTPS"}, false, false},
		{"Lambda group is out of scope", map[string]string{"target_type": "lambda", "protocol": ""}, false, false},
		// ELB.22 excludes ALB-type groups; ELB.21 still grades their health check.
		{"ALB-type group", map[string]string{"target_type": "alb", "protocol": "TCP", "health_check_protocol": "HTTP"}, false, true},
		// GENEVE (Gateway LB) is outside ELB.22; its health check is not.
		{"GENEVE group", map[string]string{"target_type": "instance", "protocol": "GENEVE", "health_check_protocol": "TCP"}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tgAsset(tt.md)
			require.Equal(t, tt.unencrypted, awsELBTargetGroupUnencrypted.Violates(a))
			require.Equal(t, tt.hcFin, awsELBTargetGroupHealthCheckUnencrypted.Violates(a))
		})
	}
}

// An unread balancer must hold its findings open rather than close them as fixed.
func TestELBChecksNotEvaluableWithoutTheirKeys(t *testing.T) {
	r := Default()
	for _, id := range []string{"aws-elb-weak-tls-policy", "aws-elb-http-no-https-redirect", "aws-elb-no-deletion-protection",
		"aws-elb-alb-invalid-headers-allowed", "aws-elb-desync-mitigation-weak"} {
		c, ok := r.ByID(id)
		require.True(t, ok, id)
		require.False(t, c.Evaluable(lbAsset(map[string]string{"type": "application"})), id)
	}
	c, _ := r.ByID("aws-elb-weak-tls-policy")
	require.True(t, c.Evaluable(lbAsset(map[string]string{"type": "application", "tls_listener_policies": ""})))
}
