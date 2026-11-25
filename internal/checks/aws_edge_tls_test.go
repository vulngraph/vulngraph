package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func edgeAsset(typ string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "id", Type: typ, Provider: asset.ProviderAWS, Metadata: md}
}

func TestAWSEdgeTLSChecks(t *testing.T) {
	const (
		pq    = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
		fips  = "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04"
		plain = "ELBSecurityPolicy-2016-08"
	)
	tests := []struct {
		name  string
		check Check
		a     asset.Asset
		fires bool
	}{
		{"lambda url with NONE auth", awsLambdaFunctionURLNoIAM, edgeAsset("lambda_function", map[string]string{"url_auth_type": "NONE"}), true},
		{"lambda url with AWS_IAM auth", awsLambdaFunctionURLNoIAM, edgeAsset("lambda_function", map[string]string{"url_auth_type": "AWS_IAM"}), false},
		{"lambda without url", awsLambdaFunctionURLNoIAM, edgeAsset("lambda_function", map[string]string{}), false},

		{"eks private access off", awsEKSNoPrivateEndpoint, edgeAsset("eks_cluster", map[string]string{"endpoint_private_access": "false"}), true},
		{"eks private access on", awsEKSNoPrivateEndpoint, edgeAsset("eks_cluster", map[string]string{"endpoint_private_access": "true"}), false},
		{"eks private access unread", awsEKSNoPrivateEndpoint, edgeAsset("eks_cluster", map[string]string{}), false},

		{"cloudfront default certificate", awsCloudFrontNoPQCTLS, edgeAsset(cloudfrontAsset, map[string]string{"default_certificate": "true"}), true},
		{"cloudfront TLS 1.2 policy", awsCloudFrontNoPQCTLS, edgeAsset(cloudfrontAsset, map[string]string{"default_certificate": "false", "minimum_protocol_version": "TLSv1.2_2021"}), true},
		{"cloudfront TLS 1.3 policy", awsCloudFrontNoPQCTLS, edgeAsset(cloudfrontAsset, map[string]string{"default_certificate": "false", "minimum_protocol_version": "TLSv1.3_2025"}), false},
		{"cloudfront custom certificate with no policy read", awsCloudFrontNoPQCTLS, edgeAsset(cloudfrontAsset, map[string]string{"default_certificate": "false"}), false},
		{"cloudfront nothing read", awsCloudFrontNoPQCTLS, edgeAsset(cloudfrontAsset, map[string]string{}), false},

		{"alb non-FIPS policy", awsELBv2ListenerNoFIPS, lbAsset(map[string]string{"type": "application", "tls_listener_policies": "HTTPS:443=" + plain}), true},
		{"alb one of two listeners non-FIPS", awsELBv2ListenerNoFIPS, lbAsset(map[string]string{"type": "application", "tls_listener_policies": "HTTPS:443=" + fips + ",HTTPS:8443=" + plain}), true},
		{"alb FIPS policy", awsELBv2ListenerNoFIPS, lbAsset(map[string]string{"type": "application", "tls_listener_policies": "HTTPS:443=" + fips}), false},
		{"nlb listener with no policy", awsELBv2ListenerNoFIPS, lbAsset(map[string]string{"type": "network", "tls_listener_policies": "TLS:443="}), true},
		{"alb no TLS listener", awsELBv2ListenerNoFIPS, lbAsset(map[string]string{"type": "application", "tls_listener_policies": ""}), false},
		{"classic balancer out of scope", awsELBv2ListenerNoFIPS, lbAsset(map[string]string{"type": "classic", "tls_listener_policies": "HTTPS:443=" + plain}), false},
		{"fips key unread", awsELBv2ListenerNoFIPS, lbAsset(map[string]string{"type": "application"}), false},

		{"alb non-PQ policy", awsELBv2ListenerNoPQC, lbAsset(map[string]string{"type": "application", "tls_listener_policies": "HTTPS:443=" + fips}), true},
		{"alb PQ policy", awsELBv2ListenerNoPQC, lbAsset(map[string]string{"type": "application", "tls_listener_policies": "HTTPS:443=" + pq}), false},
		{"nlb one of two listeners non-PQ", awsELBv2ListenerNoPQC, lbAsset(map[string]string{"type": "network", "tls_listener_policies": "TLS:443=" + pq + ",TLS:8443=" + plain}), true},
		{"alb no TLS listener for pq", awsELBv2ListenerNoPQC, lbAsset(map[string]string{"type": "application", "tls_listener_policies": ""}), false},
		{"classic balancer out of scope for pq", awsELBv2ListenerNoPQC, lbAsset(map[string]string{"type": "classic", "tls_listener_policies": "HTTPS:443=" + plain}), false},
		{"pq key unread", awsELBv2ListenerNoPQC, lbAsset(map[string]string{"type": "network"}), false},

		{"alb with no listeners", awsELBv2NoListeners, lbAsset(map[string]string{"type": "application", "listener_count": "0"}), true},
		{"gwlb with no listeners", awsELBv2NoListeners, lbAsset(map[string]string{"type": "gateway", "listener_count": "0"}), true},
		{"alb with a listener", awsELBv2NoListeners, lbAsset(map[string]string{"type": "application", "listener_count": "1"}), false},
		{"classic balancer with no listeners", awsELBv2NoListeners, lbAsset(map[string]string{"type": "classic", "listener_count": "0"}), false},
		{"listener count unread", awsELBv2NoListeners, lbAsset(map[string]string{"type": "application"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, tt.check.Violates(tt.a))
		})
	}
}

func TestIsFIPSPolicyMatchesWholeToken(t *testing.T) {
	require.True(t, isFIPSPolicy("ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09"))
	require.False(t, isFIPSPolicy("ELBSecurityPolicy-TLS13-1-2-Res-2021-06"))
	require.False(t, isFIPSPolicy("ELBSecurityPolicy-NOTFIPSY-2021"))
	require.False(t, isFIPSPolicy(""))
}

func TestLambdaFunctionURLNoIAMClosesWhenURLRemoved(t *testing.T) {
	c, ok := Default().ByID(awsLambdaFunctionURLNoIAM.ID)
	if !ok {
		t.Fatal("check not registered")
	}
	removed := edgeAsset("lambda_function", map[string]string{"url_auth_type": ""})
	if c.Violates(removed) || !c.Evaluable(removed) {
		t.Fatal("a function with no URL must be evaluable and compliant so the open finding closes")
	}
	if c.Evaluable(edgeAsset("lambda_function", map[string]string{})) {
		t.Fatal("an unread function URL must not close the finding")
	}
}
