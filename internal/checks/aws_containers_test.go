package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// A repository scanned by a registry-level rule (enhanced or basic) is
// scanned; under ENHANCED scanning the repository's own scanOnPush is ignored
// by AWS, so it cannot make an unmatched repository scanned.
func TestECRScanningDisabledHonoursRegistryScanning(t *testing.T) {
	build := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "ecr_repository", Provider: asset.ProviderAWS, Metadata: md}
	}
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"registry continuous scan", map[string]string{"scan_on_push": "false", "registry_scan_type": "ENHANCED", "registry_scan_rule": "CONTINUOUS_SCAN"}, false},
		{"basic registry rule", map[string]string{"scan_on_push": "false", "registry_scan_type": "BASIC", "registry_scan_rule": "SCAN_ON_PUSH"}, false},
		{"basic, repo scan on push", map[string]string{"scan_on_push": "true", "registry_scan_type": "BASIC", "registry_scan_rule": "none"}, false},
		{"basic, nothing scans", map[string]string{"scan_on_push": "false", "registry_scan_type": "BASIC", "registry_scan_rule": "none"}, true},
		{"enhanced ignores repo flag", map[string]string{"scan_on_push": "true", "registry_scan_type": "ENHANCED", "registry_scan_rule": "none"}, true},
		{"registry unread", map[string]string{"scan_on_push": "false"}, false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, awsECRScanningDisabled.Violates(build(tt.md)), tt.name)
	}
	require.False(t, registered(t, awsECRScanningDisabled.ID).Evaluable(build(map[string]string{"scan_on_push": "false"})),
		"an unread registry configuration must not close a finding as fixed")
}

// A public endpoint restricted to corporate CIDRs is the remediation the
// check's own text recommends; it must not keep firing.
func TestEKSPublicEndpointHonoursRestrictedCIDRs(t *testing.T) {
	build := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "eks_cluster", Provider: asset.ProviderAWS, Metadata: md}
	}
	require.True(t, awsEKSPublicEndpoint.Violates(build(map[string]string{"endpoint_public_access": "true", "public_access_cidrs": "0.0.0.0/0"})))
	require.True(t, awsEKSPublicEndpoint.Violates(build(map[string]string{"endpoint_public_access": "true", "public_access_cidrs": "10.0.0.0/8, ::/0"})))
	require.False(t, awsEKSPublicEndpoint.Violates(build(map[string]string{"endpoint_public_access": "true", "public_access_cidrs": "203.0.113.0/24,198.51.100.4/32"})))
	require.False(t, awsEKSPublicEndpoint.Violates(build(map[string]string{"endpoint_public_access": "false", "public_access_cidrs": "0.0.0.0/0"})))
	// The allowlist was not reported: unknown, never a finding.
	require.False(t, awsEKSPublicEndpoint.Violates(build(map[string]string{"endpoint_public_access": "true"})))
}
