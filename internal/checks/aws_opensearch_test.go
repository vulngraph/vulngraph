package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestAwsOpenSearchChecksNeverFireOnAbsentData(t *testing.T) {
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "aws-opensearch-domain-public", check: awsOpenSearchDomainPublic,
			violating: map[string]string{"in_vpc": "false"},
			compliant: map[string]string{"in_vpc": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-opensearch-not-encrypted-at-rest", check: awsOpenSearchNotEncryptedAtRest,
			violating: map[string]string{"encryption_at_rest": "false"},
			compliant: map[string]string{"encryption_at_rest": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-opensearch-no-node-to-node-encryption", check: awsOpenSearchNoNodeToNodeEncryption,
			violating: map[string]string{"node_to_node_encryption": "false"},
			compliant: map[string]string{"node_to_node_encryption": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-opensearch-error-logs-disabled", check: awsOpenSearchErrorLogsDisabled,
			violating: map[string]string{"error_logs_enabled": "false"},
			compliant: map[string]string{"error_logs_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-opensearch-audit-logs-disabled", check: awsOpenSearchAuditLogsDisabled,
			violating: map[string]string{"audit_logs_enabled": "false", "fine_grained_access_control": "true"},
			compliant: map[string]string{"audit_logs_enabled": "true", "fine_grained_access_control": "true"},
			unknown:   map[string]string{"audit_logs_enabled": "false"},
		},
		{
			name: "aws-opensearch-too-few-data-nodes", check: awsOpenSearchTooFewDataNodes,
			violating: map[string]string{"instance_count": "1", "zone_awareness": "true"},
			compliant: map[string]string{"instance_count": "3", "zone_awareness": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-opensearch-too-few-dedicated-masters", check: awsOpenSearchTooFewDedicatedMasters,
			violating: map[string]string{"dedicated_master_enabled": "true", "dedicated_master_count": "2"},
			compliant: map[string]string{"dedicated_master_enabled": "true", "dedicated_master_count": "3"},
			unknown:   map[string]string{"dedicated_master_count": "0"},
		},
		{
			name: "aws-opensearch-no-fine-grained-access-control", check: awsOpenSearchNoFineGrainedAccessControl,
			violating: map[string]string{"fine_grained_access_control": "false"},
			compliant: map[string]string{"fine_grained_access_control": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-opensearch-weak-tls-policy", check: awsOpenSearchWeakTLSPolicy,
			violating: map[string]string{"enforce_https": "true", "tls_security_policy": "Policy-Min-TLS-1-0-2019-07"},
			compliant: map[string]string{"enforce_https": "true", "tls_security_policy": "Policy-Min-TLS-1-2-PFS-2023-10"},
			unknown:   map[string]string{"tls_security_policy": "Policy-Min-TLS-1-0-2019-07"},
		},
		{
			name: "aws-opensearch-software-update-available", check: awsOpenSearchSoftwareUpdateAvailable,
			violating: map[string]string{"service_software_update_available": "true"},
			compliant: map[string]string{"service_software_update_available": "false"},
			unknown:   map[string]string{},
		},
	})
}

func osDomain(md map[string]string) asset.Asset {
	return asset.Asset{ID: "arn:aws:es:eu-west-1:1:domain/d", Type: "opensearch_domain", Provider: asset.ProviderAWS, Metadata: md}
}

func TestOpenSearchDomainPublicTiers(t *testing.T) {
	tests := []struct {
		tier     string
		severity finding.Severity
		title    string
	}{
		{asset.PublicAccessConfirmed, finding.SeverityCritical, "OpenSearch domain is publicly readable and writable"},
		{asset.PublicAccessPossible, finding.SeverityMedium, "OpenSearch domain has a public endpoint"},
	}
	for _, tt := range tests {
		a := osDomain(map[string]string{"in_vpc": "false", "public_access": tt.tier})
		f, ok := awsOpenSearchDomainPublic.eval(a, time.Now())
		require.True(t, ok)
		require.Equal(t, tt.severity, f.Severity)
		require.Equal(t, tt.title, f.Title)
	}
	// A VPC domain with an open policy is not internet exposure.
	require.False(t, awsOpenSearchDomainPublic.Violates(osDomain(map[string]string{"in_vpc": "true", "access_policy_public": "true"})))
}

func TestOpenSearchDataNodesAndMasters(t *testing.T) {
	cases := []struct {
		md         map[string]string
		data, mstr bool
	}{
		{map[string]string{"instance_count": "3", "zone_awareness": "false"}, true, false},
		{map[string]string{"instance_count": "2", "zone_awareness": "true"}, true, false},
		{map[string]string{"instance_count": "6", "zone_awareness": "true"}, false, false},
		{map[string]string{"dedicated_master_enabled": "false", "dedicated_master_count": "0"}, false, true},
		{map[string]string{"dedicated_master_enabled": "true", "dedicated_master_count": "5"}, false, false},
		{map[string]string{"dedicated_master_enabled": "true", "dedicated_master_count": "1"}, false, true},
	}
	for _, c := range cases {
		require.Equal(t, c.data, awsOpenSearchTooFewDataNodes.Violates(osDomain(c.md)), c.md)
		require.Equal(t, c.mstr, awsOpenSearchTooFewDedicatedMasters.Violates(osDomain(c.md)), c.md)
	}
}

func TestOpenSearchTLSPolicy(t *testing.T) {
	require.True(t, awsOpenSearchWeakTLSPolicy.Violates(osDomain(map[string]string{"enforce_https": "false", "tls_security_policy": "Policy-Min-TLS-1-2-PFS-2023-10"})),
		"plain HTTP allowed fails whatever the TLS policy")
	require.True(t, awsOpenSearchWeakTLSPolicy.Violates(osDomain(map[string]string{"enforce_https": "true", "tls_security_policy": "Policy-Min-TLS-1-2-2019-07"})))
	require.False(t, awsOpenSearchWeakTLSPolicy.Violates(osDomain(map[string]string{"enforce_https": "true", "tls_security_policy": "Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08"})),
		"the FIPS policy is stricter than the general one")
}

// Audit logs need fine-grained access control: without it the domain is one
// finding (no FGAC), not two.
func TestOpenSearchAuditLogsStepAsideWithoutFGAC(t *testing.T) {
	a := osDomain(map[string]string{"audit_logs_enabled": "false", "fine_grained_access_control": "false"})
	require.False(t, awsOpenSearchAuditLogsDisabled.Violates(a))
	require.True(t, awsOpenSearchNoFineGrainedAccessControl.Violates(a))
}
