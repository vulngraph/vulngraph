package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// One root cause, one finding: each CIS EKS check steps aside for the check
// that already reports the more severe form of the same setting.
func TestEKSCISChecksStepAside(t *testing.T) {
	eks := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "eks_cluster", Provider: asset.ProviderAWS, Metadata: md}
	}
	auditOff := eks(map[string]string{"audit_logging": "false", "logging_disabled_types": "api,audit,authenticator,controllerManager,scheduler"})
	require.True(t, awsEKSAuditLoggingDisabled.Violates(auditOff))
	require.False(t, awsEKSControlPlaneLogsIncomplete.Violates(auditOff))

	worldOpen := eks(map[string]string{"endpoint_public_access": "true", "public_access_cidrs": "0.0.0.0/0"})
	require.True(t, awsEKSPublicEndpoint.Violates(worldOpen))
	require.False(t, awsEKSPublicEndpointEnabled.Violates(worldOpen))
	unknownCIDRs := eks(map[string]string{"endpoint_public_access": "true"})
	require.True(t, awsEKSPublicEndpointEnabled.Violates(unknownCIDRs), "public access is known even when the allowlist is not")
	require.False(t, awsEKSPublicEndpoint.Violates(unknownCIDRs))

	node := asset.Asset{Type: "ec2_instance", Provider: asset.ProviderAWS, Metadata: map[string]string{
		"k8s_node": "true", "iam_role_ecr_push": "true", "http_tokens": "optional"}}
	require.True(t, eksNodeIMDSv1RegistryWrite.Violates(node))
	role := asset.Asset{Type: "iam_role", Provider: asset.ProviderAWS, Metadata: map[string]string{
		"k8s_node_role": "true", "ecr_push": "true", "k8s_node_imdsv1": "true"}}
	require.False(t, awsEKSNodeRoleECRWrite.Violates(role), "an IMDSv1 node already reports the role at High")
	role.Metadata["k8s_node_imdsv1"] = "false"
	require.True(t, awsEKSNodeRoleECRWrite.Violates(role))

	// Fifty nodes on one role are one finding: the check runs on the role.
	r := NewRegistry()
	r.Register(awsEKSNodeRoleECRWrite)
	assets := []asset.Asset{{ID: "arn:aws:iam::1:role/nodes", Type: "iam_role", Provider: asset.ProviderAWS, Metadata: role.Metadata}}
	for i := 0; i < 50; i++ {
		assets = append(assets, asset.Asset{ID: "i-" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Type: "ec2_instance", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"k8s_node": "true", "iam_role_ecr_push": "true", "http_tokens": "required"}})
	}
	require.Len(t, r.Run(assets, fixedTime), 1)

	cluster := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "k8s_cluster", Provider: asset.ProviderKubernetes, Metadata: md}
	}
	eksNone := cluster(map[string]string{"cloud_provider": "aws", "network_policy_engines": ""})
	require.True(t, k8sNoNetworkPolicyEngine.Violates(eksNone))
	require.Equal(t, finding.SeverityMedium, k8sNoNetworkPolicyEngine.SeverityFor(eksNone))
	selfManaged := cluster(map[string]string{"network_policy_engines": ""})
	require.True(t, k8sNoNetworkPolicyEngine.Violates(selfManaged))
	require.Equal(t, finding.SeverityLow, k8sNoNetworkPolicyEngine.SeverityFor(selfManaged), "a closed engine list grades lower off EKS")
	require.False(t, k8sNoNetworkPolicyEngine.Violates(cluster(map[string]string{"cloud_provider": "gcp", "network_policy_engines": ""})),
		"GKE's own addon checks report it")
}
