package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestEKSNodeStepsAsideIMDSv2(t *testing.T) {
	node := asset.Asset{Metadata: map[string]string{"http_tokens": "optional", "k8s_node": "true", "iam_role_ecr_push": "true"}}
	require.True(t, eksNodeIMDSv1RegistryWrite.Violates(node))
	require.False(t, awsEC2IMDSv2NotRequired.Violates(node), "one finding per instance")

	for _, md := range []map[string]string{
		{"http_tokens": "optional", "k8s_node": "true"},                               // role unobserved
		{"http_tokens": "optional", "k8s_node": "false", "iam_role_ecr_push": "true"}, // not a node
		{"http_tokens": "optional", "k8s_node": "true", "iam_role_ecr_push": "false"}, // read-only role
	} {
		a := asset.Asset{Metadata: md}
		require.False(t, eksNodeIMDSv1RegistryWrite.Violates(a), "%v", md)
		require.True(t, awsEC2IMDSv2NotRequired.Violates(a), "the plain IMDSv1 finding stays: %v", md)
	}
}
