package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Only the collector-resolved role produces an edge. eksctl and Terraform
// routinely give the profile a different name from the role, so deriving the
// role from the profile name either misses or links an unrelated role that
// happens to share the profile's name — here app-server.
func TestEC2InstanceProfile_UsesOnlyResolvedRoleARN(t *testing.T) {
	realRole := "arn:aws:iam::123:role/eksctl-prod-nodegroup-NodeInstanceRole"
	sameNameRole := "arn:aws:iam::123:role/app-server"

	assets := []asset.Asset{
		{
			ID: "i-eks", Type: "ec2_instance", AccountID: "123",
			Metadata: map[string]string{
				"iam_instance_profile": "arn:aws:iam::123:instance-profile/eks-1a2b3c4d",
				"iam_role_arn":         realRole,
			},
		},
		{
			ID: "i-console", Type: "ec2_instance", AccountID: "123",
			Metadata: map[string]string{
				"iam_instance_profile": "arn:aws:iam::123:instance-profile/app-server",
			},
		},
		{ID: realRole, Type: "iam_role", AccountID: "123"},
		{ID: sameNameRole, Type: "iam_role", AccountID: "123"},
	}

	edges := EC2InstanceProfile{}.Correlate(NewGraph(assets))
	require.Len(t, edges, 1, "the unresolved profile is not guessed into the same-named role")
	require.Equal(t, "i-eks", edges[0].SrcID)
	require.Equal(t, realRole, edges[0].DstID)
}

// A resolved role absent from inventory is still dropped — the membership check
// guards both paths, so an unsynced account cannot create a dangling stub.
func TestEC2InstanceProfile_ResolvedRoleStillNeedsInventory(t *testing.T) {
	assets := []asset.Asset{
		{
			ID: "i-1", Type: "ec2_instance", AccountID: "123",
			Metadata: map[string]string{
				"iam_instance_profile": "arn:aws:iam::123:instance-profile/p",
				"iam_role_arn":         "arn:aws:iam::999:role/unsynced",
			},
		},
	}
	require.Empty(t, EC2InstanceProfile{}.Correlate(NewGraph(assets)))
}
