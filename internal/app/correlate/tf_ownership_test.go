package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func declaredTF(repo, address, targetARN, targetID string) asset.Asset {
	meta := map[string]string{
		"repo":    repo,
		"address": address,
	}
	if targetARN != "" {
		meta["target_arn"] = targetARN
	}
	if targetID != "" {
		meta["target_id"] = targetID
	}
	return asset.Asset{
		ID:       "declared_tf_resource:" + repo + ":" + address,
		Type:     "declared_tf_resource",
		Name:     address,
		Metadata: meta,
	}
}

func TestTFOwnership_IamRoleARNMatchEmitsHighConfidenceEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "arn:aws:iam::123:role/app", Type: "iam_role", Name: "app"},
		declaredTF("org/infra-repo", "aws_iam_role.app", "arn:aws:iam::123:role/app", ""),
	})
	edges := TFOwnership{}.Correlate(g)
	require.Len(t, edges, 1)
	e := edges[0]
	require.Equal(t, "defined_in", e.EdgeType)
	require.Equal(t, "arn:aws:iam::123:role/app", e.SrcID)
	require.Equal(t, "iam_role", e.SrcType)
	require.Equal(t, "org/infra-repo", e.DstID)
	require.Equal(t, "github_repo", e.DstType)
	require.Equal(t, "high", e.Properties["confidence"])
	require.Equal(t, "iac_terraform", e.Properties["provenance"])
}

func TestTFOwnership_AssetLabelLiveTypeMatchEmitsEdge(t *testing.T) {
	// lambda_function is not in graphstore's assetTypeToNode map, so it maps
	// to the catch-all NodeAsset label and routes to DefinedInAsset.
	g := NewGraph([]asset.Asset{
		{ID: "arn:aws:lambda:eu-west-1:123:function:app", Type: "lambda_function", Name: "app"},
		declaredTF("org/infra-repo", "aws_lambda_function.app", "arn:aws:lambda:eu-west-1:123:function:app", ""),
	})
	edges := TFOwnership{}.Correlate(g)
	require.Len(t, edges, 1)
	e := edges[0]
	require.Equal(t, "arn:aws:lambda:eu-west-1:123:function:app", e.SrcID)
	require.Equal(t, "lambda_function", e.SrcType)
	require.Equal(t, "high", e.Properties["confidence"])
	require.Equal(t, "iac_terraform", e.Properties["provenance"])
}

func TestTFOwnership_UnroutableLiveTypeNeverEmitsEdge(t *testing.T) {
	// security_group is not in tfOwnershipSafeLiveTypes, so even with a live match
	// TFOwnership must not emit for it. It is on NodeAsset, so the
	// edge would route correctly, so this now pins a deliberate scope boundary
	// rather than a routing hazard — see tf_ownership.go.
	g := NewGraph([]asset.Asset{
		{ID: "sg-123", Type: "security_group", Name: "app-sg"},
		declaredTF("org/infra-repo", "aws_security_group.app", "", "sg-123"),
	})
	require.Empty(t, TFOwnership{}.Correlate(g))
}

func TestTFOwnership_TargetIDMatchWhenNoARN(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "my-bucket", Type: "s3_bucket", Name: "my-bucket"},
		declaredTF("org/infra-repo", "aws_s3_bucket.app", "", "my-bucket"),
	})
	edges := TFOwnership{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "my-bucket", edges[0].SrcID)
	require.Equal(t, "s3_bucket", edges[0].SrcType)
}

func TestTFOwnership_NoLiveMatchNoEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		declaredTF("org/infra-repo", "aws_iam_role.app", "arn:aws:iam::123:role/app", ""),
	})
	require.Empty(t, TFOwnership{}.Correlate(g))
}

func TestTFOwnership_MissingRepoNoEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "arn:aws:iam::123:role/app", Type: "iam_role", Name: "app"},
		declaredTF("", "aws_iam_role.app", "arn:aws:iam::123:role/app", ""),
	})
	require.Empty(t, TFOwnership{}.Correlate(g), "repo==\"\" must skip, no edge")
}

// TestTFOwnershipSafeLiveTypes_ExcludesUnsafeRoutes pins the excluded live types.
// subnet/elastic_ip/sqs_queue/ecr_repository/ecs_cluster are excluded because they
// would mis-route or have no Ladybug node at all. security_group and ec2_instance are
// excluded by scope choice although they are routable — widening to them is a
// coverage change that should be made deliberately, not silently.
func TestTFOwnershipSafeLiveTypes_ExcludesUnsafeRoutes(t *testing.T) {
	unsafe := []string{"security_group", "ec2_instance", "subnet", "elastic_ip", "sqs_queue", "ecr_repository", "ecs_cluster"}
	for _, lt := range unsafe {
		require.False(t, tfOwnershipSafeLiveTypes[lt], "%s must not be in the TF ownership safe set", lt)
	}
	require.True(t, tfOwnershipSafeLiveTypes["iam_role"])
	require.True(t, tfOwnershipSafeLiveTypes["lambda_function"])
	require.True(t, tfOwnershipSafeLiveTypes["s3_bucket"])
}
