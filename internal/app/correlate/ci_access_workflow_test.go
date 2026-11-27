package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestCIAccessPreservesWorkflowEvidenceAndUnknownCoverage(t *testing.T) {
	assets := []asset.Asset{
		{ID: "workflow", Type: "github_workflow"},
		{ID: "arn:aws:iam::123456789012:role/test", Type: "iam_role"},
		{ID: "decl", Type: "declared_ci_access", Metadata: map[string]string{"provider": "aws", "repo": "org/repo", "target_arn": "arn:aws:iam::123456789012:role/test", "workflow_id": "workflow", "workflow_path": "ci.yml", "condition": "conditional", "coverage": "unknown"}},
	}
	edges := (&CIAccess{}).Correlate(NewGraph(assets))
	require.Len(t, edges, 2)
	require.Equal(t, "github_workflow", edges[1].SrcType)
	for _, edge := range edges {
		require.Equal(t, "declaration", edge.Properties["evidence"])
		require.Equal(t, "unverified", edge.Properties["execution"])
		require.Equal(t, "unknown", edge.Properties["coverage"])
	}
	assets[2].Metadata["condition"] = "disabled"
	require.Empty(t, (&CIAccess{}).Correlate(NewGraph(assets)))
}
