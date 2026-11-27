package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWorkflowIngestProjectsDeclaredCIAccess(t *testing.T) {
	c := New()
	c.workflowTree = func(_ context.Context, _, _ string, _ repo) ([]string, bool) {
		return []string{".github/workflows/deploy.yml"}, true
	}
	c.workflowFile = func(_ context.Context, _, _ string, _ repo, _ string) (string, bool) {
		return "jobs:\n  deploy:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::210987654321:role/gh-deploy\n", true
	}
	inventory := c.collectWorkflowVisibility(t.Context(), "", "", []repo{{FullName: "example-corp/api", DefaultBranch: "main"}}, nil, appInventory{})
	require.True(t, inventory.Complete)
	require.Len(t, inventory.Assets, 2)
	require.Equal(t, "github_workflow", inventory.Assets[0].Type)
	require.Equal(t, "declared_ci_access", inventory.Assets[1].Type)
	require.Equal(t, "arn:aws:iam::210987654321:role/gh-deploy", inventory.Assets[1].Metadata["target_arn"])
	require.Equal(t, inventory.Assets[0].ID, inventory.Assets[1].Metadata["workflow_id"])
}

func TestWorkflowIngestDistinguishesEmptyFromUnscanned(t *testing.T) {
	for _, archived := range []bool{false, true} {
		called := false
		c := New()
		c.workflowTree = func(_ context.Context, _, _ string, _ repo) ([]string, bool) { called = true; return nil, true }
		inventory := c.collectWorkflowVisibility(t.Context(), "", "", []repo{{FullName: "org/repo", DefaultBranch: "main", Archived: archived}}, nil, appInventory{})
		require.Empty(t, inventory.Assets)
		require.Equal(t, !archived, called)
		require.Equal(t, !archived, inventory.Complete)
	}
}
