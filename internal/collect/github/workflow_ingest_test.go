package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCollectWorkflows_ProjectsDeclaredCIAccess(t *testing.T) {
	// Inject the file-listing + content seams so the test needs no network.
	c := &Collector{
		workflowTree: func(_ context.Context, _, _ string, r repo) []string {
			if r.FullName == "example-corp/api" {
				return []string{".github/workflows/deploy.yml", "README.md", ".github/workflows/notes.txt"}
			}
			return nil
		},
		workflowFile: func(_ context.Context, _, _ string, _ repo, path string) (string, bool) {
			if path == ".github/workflows/deploy.yml" {
				return "jobs:\n  deploy:\n    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::210987654321:role/gh-deploy\n", true
			}
			return "", false
		},
	}
	repos := []repo{{FullName: "example-corp/api", Name: "api", DefaultBranch: "main"}}

	assets := c.collectWorkflows(context.Background(), "", "", repos)

	require.Len(t, assets, 1)
	require.Equal(t, "declared_ci_access", assets[0].Type)
	require.Equal(t, "arn:aws:iam::210987654321:role/gh-deploy", assets[0].Metadata["target_arn"])
	require.Equal(t, "example-corp/api", assets[0].Metadata["repo"])
}

func TestCollectWorkflows_NoWorkflowsIsNoop(t *testing.T) {
	c := &Collector{
		workflowTree: func(_ context.Context, _, _ string, _ repo) []string { return nil },
		workflowFile: func(_ context.Context, _, _ string, _ repo, _ string) (string, bool) { return "", false },
	}
	assets := c.collectWorkflows(context.Background(), "", "", []repo{{FullName: "org/x", Name: "x", DefaultBranch: "main"}})
	require.Empty(t, assets)
}

func TestCollectWorkflows_ArchivedRepoSkipped(t *testing.T) {
	called := false
	c := &Collector{
		workflowTree: func(_ context.Context, _, _ string, _ repo) []string {
			called = true
			return nil
		},
		workflowFile: func(_ context.Context, _, _ string, _ repo, _ string) (string, bool) { return "", false },
	}
	assets := c.collectWorkflows(context.Background(), "", "", []repo{{FullName: "org/x", Name: "x", DefaultBranch: "main", Archived: true}})
	require.Empty(t, assets)
	require.False(t, called, "archived repos must not be walked")
}
