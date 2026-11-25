package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCollectK8sManifests_ProjectsDeclaredWorkloads(t *testing.T) {
	// Inject the file-listing + content seams so the test needs no network.
	c := &Collector{
		manifestTree: func(_ context.Context, _, _ string, r repo) []string {
			if r.FullName == "org/payments-repo" {
				return []string{"k8s/api.yaml", "README.md", "test/fixtures/bad.yaml"}
			}
			return nil
		},
		manifestFile: func(_ context.Context, _, _ string, _ repo, path string) (string, bool) {
			if path == "k8s/api.yaml" {
				return "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n  namespace: billing\n", true
			}
			return "", false
		},
	}
	repos := []repo{{FullName: "org/payments-repo", Name: "payments", DefaultBranch: "main"}}

	assets := c.collectK8sManifests(context.Background(), "", "", repos)

	require.Len(t, assets, 1)
	require.Equal(t, "declared_k8s_workload", assets[0].Type)
	require.Equal(t, "deployment/billing/api", assets[0].Metadata["manifest_key"])
	require.Equal(t, "org/payments-repo", assets[0].Metadata["repo"])
}

func TestCollectK8sManifests_NoManifestsIsNoop(t *testing.T) {
	c := &Collector{
		manifestTree: func(_ context.Context, _, _ string, _ repo) []string { return nil },
		manifestFile: func(_ context.Context, _, _ string, _ repo, _ string) (string, bool) { return "", false },
	}
	assets := c.collectK8sManifests(context.Background(), "", "", []repo{{FullName: "org/x", Name: "x", DefaultBranch: "main"}})
	require.Empty(t, assets)
}
