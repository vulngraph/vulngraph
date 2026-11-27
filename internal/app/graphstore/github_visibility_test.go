package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestGitHubVisibilityGraphKeepsScopeAndEvidence(t *testing.T) {
	assets := []asset.Asset{
		{ID: "public", Type: "github_repo"}, {ID: "private", Type: "github_repo"},
		{ID: "workflow", Type: "github_workflow"}, {ID: "scope", Type: "github_app_token_scope"},
		{ID: "grant", Type: "github_app_grant"}, {ID: "install", Type: "github_app_installation"}, {ID: "app", Type: "github_app"},
	}
	edge := func(src, st, dst, dt, kind string) asset.Edge {
		return asset.Edge{SrcID: src, SrcType: st, DstID: dst, DstType: dt, EdgeType: kind, Properties: map[string]string{"evidence": "potential_path", "coverage": "unknown", "execution": "unverified", "permissions": `{"contents":"read"}`, "condition": "conditional", "scope": "installation"}}
	}
	edges := []asset.Edge{
		edge("public", "github_repo", "workflow", "github_workflow", "github_workflow"),
		edge("workflow", "github_workflow", "scope", "github_app_token_scope", "github_workflow_token"),
		edge("scope", "github_app_token_scope", "grant", "github_app_grant", "github_token_grant"),
		edge("app", "github_app", "install", "github_app_installation", "github_app_installation"),
		edge("install", "github_app_installation", "grant", "github_app_grant", "github_installation_grant"),
		edge("grant", "github_app_grant", "private", "github_repo", "github_grant_repository"),
	}
	for _, copyPath := range []bool{false, true} {
		_, conn := openTestDB(t)
		if copyPath {
			_, err := bulkSyncCopy(t.Context(), conn, assets, edges, newReachOverlay(edges), nil, true, 4, nil)
			require.NoError(t, err)
		} else {
			require.NoError(t, bulkSync(t.Context(), conn, assets, edges, nil))
		}
		require.Equal(t, int64(1), countQuery(t, conn, `MATCH (:Repo {id:'public'})-[:GitHubWorkflow]->()-[:GitHubWorkflowToken]->()-[:GitHubTokenGrant]->()-[:GitHubGrantRepository]->(:Repo {id:'private'}) RETURN count(*)`))
		result, err := conn.Query(`MATCH ()-[e:GitHubTokenGrant]->() RETURN e.evidence, e.coverage, e.execution, e.permissions, e.condition, e.scope`)
		require.NoError(t, err)
		require.True(t, result.HasNext())
		row, err := result.Next()
		require.NoError(t, err)
		for i, want := range []string{"potential_path", "unknown", "unverified", `{"contents":"read"}`, "conditional", "installation"} {
			got, err := row.GetValue(uint64(i))
			require.NoError(t, err)
			require.Equal(t, want, got)
		}
		result.Close()
	}
}
