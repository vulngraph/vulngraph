package github

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
)

func TestWorkflowPartialReadPreservesSnapshotAndUnknownEdges(t *testing.T) {
	source := `on: pull_request_target
jobs:
  build:
    steps:
      - run: echo "${{ github.event.comment.body }}"
      - uses: actions/create-github-app-token@v3
        with:
          app-id: 123
          owner: org
          private-key: ${{ secrets.KEY }}
`
	denied, empty, truncated := false, false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if denied {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/repos/org/public/git/trees/main" {
			if empty {
				_, _ = w.Write([]byte(`{"tree":[],"truncated":false}`))
				return
			}
			_, _ = w.Write([]byte(jsonString(map[string]any{"tree": []map[string]string{{"path": ".github/workflows/ci.yml", "type": "blob"}}, "truncated": truncated})))
			return
		}
		_, _ = w.Write([]byte(jsonString(map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(source)), "size": len(source)})))
	}))
	defer srv.Close()
	c := New()
	c.client = srv.Client()
	repos := []repo{{FullName: "org/public", Visibility: "public", DefaultBranch: "main"}}
	app := appInventory{Snapshot: appSnapshot{Coverage: "complete", Installations: []appInstallation{observedInstallation(1, 123, "org", "org/public", "org/private")}}}
	first := c.collectWorkflowVisibility(context.Background(), srv.URL, "token", repos, nil, app)
	require.True(t, first.Complete)
	require.Len(t, first.Assets, 2)
	denied = true
	failed := c.collectWorkflowVisibility(context.Background(), srv.URL, "token", repos, first.Metadata, app)
	require.False(t, failed.Complete)
	require.Len(t, failed.Assets, 2)
	require.Empty(t, failed.Findings)
	found := false
	for _, e := range failed.Edges {
		if e.EdgeType == "github_token_grant" {
			found = true
			require.Equal(t, "unknown", e.Properties["coverage"])
		}
	}
	require.True(t, found, "retain previously declared grant with unknown current coverage")
	denied = false
	truncated = true
	incomplete := c.collectWorkflowVisibility(context.Background(), srv.URL, "token", repos, first.Metadata, app)
	require.False(t, incomplete.Complete)
	require.Len(t, incomplete.Assets, 2)
	truncated = false
	empty = true
	removed := c.collectWorkflowVisibility(context.Background(), srv.URL, "token", repos, first.Metadata, app)
	require.True(t, removed.Complete)
	require.Empty(t, removed.Assets)
}

func TestTokenVersionChangesWithGrantAndNotCoverage(t *testing.T) {
	r := []repo{{FullName: "org/public"}, {FullName: "org/private"}}
	i := observedInstallation(1, 123, "org", "org/public", "org/private")
	token := iac.WorkflowToken{AppID: "123", Owner: "org", Scope: "selected", Repositories: []string{"private"}}
	id := func(i appInstallation) string {
		return tokenScopeID("workflow", token, newAppScopeIndex(appSnapshot{Installations: []appInstallation{i}}, r))
	}
	first := id(i)
	i.Coverage = "unknown"
	i.Membership = "unknown"
	require.Equal(t, first, id(i))
	i.Members = []string{"org/public"}
	require.NotEqual(t, first, id(i))
	i.Members = []string{"org/public", "org/private"}
	i.Permissions = map[string]string{"contents": "read"}
	require.NotEqual(t, first, id(i))
}

func TestKnownSafeChangesClosePotentialFindingButUnknownDoesNot(t *testing.T) {
	repos := []repo{{FullName: "org/public", Visibility: "public"}, {FullName: "org/private", Visibility: "private"}}
	token := iac.WorkflowToken{AppID: "123", Owner: "org", Job: "build", Scope: "installation", PublicInput: true, UntrustedExecution: true}
	workflow := iac.WorkflowSupplyChain{Path: "ci.yml", Tokens: []iac.WorkflowToken{token}}
	snapshot := workflowSnapshot{Coverage: "complete", Workflows: []iac.WorkflowSupplyChain{workflow}}
	apps := appInventory{ID: "snapshot", Snapshot: appSnapshot{Coverage: "complete", Installations: []appInstallation{observedInstallation(1, 123, "org", "org/public", "org/private")}}}
	prior := map[string]map[string]string{"org/public": {"workflow_snapshot": jsonString(snapshot)}, "snapshot": {"snapshot": jsonString(apps.Snapshot)}}
	current := workflowInventory{Metadata: map[string]map[string]string{"org/public": {"workflow_snapshot": jsonString(snapshot)}}}
	apps.Snapshot.Coverage = "unknown"
	apps.Snapshot.Installations[0].Coverage = "unknown"
	require.Empty(t, workflowClosures("base", repos, prior, current, apps))
	snapshot.Workflows[0].Tokens[0].Condition = "disabled"
	current.Metadata["org/public"]["workflow_snapshot"] = jsonString(snapshot)
	closed := workflowClosures("base", repos, prior, current, apps)
	require.Len(t, closed, 1)
	require.Equal(t, "supply_chain", closed[0].Source)
	snapshot.Workflows[0].Tokens[0].Condition = ""
	current.Metadata["org/public"]["workflow_snapshot"] = jsonString(snapshot)
	apps.Snapshot.Coverage = "complete"
	apps.Snapshot.Installations = nil
	require.Len(t, workflowClosures("base", repos, prior, current, apps), 1, "authoritative installation removal")
}
