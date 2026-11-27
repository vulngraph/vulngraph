package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
)

func observedInstallation(id, app int64, owner string, members ...string) appInstallation {
	return appInstallation{ID: id, AppID: app, Account: appAccount{Login: owner, Type: "Organization"}, Selection: "selected", Permissions: map[string]string{"contents": "write", "metadata": "read"}, Coverage: "observed", Membership: "complete", Members: members}
}

func TestTokenScopeBoundariesAndPotentialFindings(t *testing.T) {
	repos := []repo{{FullName: "org/public", Visibility: "public"}, {FullName: "org/private", Visibility: "private"}, {FullName: "elsewhere/private", Visibility: "private"}}
	base := appSnapshot{Installations: []appInstallation{observedInstallation(1, 123, "org", "org/public", "org/private"), observedInstallation(2, 123, "elsewhere", "elsewhere/private")}}
	for _, tc := range []struct {
		name, scope, owner, condition string
		permissions                   map[string]string
		permissionScope               string
		unknown, suspended            bool
		want                          int
	}{
		{name: "broad dangerous", scope: "installation", owner: "org", want: 1},
		{name: "current safe", scope: "current", owner: "org", want: 0},
		{name: "selected private", scope: "selected", owner: "org", want: 1},
		{name: "unknown scope", scope: "unknown", owner: "org", want: 0},
		{name: "disabled job", scope: "installation", owner: "org", condition: "disabled", want: 0},
		{name: "unknown installation", scope: "installation", owner: "org", unknown: true, want: 0},
		{name: "suspended", scope: "installation", owner: "org", suspended: true, want: 0},
		{name: "issues only", scope: "installation", owner: "org", permissionScope: "selected", permissions: map[string]string{"metadata": "read"}, want: 0},
		{name: "read private", scope: "installation", owner: "org", permissionScope: "selected", permissions: map[string]string{"contents": "read"}, want: 1},
		{name: "exceeds grant", scope: "installation", owner: "org", permissionScope: "selected", permissions: map[string]string{"administration": "write"}, want: 0},
		{name: "different installation owner missing", scope: "installation", owner: "missing", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap := appSnapshot{Installations: append([]appInstallation{}, base.Installations...)}
			if tc.unknown {
				snap.Installations[0].Coverage = "unknown"
			}
			if tc.suspended {
				s := "2026-11-01"
				snap.Installations[0].SuspendedAt = &s
			}
			token := iac.WorkflowToken{Job: "build", AppID: "123", Scope: tc.scope, Owner: tc.owner, Repositories: []string{"private"}, PublicInput: true, UntrustedExecution: true, Condition: tc.condition, PermissionScope: tc.permissionScope, Permissions: tc.permissions}
			_, edges, findings := projectWorkflowVisibility("https://api.github.com", repos[0], workflowSnapshot{Coverage: "complete", Workflows: []iac.WorkflowSupplyChain{{Path: ".github/workflows/ci.yml", Tokens: []iac.WorkflowToken{token}}}}, newAppScopeIndex(snap, repos))
			require.Len(t, findings, tc.want)
			for _, e := range edges {
				require.NotEqual(t, "elsewhere/private", e.DstID)
				require.Equal(t, "unverified", e.Properties["execution"])
			}
		})
	}
}

func TestAppInventoryDeniedAndRevocations(t *testing.T) {
	inst := observedInstallation(456, 123, "org", "org/public", "org/private")
	app := appIdentity{ID: 123, Slug: "test", Owner: appAccount{Login: "builder"}}
	denied := false
	removed := false
	suspended := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if denied {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/app":
			require.NoError(t, json.NewEncoder(w).Encode(app))
		case "/app/installations", "/orgs/org/installations":
			i := inst
			i.Members = nil
			i.Coverage = ""
			i.Membership = ""
			if suspended {
				v := "2026-11-01T00:00:00Z"
				i.SuspendedAt = &v
			}
			rows := []appInstallation{i}
			if removed {
				rows = []appInstallation{}
			}
			if strings.HasPrefix(r.URL.Path, "/orgs/") {
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"installations": rows}))
			} else {
				require.NoError(t, json.NewEncoder(w).Encode(rows))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := New()
	c.client = srv.Client()
	repos := []repo{{FullName: "org/public"}, {FullName: "org/private"}}
	first := c.collectAppInventory(context.Background(), srv.URL, "jwt", "token", "456", repos, false, nil)
	require.Equal(t, "complete", first.Snapshot.Coverage)
	require.Len(t, first.Snapshot.Installations, 1)
	require.Len(t, first.Snapshot.Installations[0].Members, 2)
	prior := map[string]string{"snapshot": jsonString(first.Snapshot)}
	denied = true
	failed := c.collectAppInventory(context.Background(), srv.URL, "jwt", "token", "456", repos, false, prior)
	require.Equal(t, "unknown", failed.Snapshot.Coverage)
	require.Len(t, failed.Snapshot.Installations[0].Members, 2)
	require.Equal(t, "unknown", failed.Snapshot.Installations[0].Coverage)
	denied = false
	suspended = true
	changed := c.collectAppInventory(context.Background(), srv.URL, "jwt", "token", "456", repos, false, prior)
	require.NotEqual(t, installationGrantID(srv.URL, first.Snapshot.Installations[0]), installationGrantID(srv.URL, changed.Snapshot.Installations[0]))
	for _, e := range changed.Edges {
		require.NotEqual(t, "github_grant_repository", e.EdgeType)
	}
	removed = true
	deleted := c.collectAppInventory(context.Background(), srv.URL, "jwt", "token", "456", repos, false, prior)
	require.Empty(t, deleted.Snapshot.Installations)
}

func TestOtherAppSelectedMembershipUnknown(t *testing.T) {
	install := observedInstallation(42, 999, "org")
	install.Membership = "unknown"
	snap := appSnapshot{Installations: []appInstallation{install}}
	repos := []repo{{FullName: "org/public", Visibility: "public"}, {FullName: "org/private", Visibility: "private"}}
	token := iac.WorkflowToken{AppID: "999", Owner: "org", Scope: "selected", Repositories: []string{"private"}}
	edges, count, resolution, _ := resolveTokenScope("https://api.github.com", repos[0], token, "scope", newAppScopeIndex(snap, repos), "complete")
	require.Empty(t, edges)
	require.Zero(t, count)
	require.Equal(t, "unknown", resolution)
}

func TestInstallationEnumerationRejectsIncompleteOrMalformedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		complete   bool
	}{
		{"empty complete", `{"total_count":0,"installations":[]}`, 200, true},
		{"missing collection", `{}`, 200, false},
		{"denied", `{}`, 403, false},
		{"malformed JSON", `{`, 200, false},
		{"short page mismatched total", `{"total_count":2,"installations":[]}`, 200, false},
		{"missing suspension state", `{"installations":[{"id":1,"app_id":2,"account":{"login":"org"},"repository_selection":"all","permissions":{"contents":"read"}}]}`, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c := New()
			c.client = srv.Client()
			_, complete := c.listAppInstallations(t.Context(), srv.URL, "token", "/orgs/org/installations", true)
			require.Equal(t, tc.complete, complete)
		})
	}
}

func TestRepositoryTotalMismatchIsNotComplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total_count":3,"repositories":[{"full_name":"org/repo"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.client = srv.Client()
	repos, partial, err := c.listRepos(t.Context(), srv.URL, "token")
	require.NoError(t, err)
	require.True(t, partial)
	require.Len(t, repos, 1)
}

func TestNarrowTokenDoesNotMakeSameJobPrivateKeySafe(t *testing.T) {
	repos := []repo{{FullName: "org/public", Visibility: "public"}, {FullName: "org/private", Visibility: "private"}}
	idx := newAppScopeIndex(appSnapshot{Installations: []appInstallation{observedInstallation(1, 123, "org", "org/public", "org/private")}}, repos)
	token := iac.WorkflowToken{AppID: "123", Owner: "org", Job: "build", Scope: "current", PermissionScope: "selected", Permissions: map[string]string{"contents": "read"}, CredentialProvided: true, PublicInput: true, UntrustedExecution: true}
	snapshot := workflowSnapshot{Coverage: "complete", Workflows: []iac.WorkflowSupplyChain{{Path: "ci.yml", Tokens: []iac.WorkflowToken{token}}}}
	_, _, findings := projectWorkflowVisibility("base", repos[0], snapshot, idx)
	require.Len(t, findings, 1)
	require.Equal(t, "github-app-key-untrusted-job", findings[0].CheckID)
	snapshot.Workflows[0].Tokens[0].UntrustedExecution = false
	_, _, findings = projectWorkflowVisibility("base", repos[0], snapshot, idx)
	require.Empty(t, findings, "isolated trusted minting with a narrow token has no demonstrated untrusted job path")
}
