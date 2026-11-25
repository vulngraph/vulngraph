package correlate

import (
	"encoding/json"
	"sort"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func githubTrustRole(id, condition string) asset.Asset {
	doc := `{"Statement":{"Effect":"Allow",` +
		`"Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},` +
		`"Action":"sts:AssumeRoleWithWebIdentity"` + condition + `}}`
	return asset.Asset{ID: id, Type: "iam_role",
		Metadata: map[string]string{"policies": `[{"type":"trust","document":` + strconv.Quote(doc) + `}]`}}
}

func federatedRepos(g Graph) []string {
	var out []string
	for _, e := range (FederationTrust{}).Correlate(g) {
		out = append(out, e.SrcID)
	}
	sort.Strings(out)
	return out
}

func TestFederationTrust_SubjectMatching(t *testing.T) {
	repos := []asset.Asset{
		{ID: "acme/infra", Type: "github_repo"},
		{ID: "acme/api", Type: "github_repo"},
		{ID: "otherorg/infra", Type: "github_repo"},
		{ID: "acme-labs/tool", Type: "github_repo"},
	}
	cases := []struct {
		name      string
		condition string
		want      []string
	}{
		{"exact subject needs the full owner/name",
			`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:otherorg/infra:ref:refs/heads/main"}}`,
			[]string{"otherorg/infra"}},
		{"unknown full name does not fall back to the short name",
			`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:sub":"repo:stranger/infra:ref:refs/heads/main"}}`,
			nil},
		{"org wildcard matches every repo of that org only",
			`,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/*:ref:refs/heads/main"}}`,
			[]string{"acme/api", "acme/infra"}},
		{"leading wildcard can span the org",
			`,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme*"}}`,
			[]string{"acme-labs/tool", "acme/api", "acme/infra"}},
		// IAM's * also matches ":" and "/", so "repo:*/infra" is satisfied by
		// "repo:acme/api:ref:refs/heads/x/infra" — anyone who can push a branch
		// named x/infra to any repo can assume the role. The loose pattern
		// really is that broad, and is reported as such.
		{"a star before the name is as broad as IAM makes it",
			`,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:*/infra"}}`,
			[]string{"acme-labs/tool", "acme/api", "acme/infra", "otherorg/infra"}},
		{"no sub condition trusts every repo",
			`,"Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}`,
			[]string{"acme-labs/tool", "acme/api", "acme/infra", "otherorg/infra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGraph(append([]asset.Asset{githubTrustRole("arn:aws:iam::1:role/ci", tc.condition)}, repos...))
			require.Equal(t, tc.want, federatedRepos(g))
		})
	}
}

func TestGitHubSubjectMatchesRepo(t *testing.T) {
	require.True(t, githubSubjectMatchesRepo("repo:Acme/API:ref:refs/heads/main", "acme/api"))
	require.True(t, githubSubjectMatchesRepo("*", "acme/api"))
	require.True(t, githubSubjectMatchesRepo("repo:acme/a?i:*", "acme/api"))
	require.False(t, githubSubjectMatchesRepo("repo:acme/api-*", "acme/api"))
	require.False(t, githubSubjectMatchesRepo("repo:acme/api:*", "acme/api2"))
	require.False(t, githubSubjectMatchesRepo("org/acme/api", "acme/api"))
}

func TestDeclaredIdentityOwnership_OIDCPairsOnlyTheFilesOwnRole(t *testing.T) {
	const (
		roleA = "arn:aws:iam::1:role/app-a"
		roleB = "arn:aws:iam::1:role/other"
	)
	base := []asset.Asset{
		{ID: roleA, Type: "iam_role", Name: "app-a"},
		{ID: roleB, Type: "iam_role", Name: "other"},
		{ID: "acme/iam", Type: "github_repo"},
		{ID: "acme/app", Type: "github_repo"},
	}
	fedDsts := func(extra ...asset.Asset) []string {
		var out []string
		for _, e := range (DeclaredIdentityOwnership{}).Correlate(NewGraph(append(append([]asset.Asset{}, base...), extra...))) {
			if e.EdgeType == EdgeFederatedAccess {
				out = append(out, e.DstID)
			}
		}
		return out
	}

	require.Empty(t, fedDsts(
		declaredIdentity("acme/iam", "main.tf", kindIamRole, roleA),
		declaredIdentity("acme/iam", "main.tf", kindIamRole, roleB),
		declaredIdentity("acme/iam", "main.tf", kindGitHubOIDC, "acme/app"),
	), "a subject in a file naming two roles cannot be attributed to either")

	require.Equal(t, []string{roleA}, fedDsts(
		declaredIdentity("acme/iam", "roles/a.json", kindIamRole, roleA),
		declaredIdentity("acme/iam", "roles/a.json", kindGitHubOIDC, "acme/app"),
	), "a subject in a file naming exactly one role is that role's trust grant")
}

func TestHumanIdentityFederation_NoOwnershipFromEmailLocalPart(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "human:alice", Type: "human_identity", Domain: "alice@example.com"},
		{ID: "someorg/alice", Type: "github_repo"},
	})
	require.Empty(t, HumanIdentityFederation{}.Correlate(g))
}

// A trust sub under a negated operator names the person kept OUT; it must not
// link that person to the role.
func TestExtractOIDCSubs_NegatedSubIsNotASubject(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"accounts.google.com"},
		"Condition":{"StringNotEquals":{"accounts.google.com:sub":"alice@example.com"},
		"StringEquals":{"accounts.google.com:sub":"bob@example.com"}}}]}`
	policies, err := json.Marshal([]map[string]string{{"type": "trust", "document": doc}})
	require.NoError(t, err)

	require.Equal(t, []string{"bob@example.com"},
		extractOIDCSubs(asset.Asset{Type: "iam_role", Metadata: map[string]string{"policies": string(policies)}}))
}

// A token always carries sub, so StringEqualsIfExists names the subject as
// StringEquals does.
func TestExtractOIDCSubs_IfExistsSubIsASubject(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"accounts.google.com"},
		"Condition":{"StringEqualsIfExists":{"accounts.google.com:sub":"carol@example.com"}}}]}`
	policies, err := json.Marshal([]map[string]string{{"type": "trust", "document": doc}})
	require.NoError(t, err)

	require.Equal(t, []string{"carol@example.com"},
		extractOIDCSubs(asset.Asset{Type: "iam_role", Metadata: map[string]string{"policies": string(policies)}}))
}
