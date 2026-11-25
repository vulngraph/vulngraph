package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A role trusted by GitHub Actions almost always has exactly ONE trust
// statement — the single-object Statement shape. Declaring Statement array-only
// made the entire unmarshal fail on that shape, so extractGitHubSubjects
// returned nothing and no federated_access edge was emitted. The common case was
// the broken case, which is why repo → cloud-identity linkage was largely dark.
func TestExtractGitHubSubjects_SingleObjectStatement(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{
		"Effect":"Allow",
		"Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
		"Action":"sts:AssumeRoleWithWebIdentity",
		"Condition":{"StringLike":{
			"token.actions.githubusercontent.com:sub":"repo:example/api:ref:refs/heads/main"}}}}`

	require.Equal(t, []string{"repo:example/api:ref:refs/heads/main"}, extractGitHubSubjects(doc))
}

// The array form must keep working.
func TestExtractGitHubSubjects_ArrayStatement(t *testing.T) {
	doc := `{"Statement":[{
		"Effect":"Allow",
		"Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
		"Condition":{"StringEquals":{
			"token.actions.githubusercontent.com:sub":["repo:example/api:ref:refs/heads/main","repo:example/web:*"]}}}]}`

	require.Equal(t, []string{
		"repo:example/api:ref:refs/heads/main",
		"repo:example/web:*",
	}, extractGitHubSubjects(doc))
}

// IAM APIs return trust documents percent-encoded.
func TestExtractGitHubSubjects_URLEncodedDocument(t *testing.T) {
	doc := `%7B%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Federated%22` +
		`%3A%22arn%3Aaws%3Aiam%3A%3A1%3Aoidc-provider%2Ftoken.actions.githubusercontent.com%22%7D%2C` +
		`%22Condition%22%3A%7B%22StringLike%22%3A%7B%22token.actions.githubusercontent.com%3Asub%22` +
		`%3A%22repo%3Aexample%2Fapi%3A*%22%7D%7D%7D%7D`

	require.Equal(t, []string{"repo:example/api:*"}, extractGitHubSubjects(doc))
}

// A Deny statement must not be read as granting federated access.
func TestExtractGitHubSubjects_DenyIsNotAGrant(t *testing.T) {
	doc := `{"Statement":{
		"Effect":"Deny",
		"Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
		"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:example/api:*"}}}}`

	require.Empty(t, extractGitHubSubjects(doc))
}

// A non-GitHub federated provider must not yield GitHub subjects.
func TestExtractGitHubSubjects_OtherProviderIgnored(t *testing.T) {
	doc := `{"Statement":{
		"Effect":"Allow",
		"Principal":{"Federated":"arn:aws:iam::1:saml-provider/Okta"},
		"Condition":{"StringLike":{"okta:sub":"someone"}}}}`

	require.Empty(t, extractGitHubSubjects(doc))
}

// A sub under a negated operator names the repos kept OUT, so it is not a
// subject; with no positive sub the trust is open to every repo, the "*"
// subject.
func TestExtractGitHubSubjects_NegatedSubIsNotTheSubject(t *testing.T) {
	doc := `{"Statement":{
		"Effect":"Allow",
		"Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
		"Condition":{
			"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
			"StringNotLike":{"token.actions.githubusercontent.com:sub":"repo:example/forks:*"}}}}`

	require.Equal(t, []string{"*"}, extractGitHubSubjects(doc))
}

// Every GitHub token carries sub, so an ...IfExists operator on it admits
// exactly what the plain operator admits.
func TestExtractGitHubSubjects_IfExistsSubIsTheSubject(t *testing.T) {
	doc := `{"Statement":{
		"Effect":"Allow",
		"Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
		"Condition":{"StringLikeIfExists":{"token.actions.githubusercontent.com:sub":"repo:example/api:*"}}}}`

	require.Equal(t, []string{"repo:example/api:*"}, extractGitHubSubjects(doc))
}
