package correlate

import (
	"encoding/json"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

// EdgeFederatedAccess links a GitHub repo (or K8s workload) to the cloud IAM
// role it can assume via a federated trust (OIDC, IRSA, WIF). This is the
// "supply chain to cloud access" attack path: a compromised repo pipeline
// becomes a privileged cloud identity.
const EdgeFederatedAccess = "federated_access"

// FederationTrust discovers IAM roles with federated trust policies and
// emits federated_access edges to any matching repos in the graph.
//
// This rule covers GitHub Actions OIDC → AWS IAM role
// (token.actions.githubusercontent.com). The other two federated trusts emit the
// same edge type from their own rules, because each is driven from a different
// side of the join: GCP Workload Identity from the ServiceAccount's annotation
// (gcp_wif.go), EKS IRSA from the role's trust policy (irsa.go).
type FederationTrust struct{}

func (FederationTrust) Name() string { return "federation_trust" }

func (FederationTrust) InterestedIn() []string {
	return []string{"iam_role", "github_repo"}
}

func (FederationTrust) Correlate(g Graph) []asset.Edge {
	// Two-sided: a role's trust policy is matched against g's live repos. A
	// partial run that changed only a repo (not any role) can still need this
	// — a brand-new repo can match an EXISTING, untouched role's trust subject
	// — so only skip unchanged roles when no github_repo changed this run.
	skipUnchanged := g.OtherSideUnchanged("github_repo")
	var edges []asset.Edge
	for _, role := range g.IAMRoles() {
		if skipUnchanged && !g.NeedsRecompute(role.ID) {
			continue
		}
		edges = append(edges, githubOIDCEdges(role, g)...)
	}
	return edges
}

// githubOIDCEdges parses an IAM role's trust policy for GitHub Actions OIDC
// principals and matches them against repos in the graph.
//
// GitHub trust policy condition format:
//
//	"token.actions.githubusercontent.com:sub": "repo:org/name:ref:refs/heads/main"
//	or "repo:org/name:*"  (any branch)
func githubOIDCEdges(role asset.Asset, g Graph) []asset.Edge {
	policies := decodePolicies(role.Metadata["policies"])
	if len(policies) == 0 {
		return nil
	}

	var edges []asset.Edge
	seen := map[string]bool{}
	emit := func(repo asset.Asset, sub string) {
		if seen[repo.ID] {
			return
		}
		seen[repo.ID] = true
		edges = append(edges, asset.Edge{
			SrcID: repo.ID, SrcType: "github_repo",
			DstID: role.ID, DstType: role.Type,
			EdgeType: EdgeFederatedAccess,
			Properties: map[string]string{
				"origin":     edgeOrigin,
				"rule":       "federation_trust",
				"trust_type": "github_oidc",
				"subject":    sub,
				"provenance": "trust_policy",
			},
		})
	}
	for _, pol := range policies {
		// Only trust policies contain federated principals; skip identity/boundary/scp.
		if pol.Type != "trust" && pol.Type != "" {
			continue
		}
		for _, sub := range extractGitHubSubjects(pol.Document) {
			// sub format: "repo:org/name:ref:refs/heads/main" or "repo:org/name:*".
			// The full "org/name" is required: a short-name match would link
			// repo:otherorg/infra to every repo called "infra" in the estate.
			pattern := githubRepoFromSub(sub)
			if pattern == "" {
				continue
			}
			if !strings.ContainsAny(pattern, "*?") {
				if repo, ok := g.RepoByFullName(pattern); ok {
					emit(repo, sub)
				}
				continue
			}
			// A wildcard subject (StringLike "repo:org/*:ref:refs/heads/main")
			// trusts every repo whose full name the pattern can match.
			for _, repo := range g.GitHubRepos() {
				if githubSubjectMatchesRepo(sub, repo.ID) {
					emit(repo, sub)
				}
			}
		}
	}
	return edges
}

// githubSubjectMatchesRepo reports whether a StringLike sub pattern can be
// satisfied by some token GitHub issues to repoFull, i.e. whether the pattern
// can match a string beginning "repo:<org/name>:" (the suffix — ref,
// environment, pull_request — varies per workflow run, so any suffix counts).
// IAM's "*" matches any run of characters including ":" and "/", so this runs
// the glob as an NFA over that literal prefix: if any pattern position is
// still live after consuming it, the rest of the pattern can always be
// completed. Case-insensitive, as GitHub owner/repo names are.
func githubSubjectMatchesRepo(pattern, repoFull string) bool {
	p := strings.ToLower(pattern)
	closure := func(states map[int]bool) map[int]bool {
		for i := 0; i < len(p); i++ {
			if states[i] && p[i] == '*' {
				states[i+1] = true
			}
		}
		return states
	}
	states := closure(map[int]bool{0: true})
	for _, c := range []byte("repo:" + strings.ToLower(repoFull) + ":") {
		next := map[int]bool{}
		for i := range states {
			switch {
			case i >= len(p):
			case p[i] == '*':
				next[i] = true
			case p[i] == '?' || p[i] == c:
				next[i+1] = true
			}
		}
		if len(next) == 0 {
			return false
		}
		states = closure(next)
	}
	return true
}

// trustStatement is one trust-policy statement, enough to find an OIDC
// federation grant (GitHub Actions or EKS/IRSA) and its sub condition.
type trustStatement struct {
	Effect    string                    `json:"Effect"`
	Principal json.RawMessage           `json:"Principal"`
	Condition map[string]map[string]any `json:"Condition"`
}

// extractGitHubSubjects finds GitHub Actions OIDC sub conditions in a trust
// policy document.
//
// Statement is accepted as a single object as well as an array, since a role
// trusted by GitHub Actions almost always has exactly one trust statement (the
// single-object shape), not the array shape — this is the common case, not an
// edge case.
func extractGitHubSubjects(document string) []string {
	var subjects []string
	for _, stmt := range trustStatements(document) {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		if !hasFederatedGitHub(stmt.Principal) {
			continue
		}
		// A sub names the repos let in only under a matching operator
		// (StringEquals, StringLike, either ...IfExists, as a token always
		// carries sub): under a negated one (StringNotLike) it names the
		// repos kept OUT, so reading it as the subject would invert the trust.
		found := false
		for op, condMap := range stmt.Condition {
			if matching, _ := awspolicy.PresentKeyOperator(op); !matching {
				continue
			}
			for key, val := range condMap {
				if strings.HasSuffix(strings.ToLower(key), ":sub") &&
					strings.Contains(strings.ToLower(key), "actions.githubusercontent.com") {
					subjects = append(subjects, conditionStrings(val)...)
					found = true
				}
			}
		}
		// No sub condition: GitHub's provider issues tokens to every workflow
		// in every repository on github.com, and an aud check alone does not
		// narrow that, so the role is assumable from ANY repo. It is reported
		// as the subject "*", which matches every repo in the graph.
		if !found {
			subjects = append(subjects, "*")
		}
	}
	return subjects
}

// trustStatements decodes a trust policy's Statement(s), tolerant of the
// single-object-or-array polymorphism AWS allows and of URL-encoded documents.
func trustStatements(document string) []trustStatement {
	if document == "" {
		return nil
	}
	document = awspolicy.NormalizeDocument(document)
	var policy struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(document), &policy) != nil || len(policy.Statement) == 0 {
		return nil
	}
	var arr []trustStatement
	if json.Unmarshal(policy.Statement, &arr) == nil {
		return arr
	}
	var one trustStatement
	if json.Unmarshal(policy.Statement, &one) == nil {
		return []trustStatement{one}
	}
	return nil
}

func hasFederatedGitHub(principal json.RawMessage) bool {
	for _, f := range federatedPrincipals(principal) {
		if strings.Contains(strings.ToLower(f), "actions.githubusercontent.com") {
			return true
		}
	}
	return false
}

// federatedPrincipals returns the Federated values of a trust statement's
// Principal block, tolerant of the single-string-or-array polymorphism AWS
// allows. Empty when the statement names no federated principal.
func federatedPrincipals(principal json.RawMessage) []string {
	if principal == nil {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(principal, &m); err != nil {
		return nil
	}
	raw, ok := m["Federated"]
	if !ok {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

func conditionStrings(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		var out []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// githubRepoFromSub extracts the "org/name" portion from a GitHub OIDC sub.
// Input: "repo:org/name:ref:refs/heads/main" → "org/name"
// Input: "repo:org/name:*" → "org/name"
func githubRepoFromSub(sub string) string {
	sub = strings.TrimPrefix(sub, "repo:")
	if i := strings.Index(sub, ":"); i > 0 {
		return sub[:i]
	}
	return sub
}

// decodePolicies reads the asset metadata policies JSON (same format as
// internal/app/ciem parsePolicies but local to avoid the import).
func decodePolicies(raw string) []struct{ Type, Document string } {
	if raw == "" {
		return nil
	}
	var stored []struct {
		Type     string `json:"type"`
		Document string `json:"document"`
	}
	if err := json.Unmarshal([]byte(raw), &stored); err != nil {
		return nil
	}
	out := make([]struct{ Type, Document string }, len(stored))
	for i, s := range stored {
		out[i] = struct{ Type, Document string }{s.Type, s.Document}
	}
	return out
}
