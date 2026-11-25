package correlate

import (
	"encoding/json"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// IAMCanAssume links principals to the roles they are trusted to assume, derived
// from each role's trust policy (AssumeRolePolicyDocument). For every concrete
// IAM principal ARN named in a role's trust policy, it emits a
// principal -[can_assume]-> role edge. This is the cross-principal relationship
// that blast-radius / enrichment BFS traverses to find escalation reach — the
// graph counterpart to the per-principal aws-privesc-* findings.
//
// Service principals (ec2.amazonaws.com) and federated/OIDC/SAML trusts are not
// emitted as edges (they have no principal node); only IAM user/role/root ARNs.
type IAMCanAssume struct{}

func (IAMCanAssume) Name() string { return "can_assume" }

func (IAMCanAssume) InterestedIn() []string {
	return []string{"iam_role", "iam_user"}
}

func (IAMCanAssume) Correlate(g Graph) []asset.Edge {
	var edges []asset.Edge
	for _, role := range g.IAMRoles() {
		// Single-sided: every emitted edge derives entirely from role's OWN
		// trust document (principalARN is a raw string extracted from it, never
		// looked up elsewhere in g), so an unchanged role produces the same
		// edges it already has. Safe to skip on a partial run regardless of
		// which OTHER iam_role/iam_user triggered this rule to activate — see
		// IAMEffectivePermissions for the cost this avoids.
		if !g.NeedsRecompute(role.ID) {
			continue
		}
		for _, principalARN := range trustPrincipals(role.Metadata["policies"]) {
			if principalARN == role.ID {
				continue
			}
			edges = append(edges, asset.Edge{
				SrcID: principalARN, SrcType: principalType(principalARN),
				DstID: role.ID, DstType: "iam_role",
				EdgeType: EdgeCanAssume,
				Properties: map[string]string{
					"origin": edgeOrigin,
					"rule":   "can_assume",
				},
			})
		}
	}
	return edges
}

// trustPrincipals extracts the concrete IAM principal ARNs that may assume the
// role, from the trust policy stored in the policies metadata.
//
// Delegates to ciem.EvaluateTrustPolicy — the shared, deny-aware trust evaluator
// the AWS collector also uses, rather than a second independent parser here.
// Because blast-radius and enrichment BFS traverse these edges, a phantom edge
// (e.g. one for a principal an explicit Deny has revoked) becomes a phantom
// attack path.
func trustPrincipals(policiesJSON string) []string {
	if policiesJSON == "" {
		return nil
	}
	var stored []struct {
		Type     string `json:"type"`
		Document string `json:"document"`
	}
	if err := json.Unmarshal([]byte(policiesJSON), &stored); err != nil {
		return nil
	}

	seen := map[string]bool{}
	var out []string
	for _, p := range stored {
		if p.Type != "trust" || p.Document == "" {
			continue
		}
		for _, arn := range ciem.EvaluateTrustPolicy(p.Document).AWSPrincipals {
			if isIAMPrincipalARN(arn) && !seen[arn] {
				seen[arn] = true
				out = append(out, arn)
			}
		}
	}
	return out
}

// isIAMPrincipalARN reports whether s is a concrete IAM principal ARN (user,
// role, or account root) — the only trust principals that correspond to a graph
// node. Service names and federated providers are excluded.
func isIAMPrincipalARN(s string) bool {
	// Any partition: GovCloud (aws-us-gov) and China (aws-cn) trust principals
	// name graph nodes too.
	if !strings.HasPrefix(s, "arn:aws:iam::") && !strings.HasPrefix(s, "arn:aws-us-gov:iam::") && !strings.HasPrefix(s, "arn:aws-cn:iam::") {
		return false
	}
	return strings.Contains(s, ":role/") || strings.Contains(s, ":user/") || strings.HasSuffix(s, ":root")
}

func principalType(arn string) string {
	switch {
	case strings.Contains(arn, ":role/"):
		return "iam_role"
	case strings.Contains(arn, ":user/"):
		return "iam_user"
	default:
		return "aws_account"
	}
}
