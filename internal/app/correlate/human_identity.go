package correlate

import (
	"encoding/json"
	"iter"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

// HumanIdentityFederation links human identities (from Okta, Google, AWS
// Identity Center) to the cloud roles they can assume. This closes the "who is
// the human behind this compromised role?" question that no single collector
// can answer on its own.
//
// Edge emitted: human_identity -[federated_access]→ iam_role, when the
// human's email is an OIDC sub in the role's trust policy.
//
// There is deliberately no human → repo ownership edge: the only signal
// available is an email local-part equal to a repo's short name, which links
// alice@corp to every repo named "alice" in every org — evidence of nothing.
type HumanIdentityFederation struct{}

func (HumanIdentityFederation) Name() string { return "human_identity_federation" }

func (HumanIdentityFederation) InterestedIn() []string {
	return []string{"human_identity", "iam_role"}
}

func (r HumanIdentityFederation) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (HumanIdentityFederation) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		if len(g.HumanIdentities()) == 0 {
			return
		}

		// When an IAM role's trust policy names an OIDC subject equal to a human's
		// email (email-based IdPs such as Okta/Google), link that human to the role.
		//
		// skipUnchanged only skips a role when human_identity did NOT change this
		// run: a partial that adds only a human can still match an existing,
		// untouched role's trust sub. Guarding it at all matters because
		// extractOIDCSubs is a full policy decode over every IAMRole() — running it
		// unconditionally on every partial touching iam_role/github_repo/human_identity
		// would repeat IAMEffectivePermissions' cost blowup on a large role set.
		skipUnchanged := g.OtherSideUnchanged("human_identity")
		for _, role := range g.IAMRoles() {
			if skipUnchanged && !g.NeedsRecompute(role.ID) {
				continue
			}
			subs := extractOIDCSubs(role)
			for _, sub := range subs {
				email := strings.ToLower(sub)
				if human, ok := g.HumanByEmail(email); ok {
					if !yield(asset.Edge{
						SrcID:    human.ID,
						SrcType:  "human_identity",
						DstID:    role.ID,
						DstType:  "iam_role",
						EdgeType: EdgeFederatedAccess,
						Properties: map[string]string{
							"origin":     edgeOrigin,
							"rule":       "human_identity_federation",
							"trust_type": "oidc_email",
							"subject":    sub,
						},
					}) {
						return
					}
				}
			}
		}

	}
}

// extractOIDCSubs returns OIDC subject values from an IAM role's trust policies.
// Parses the JSON document string and extracts any Condition :sub values.
func extractOIDCSubs(role asset.Asset) []string {
	policies := decodePolicies(role.Metadata["policies"])
	var subs []string
	for _, pol := range policies {
		if pol.Type != "trust" && pol.Type != "" {
			continue
		}
		if pol.Document == "" {
			continue
		}
		var doc struct {
			Statement []struct {
				Condition map[string]map[string]any `json:"Condition"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(pol.Document), &doc); err != nil {
			continue
		}
		for _, stmt := range doc.Statement {
			for op, condMap := range stmt.Condition {
				// A sub under a negated operator names who is kept out.
				if matching, _ := awspolicy.PresentKeyOperator(op); !matching {
					continue
				}
				for k, v := range condMap {
					if !strings.HasSuffix(strings.ToLower(k), ":sub") {
						continue
					}
					switch sv := v.(type) {
					case string:
						subs = append(subs, sv)
					case []any:
						for _, sv2 := range sv {
							if s2, ok := sv2.(string); ok {
								subs = append(subs, s2)
							}
						}
					}
				}
			}
		}
	}
	return subs
}
