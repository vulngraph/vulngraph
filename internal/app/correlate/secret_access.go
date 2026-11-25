package correlate

import (
	"encoding/json"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// secretReadActions are, per secret asset type, the IAM actions that grant
// read access to a secret's value. A principal effectively allowed any of
// them on a secret's ARN can exfiltrate it.
var secretReadActions = map[string][]string{
	"secretsmanager_secret": {"secretsmanager:getsecretvalue", "secretsmanager:batchgetsecretvalue"},
	"ssm_parameter":         {"ssm:getparameter", "ssm:getparameters", "ssm:getparametersbypath"},
}

// SecretAccess emits accesses_secret edges from IAM principals to the specific
// secret stores (Secrets Manager secrets, SSM SecureString parameters) their
// policies allow them to read. This closes the AWS half of the "who can read
// this secret" question — GCP already has it via the collector.
//
// Every decision goes through the CIEM evaluator's effective permissions
// (identity ∩ boundary ∩ SCP, explicit Deny retained): an action is granted on
// a secret when some Allow's action glob (NotAction included) matches a read
// action and its resource glob matches the secret ARN, and no explicit Deny
// matching that action covers the ARN. Conditions on Allows are ignored (same
// simplification as IAMEffectivePermissions) — this is a reachability signal.
type SecretAccess struct{}

func (SecretAccess) Name() string { return "secret_access" }

func (SecretAccess) InterestedIn() []string {
	return []string{
		"iam_role", "iam_user",
		"secretsmanager_secret", "ssm_parameter",
		// Read via Graph.SCPPoliciesForAccount — see IAMEffectivePermissions.
		"aws_scp_set",
	}
}

func (SecretAccess) Correlate(g Graph) []asset.Edge {
	// Only AWS secret stores are matched here (GCP secret access comes from the
	// GCP collector's IAM-policy read).
	var awsSecrets []asset.Asset
	types := map[string]bool{}
	for _, s := range g.SecretAssets() {
		if _, ok := secretReadActions[s.Type]; ok {
			awsSecrets = append(awsSecrets, s)
			types[s.Type] = true
		}
	}
	if len(awsSecrets) == 0 {
		return nil
	}

	// Two-sided: a role's policies are matched against g's live secrets. A
	// partial run that added/changed only a secret (no role) can still need
	// this — a new secret can match an EXISTING, untouched role's wildcard
	// grant — so only skip via NeedsPermissionRecompute (role itself changed,
	// or its account's SCP did) when neither secret type changed this run.
	skipUnchanged := g.OtherSideUnchanged("secretsmanager_secret", "ssm_parameter")

	var edges []asset.Edge
	// PermissionPrincipals, not IAMRoles: IAM users can hold secret-read
	// grants too.
	for _, role := range g.PermissionPrincipals() {
		if skipUnchanged && !g.NeedsPermissionRecompute(role) {
			continue
		}
		perms := secretPermsForRole(role, g.SCPPoliciesForAccount(role.AccountID))
		if len(perms) == 0 {
			continue
		}

		// A principal that can read EVERY secret of a type would fan out an edge
		// to each one — combinatorial for an admin/CDK/org role — so that fact
		// collapses to a SINGLE sentinel edge instead. Scoped grants (and
		// wildcard grants carved up by a resource-scoped Deny) still emit
		// per-secret edges.
		wildcardType := map[string]bool{}
		for typ := range types {
			for _, action := range secretReadActions[typ] {
				if allowedOnEverySecret(perms, action) {
					wildcardType[typ] = true
					break
				}
			}
		}
		if len(wildcardType) > 0 {
			edges = append(edges, asset.Edge{
				// SrcType is the principal's OWN type — PermissionPrincipals
				// includes iam_users too, not just roles.
				SrcID: role.ID, SrcType: role.Type,
				DstID: secretWildcardID, DstType: secretWildcardType,
				EdgeType: "accesses_secret",
				Properties: map[string]string{
					"origin": edgeOrigin,
					"rule":   "secret_access",
					"scope":  "wildcard",
				},
			})
		}

		for _, sec := range awsSecrets {
			if wildcardType[sec.Type] {
				continue // represented by the single wildcard sentinel edge above
			}
			for _, action := range secretReadActions[sec.Type] {
				if !allowedOnResource(perms, action, sec.ID) {
					continue
				}
				edges = append(edges, asset.Edge{
					SrcID: role.ID, SrcType: role.Type,
					DstID: sec.ID, DstType: sec.Type,
					EdgeType: "accesses_secret",
					Properties: map[string]string{
						"origin": edgeOrigin,
						"rule":   "secret_access",
					},
				})
				break
			}
		}
	}
	return edges
}

// secretWildcardID / secretWildcardType identify the synthetic sentinel node a
// role points at when its secret grant covers ALL secrets (resource "*"). Seeded
// in the Ladybug graph (graphstore bulkSync) like the "internet" sentinel so the
// edge isn't dropped. One edge per wildcard role replaces a fan-out to every
// secret.
const (
	secretWildcardID   = "secret:*"
	secretWildcardType = "secret_wildcard"
)

// allowedOnResource reports whether action is effectively allowed on the
// concrete resource ARN: some Allow matches the action (glob, NotAction-aware)
// and its resource glob matches the ARN, and no explicit Deny matching the
// action covers the ARN. Explicit deny wins regardless of which policy holds
// it; AWS denies carry no Grant, so they apply to every Allow.
func allowedOnResource(perms []ciem.EffectivePermission, action, arn string) bool {
	allowed := false
	for _, p := range perms {
		if !p.MatchesAction(action) || !p.CoversResource(arn) {
			continue
		}
		if p.Effect == ciem.EffectDeny {
			return false
		}
		allowed = true
	}
	return allowed
}

// allowedOnEverySecret reports whether action is allowed on resource "*" with
// no explicit Deny touching the action anywhere. A Deny scoped to some
// resources leaves the grant partial, so it is evaluated per secret instead
// of being collapsed into "can read every secret".
func allowedOnEverySecret(perms []ciem.EffectivePermission, action string) bool {
	allowed := false
	for _, p := range perms {
		if !p.MatchesAction(action) {
			continue
		}
		if p.Effect == ciem.EffectDeny {
			return false
		}
		if p.Resource == "" || p.Resource == "*" {
			allowed = true
		}
	}
	return allowed
}

// secretPermsForRole returns the principal's effective permissions from its
// identity policies plus its account's SCPs. A parse error yields nil — no
// grants are reported rather than guessing.
func secretPermsForRole(role asset.Asset, scps []collectedPolicy) []ciem.EffectivePermission {
	policiesJSON := role.Metadata["policies"]
	if policiesJSON == "" {
		return nil
	}
	var policies []collectedPolicy
	if err := json.Unmarshal([]byte(policiesJSON), &policies); err != nil {
		return nil
	}
	// SCPs cap the account's principals but live on a separate aws_scp_set asset.
	perms, err := effectivePermissionsForCollectedPolicies(append(policies, applicableOrganizationPolicies(role, scps)...))
	if err != nil {
		return nil
	}
	return perms
}
