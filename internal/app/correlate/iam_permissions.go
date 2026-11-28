package correlate

import (
	"encoding/json"
	"iter"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// EdgeAllowsAction links an IamRole to an IamPolicy when the role has a
// dangerous permission via that policy. This powers queries like:
//
//	MATCH (r:IamRole)-[:AllowsAction]->(p:IamPolicy) WHERE p.dangerous_actions CONTAINS 'iam:CreateUser'
const EdgeAllowsAction = "allows_action"

// dangerousActions is the catalogue of high-impact AWS IAM actions that can be
// leveraged for privilege escalation, data exfiltration, persistence, or
// lateral movement, grouped by attack category. Detection looks for any policy
// that *contains* one of these actions with Effect=Allow, rather than full
// policy evaluation (conditions, resource ARNs, SCPs).
var dangerousActions = map[string]string{
	// IAM admin — can modify any identity, highest severity
	"iam:createuser":             "iam-admin",
	"iam:creategroup":            "iam-admin",
	"iam:createpolicyversion":    "iam-admin",
	"iam:attachuserpolicy":       "iam-admin",
	"iam:attachrolepolicy":       "iam-admin",
	"iam:attachgrouppolicy":      "iam-admin",
	"iam:putuserpolicy":          "iam-admin",
	"iam:putrolepolicy":          "iam-admin",
	"iam:putgrouppolicy":         "iam-admin",
	"iam:addusertogroup":         "iam-admin",
	"iam:updateassumerolepolicy": "iam-admin",
	"iam:passrole":               "iam-passrole",
	"iam:createaccesskey":        "iam-credential",
	"iam:updateaccesskey":        "iam-credential",
	"iam:createloginprofile":     "iam-credential",
	"iam:updateloginprofile":     "iam-credential",
	"iam:deleteaccesskey":        "iam-credential",

	// STS — assume any role
	"sts:assumerole":                "sts",
	"sts:assumerolewithwebidentity": "sts",
	"sts:assumerolewithsaml":        "sts",
	"sts:getfederationtoken":        "sts",

	// S3 data exfiltration
	"s3:putbucketpolicy": "s3-admin",
	"s3:putbucketacl":    "s3-admin",
	"s3:getobject":       "s3-read",
	"s3:putobject":       "s3-write",
	"s3:deleteobject":    "s3-write",
	"s3:deletebucket":    "s3-admin",

	// EC2 — code execution via instances
	"ec2:runinstances":                  "ec2-control",
	"ec2:startinstances":                "ec2-control",
	"ec2:stopinstances":                 "ec2-control",
	"ec2:terminateinstances":            "ec2-control",
	"ec2:modifyinstanceattribute":       "ec2-control",
	"ec2:createimage":                   "ec2-control",
	"ec2:authorizesecuritygroupingress": "network",
	"ec2:createsecuritygroup":           "network",

	// Lambda — serverless code execution
	"lambda:createfunction":     "lambda-control",
	"lambda:updatefunctioncode": "lambda-control",
	"lambda:invokefunctionurl":  "lambda-control",
	"lambda:addpermission":      "lambda-control",

	// KMS — decrypt any secret
	"kms:decrypt":         "kms",
	"kms:encrypt":         "kms",
	"kms:generatedatakey": "kms",
	"kms:createkey":       "kms",
	"kms:putkeypolicy":    "kms",

	// Secrets Manager — read all secrets
	"secretsmanager:getsecretvalue": "secrets",
	"secretsmanager:createsecret":   "secrets",
	"secretsmanager:updatesecret":   "secrets",

	// SSM — run commands on EC2
	"ssm:sendcommand":              "ssm-execution",
	"ssm:startautomationexecution": "ssm-execution",

	// CloudFormation — deploy arbitrary infra
	"cloudformation:createstack": "infra-deploy",
	"cloudformation:updatestack": "infra-deploy",

	// EKS — cluster admin
	"eks:createcluster":       "k8s-control",
	"eks:updateclusterconfig": "k8s-control",

	// RDS — database access
	"rds:modifydbinstance":               "database",
	"rds:restoredbinstancetopointintime": "database",

	// Wildcard — everything
	"*": "admin-wildcard",
}

// policyStatement is a subset of the AWS IAM policy statement structure.
type policyStatement struct {
	Effect string `json:"Effect"`
	Action any    `json:"Action"` // string or []string
	// NotAction is the negated form ("everything except these"). It must be
	// parsed: a statement carrying only NotAction yielded no candidate actions at
	// all, so an admin-except-IAM grant produced zero edges.
	NotAction any `json:"NotAction"`
	Resource  any `json:"Resource"`
	Principal any `json:"Principal"`
}

// policyDocument is the top-level AWS IAM policy JSON.
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

// collectedPolicy matches the format stored by the AWS IAM collector in asset metadata.
type collectedPolicy struct {
	Name       string         `json:"name"`
	Type       string         `json:"type"` // "identity" | "trust" | "boundary"
	Managed    bool           `json:"managed"`
	Document   string         `json:"document"` // JSON string of policyDocument
	Incomplete bool           `json:"incomplete,omitempty"`
	SCPLevel   *ciem.SCPLevel `json:"-"`
}

// IAMEffectivePermissions discovers dangerous actions an IAM principal (role or
// user) effectively holds and emits AllowsAction edges to IamPolicy nodes.
//
// Candidate actions come from the catalogue below, but whether each is
// actually held is answered by ciem's effective-permission evaluator — Allow ∩
// boundary ∩ SCP with explicit-deny-wins semantics — not by a raw per-document
// Allow scan, since a sibling Deny or a boundary/SCP cap can remove a
// candidate action entirely. Conditions remain unmodelled.
//
// The IamPolicy node (id = policy ARN or "inline:{role_id}:{name}") is created
// synthetically if not already in the graph from the HasPolicy correlator.
type IAMEffectivePermissions struct{}

func (IAMEffectivePermissions) Name() string { return "iam_effective_permissions" }

func (IAMEffectivePermissions) InterestedIn() []string {
	// aws_scp_set is read (via Graph.SCPPoliciesForAccount) even though it is
	// never an edge endpoint: a changed SCP changes every principal's effective
	// permissions in that account, so the rule must re-run and the type must be
	// loaded into the partial view.
	return []string{"iam_role", "iam_user", "gcp_service_account", "aws_scp_set"}
}

func (r IAMEffectivePermissions) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (IAMEffectivePermissions) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		// PermissionPrincipals, not IAMRoles: IAM users (long-lived access keys)
		// are principals too and must be checked, not just roles.
		for _, principal := range g.PermissionPrincipals() {
			// A full sweep must stay exhaustive (NeedsPermissionRecompute always
			// true there). A partial correlate only needs to touch the principals
			// actually implicated by this run — recomputing the whole fleet on
			// every IAM-shaped change does not scale.
			if !g.NeedsPermissionRecompute(principal) {
				continue
			}
			for edge := range iamPermissionStream(principal, g.SCPPoliciesForAccount(principal.AccountID)) {
				if !yield(edge) {
					return
				}
			}
		}

	}
}

func iamPermissionEdges(role asset.Asset, scps []collectedPolicy) []asset.Edge {
	return slices.Collect(iamPermissionStream(role, scps))
}
func iamPermissionStream(role asset.Asset, scps []collectedPolicy) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		policiesJSON := role.Metadata["policies"]
		if policiesJSON == "" {
			return
		}

		var policies []collectedPolicy
		if err := json.Unmarshal([]byte(policiesJSON), &policies); err != nil {
			return
		}
		if (role.Type == "iam_role" || role.Type == "iam_user") && collectedBoundaryReadUnknown(role.Metadata["permission_boundary_complete"], policies) {
			policies = append(policies, collectedPolicy{Type: "boundary", Incomplete: true})
		}
		// SCPs cap what the account's principals may do at all; fold them in
		// alongside the principal's own policies so this rule's edges reflect the
		// same cap CIEM privesc detection already applies.
		policies = append(policies, applicableOrganizationPolicies(role, scps)...)

		// Effective permissions — Allow ∩ boundary ∩ SCP, explicit Deny retained per
		// AWS deny-wins semantics — computed by the same evaluator privesc detection
		// uses (internal/app/ciem), not a hand-rolled approximation. A parse error
		// means no edges are emitted rather than guessing.
		perms, err := effectivePermissionsForCollectedPolicies(policies)
		if err != nil {
			return
		}

		policyEdgeSeen := map[string]bool{} // dedupe per (role, policy, category)

		for _, p := range policies {
			if p.Type == "trust" {
				continue // trust policies grant assume — handled by federation/iam correlators
			}
			// Only identity policies grant; a boundary or SCP only CAPS a grant
			// (perms above already folds that cap in via intersection) and must
			// never be attributed as the source of a dangerous action itself.
			if p.Type == "boundary" || p.Type == "scp" {
				continue
			}
			if p.Document == "" {
				continue
			}

			categories := dangerousActionsInPolicy(p.Document, perms)
			if len(categories) == 0 {
				continue
			}

			// Policy node ID: use ARN if available (managed policies) else synthesize.
			policyID := policyIDFor(role, p)

			for category := range categories {
				key := role.ID + "|" + policyID + "|" + category
				if policyEdgeSeen[key] {
					continue
				}
				policyEdgeSeen[key] = true

				if !yield(asset.Edge{
					SrcID:    role.ID,
					SrcType:  role.Type,
					DstID:    policyID,
					DstType:  "iam_policy",
					EdgeType: EdgeAllowsAction,
					Properties: map[string]string{
						// origin/rule are stamped by every correlation rule, so an
						// edge's origin is auditable.
						"origin":      edgeOrigin,
						"rule":        "iam_effective_permissions",
						"category":    category,
						"policy_name": p.Name,
						"managed":     boolStr(p.Managed),
					},
				}) {
					return
				}
			}
		}

	}
}

// effectivePermissionsForCollectedPolicies converts the collector's raw policy
// list (the {type, document} shape stored on asset metadata) into ciem's
// evaluator input and computes effective permissions once per role — shared by
// every correlator in this package that needs "is this action actually still
// allowed" instead of a raw per-document Allow scan.
func effectivePermissionsForCollectedPolicies(policies []collectedPolicy) ([]ciem.EffectivePermission, error) {
	return ciem.EffectivePermissionsForPolicies(toCIEMPolicies(policies))
}

// toCIEMPolicies converts collected policies to evaluator input, dropping trust
// policies: they govern who may assume the role, not what it may do.
func toCIEMPolicies(policies []collectedPolicy) []ciem.Policy {
	ciemPolicies := make([]ciem.Policy, 0, len(policies))
	for _, p := range policies {
		if p.Type == "trust" {
			continue
		}
		ciemPolicies = append(ciemPolicies, ciem.Policy{
			Name: p.Name, Type: p.Type, Document: p.Document, IsManaged: p.Managed, Incomplete: p.Incomplete, SCPLevel: p.SCPLevel,
		})
	}
	return ciemPolicies
}

// notActionWidenings maps each AWS principal (iam_role, iam_user) in g to the
// policies, its own plus its account's SCPs, that hold a NotAction-only Allow.
// The evaluator widens those to Allow * when the allows_action and
// secret_access rules compute their edges; rules do no I/O, so the service
// logs this map to keep that over-approximation traceable.
func notActionWidenings(g Graph) map[string][]string {
	out := map[string][]string{}
	for _, p := range g.PermissionPrincipals() {
		if p.Type != "iam_role" && p.Type != "iam_user" {
			continue
		}
		raw := p.Metadata["policies"]
		if raw == "" {
			continue
		}
		var policies []collectedPolicy
		if json.Unmarshal([]byte(raw), &policies) != nil {
			continue
		}
		policies = append(policies, applicableOrganizationPolicies(p, g.SCPPoliciesForAccount(p.AccountID))...)
		if names := ciem.NotActionAllowPolicies(toCIEMPolicies(policies)); len(names) > 0 {
			out[p.ID] = names
		}
	}
	return out
}

// dangerousActionsInPolicy parses a policy JSON document and returns the set of
// danger categories found (e.g. "iam-admin", "s3-read", "admin-wildcard") whose
// underlying action is still actually allowed per perms — the full effective-
// permission evaluation (boundary/SCP intersection, explicit-deny-wins,
// Condition-aware). A raw Allow statement here that a sibling Deny or a
// boundary/SCP cap neutralizes is found but not reported.
func dangerousActionsInPolicy(docJSON string, perms []ciem.EffectivePermission) map[string]bool {
	var doc policyDocument
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		return nil
	}

	found := map[string]bool{}
	for _, stmt := range doc.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		actions := normaliseActions(stmt.Action)
		if len(actions) == 0 && len(normaliseActions(stmt.NotAction)) > 0 {
			// "Allow NotAction: [...]" grants everything EXCEPT the listed actions.
			// Offer every dangerous action as a candidate and let the
			// ciem.HasPermission gate below decide which actually survive — the
			// evaluator already models the negation.
			actions = []string{"*"}
			for a := range dangerousActions {
				actions = append(actions, a)
			}
		}
		for _, action := range actions {
			a := strings.ToLower(action)
			if a == "*" && allowsEveryAction(perms) {
				found["admin-wildcard"] = true
				continue
			}
			if category, ok := dangerousActions[a]; ok && a != "*" {
				if ciem.HasPermission(perms, a) {
					found[category] = true
				}
				continue
			}
			// Any glob ("*" carved up by a Deny, "iam:*", "iam:Put*",
			// "s3:Get?bject"): report each concrete dangerous action it covers
			// that is still effectively allowed.
			if strings.ContainsAny(a, "*?") {
				for action2, cat := range dangerousActions {
					if action2 != "*" && ciem.WildcardMatch(a, action2) && ciem.HasPermission(perms, action2) {
						found[cat] = true
					}
				}
			}
		}
	}
	return found
}

// allowsEveryAction reports whether perms grant every action on every
// resource: an exact Allow of action "*" on resource "*" and no unconditional
// explicit Deny at all. Approximated grants cannot prove this, even though they
// retain concrete action candidates. ciem.HasPermission(perms, "*") is not this test — a
// Deny of "secretsmanager:*" does not match the literal action "*", so "Allow
// * + Deny secretsmanager:*" would still read as full admin.
func allowsEveryAction(perms []ciem.EffectivePermission) bool {
	allowed := false
	for _, p := range perms {
		if p.Effect == ciem.EffectDeny {
			return false
		}
		if p.Action == "*" && len(p.NotActions) == 0 && !p.Approximate && (p.Resource == "" || p.Resource == "*") {
			allowed = true
		}
	}
	return allowed
}

// normaliseActions converts the Action field (string or []string) to a []string.
func normaliseActions(raw any) []string {
	switch v := raw.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// policyIDFor returns the stable node ID for a collected policy.
// Managed policies use their ARN; inline policies get a synthetic ID.
func policyIDFor(role asset.Asset, p collectedPolicy) string {
	if p.Managed && strings.HasPrefix(p.Name, "arn:") {
		return p.Name // ARN is the stable ID
	}
	// Inline policy: synthetic ID scoped to the owning role.
	return "inline:" + role.ID + ":" + p.Name
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func collectedBoundaryReadUnknown(complete string, policies []collectedPolicy) bool {
	if complete != "" {
		return complete != "true"
	}
	for _, p := range policies {
		if p.Type == "boundary" {
			return false
		}
	}
	return true
}

// Keep CIEM, dangerous-action edges and secret-access edges on the same
// organization applicability decision, including the service-linked exemption.
func applicableOrganizationPolicies(principal asset.Asset, contexts []collectedPolicy) []collectedPolicy {
	policies, _ := ciem.AWSOrganizationPolicies(principal, toCIEMPolicies(contexts))
	out := make([]collectedPolicy, 0, len(policies))
	for _, policy := range policies {
		out = append(out, collectedPolicy{Type: policy.Type, Name: policy.Name, Document: policy.Document, Incomplete: policy.Incomplete, SCPLevel: policy.SCPLevel})
	}
	return out
}
