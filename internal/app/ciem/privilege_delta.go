package ciem

import "strings"

// Privilege-delta capping: a technique only escalates if it reaches something the
// principal does not already have.
//
// DetectPrivescPaths answers "does this principal hold the actions the technique
// requires" — it never asks "does the technique reach anything MORE privileged
// than the principal already is". An already-Owner/Admin principal, or one in a
// scope that contains nothing more privileged, has no escalation path left even
// when a technique's required actions are present.
//
// This CAPS severity rather than suppressing detection. The underlying grant is
// real and worth seeing: an already-Owner service account is a legitimate finding,
// just not an active escalation path, and dropping it entirely would lose the audit
// trail that the overprivileged grant exists. Capping keeps it visible while taking
// it out of the must-fix/page band.
//
// Deliberately NOT capped: an Editor-class principal in a project that does contain
// an Owner. That is a genuine Editor→Owner escalation.

// privilegeTier ranks how much authority a principal already holds, for comparison
// against what a technique could reach.
type privilegeTier int

const (
	tierNormal    privilegeTier = iota // ordinary grants — a technique can add authority
	tierSelfGrant                      // already able to grant itself arbitrary permissions
	tierAdmin                          // already admin/owner-equivalent — nothing left to reach
)

// selfGrantActions are the concrete actions that already let a principal award
// itself anything, making every indirect technique redundant with a capability it
// holds today. Matching is deny-aware (HasPermission), so a grant pattern counts
// only where nothing revokes it — and a pattern counts as well as an exact action,
// which is what Azure needs: User Access Administrator is defined as
// "Microsoft.Authorization/*", never as the concrete write action.
//
// AWS is deliberately absent; only a proven unrestricted AWS wildcard is admin. Its
// self-grant actions would be iam:PutRolePolicy and friends — but those ARE the
// required actions of aws-privesc-01/05/06, so treating them as "already
// privileged" would cap those rules using their own predicate and silence them
// entirely. GCP/Azure have no such overlap.
var selfGrantActions = map[string][]string{
	"gcp": {"resourcemanager.projects.setIamPolicy"}, // direct route to Owner
	"azure": {
		"Microsoft.Authorization/roleAssignments/write", // can grant itself any role
		"Microsoft.Authorization/elevateAccess/Action",
	},
}

// canSelfGrant reports whether some self-grant route survives the principal's
// denies. Any ONE surviving is enough: these are alternative routes to the same
// place. A provider with no routes listed answers false.
func canSelfGrant(provider string, perms []EffectivePermission) bool {
	for _, action := range selfGrantActions[provider] {
		if HasPermission(perms, action) {
			return true
		}
	}
	return false
}

// principalTier classifies how privileged a principal already is, from its
// collected roles and effective permissions.
func principalTier(provider, roles string, perms []EffectivePermission, accountID ...string) privilegeTier {
	// GCP collection is allow-only: conditional bindings and inherited deny
	// policies can restrict even Owner or projects.setIamPolicy. Those candidates
	// cannot prove existing unrestricted authority to reduce another path's severity.
	if provider == "gcp" {
		return tierNormal
	}
	if provider == "azure" {
		if len(accountID) != 1 {
			return tierNormal
		}
		return azurePrincipalTier(accountID[0], perms)
	}
	if provider == "aws" {
		return awsPrincipalTier(perms)
	}
	selfGrant := canSelfGrant(provider, perms)
	for _, p := range perms {
		if p.Effect == EffectDeny {
			continue
		}
		action := strings.TrimSpace(p.Action)
		// A bare wildcard on everything is admin (AWS "*"/"iam:*" on Resource "*",
		// Azure Actions "*") — but only if it can still self-grant. Azure's
		// Contributor is Actions "*" with NotActions over the whole Authorization
		// namespace: it can touch every resource yet cannot grant itself a role, so
		// it has plenty left to escalate to and must not be read as admin.
		if (action == "*" || action == "iam:*") && (p.Resource == "*" || p.Resource == "") {
			if selfGrant || len(selfGrantActions[provider]) == 0 {
				return tierAdmin
			}
			continue // carved out short of self-granting — not admin
		}
	}
	if selfGrant {
		return tierSelfGrant
	}
	return tierNormal
}

// awsPrincipalTier requires an unrestricted grant before lowering severity on
// the premise that the principal already holds admin authority. HasPermission
// answers the weaker question of access somewhere: a narrow Deny can leave an
// action available while restricting access to the very target a path reaches.
func awsPrincipalTier(perms []EffectivePermission) privilegeTier {
	admin := false
	for _, p := range perms {
		if p.Effect == EffectDeny {
			return tierNormal
		}
		if p.Approximate || len(p.NotActions) > 0 || len(p.NotResources) > 0 {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(p.Action))
		if action == "*" && (p.Resource == "*" || p.Resource == "") {
			admin = true
		}
	}
	if admin {
		return tierAdmin
	}
	return tierNormal
}

// A grant-writing action cannot establish unrestricted escalation while an
// observed permissions boundary or SCP still caps that grant. Evaluate the
// same guardrails against a hypothetical full identity grant to test the cap,
// without treating cap Allows as permissions the identity currently holds.
func awsGuardrailsPermitAdmin(policies []Policy) bool {
	caps := []Policy{{Type: PolicyIdentity, Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}}
	for _, policy := range policies {
		if policy.Type == PolicyBoundary || policy.Type == PolicySCP {
			caps = append(caps, policy)
		}
	}
	permissions, err := EvaluateEffectivePermissions(Principal{Policies: caps})
	return err == nil && awsPrincipalTier(permissions) == tierAdmin
}

// privilegeCeiling returns the severity ceiling implied by the privilege delta, or
// "" when the path can genuinely add authority and no cap applies.
//
// scopeMax is the highest tier held by ANY principal in the same account/project.
// A principal already at the scope maximum has nothing more privileged to reach
// within that scope (e.g. a CI runner SA in a project whose top role is Editor) — real permissions,
// no possible escalation.
func privilegeCeiling(tier, scopeMax privilegeTier) string {
	switch {
	case tier == tierAdmin:
		// Nothing above admin. The grant is still worth reporting, at low.
		return SeverityLow
	case tier == tierSelfGrant:
		// Already self-grants; indirect routes add no capability.
		return SeverityMedium
	case tier >= scopeMax && scopeMax > tierNormal:
		// The principal is as privileged as anything in its scope. Not nothing —
		// a cross-scope target may exist and this layer cannot see it — so medium,
		// not low.
		return SeverityMedium
	}
	return ""
}

// capToPrivilegeDelta lowers sev to the privilege-delta ceiling when one applies.
// Never raises: this composes with capSeverity (trust-based entry capping) by
// taking whichever ceiling is lower.
func capToPrivilegeDelta(sev string, tier, scopeMax privilegeTier) string {
	ceil := privilegeCeiling(tier, scopeMax)
	if ceil != "" && severityRank(sev) > severityRank(ceil) {
		return ceil
	}
	return sev
}
