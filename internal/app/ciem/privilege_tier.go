package ciem

import (
	"sort"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Privilege tiers stamped on identity assets (metadata privilege_tier) so the
// posture checks, which only see collector output, can grade a principal by
// what it can reach and not only by the collector's direct-admin flag.
//
// Unknown is never folded into standard: a principal whose permission set was
// not fully read has no tier to state.
const (
	MetaPrivilegeTier       = "privilege_tier"
	MetaPrivilegeTierSource = "privilege_tier_source"

	// TierAdmin: already admin/owner-equivalent.
	TierAdmin = "admin"
	// TierCanEscalateToAdmin: not admin, but a detected path grants itself
	// arbitrary permissions or reaches an admin principal.
	TierCanEscalateToAdmin = "can_escalate_to_admin"
	// TierHigh: a detected path reaches another identity's credentials,
	// secrets or data (every other CIEM technique), short of proven admin.
	TierHigh = "high"
	// TierStandard: permissions fully read, no admin grant, no detected path.
	TierStandard = "standard"
	// TierUnknown: the permission set was not (fully) collected or could not
	// be evaluated.
	TierUnknown = "unknown"

	// Sources. Escalation tiers name the establishing rule: "ciem:<rule id>".
	TierSourceCIEM       = "ciem"
	TierSourceCollector  = "collector"
	TierSourceSelfGrant  = "ciem:self_grant"
	TierSourceNoPermData = "no_permission_data"
)

// TierVerdict is one principal's tier and the evidence it rests on.
type TierVerdict struct {
	Tier   string
	Source string
}

// adminGrantRules are the techniques whose effect is to write an arbitrary
// permission grant (an admin policy, a custom role, a role assignment) for the
// principal or one it controls, so holding them is one step from admin. Like
// detection itself this is action-only (see PrivescResult.Resources). Rules
// that only reach ANOTHER principal's authority are absent: they reach admin
// only when that principal is admin, which reachesAdmin checks separately.
var adminGrantRules = map[string]bool{
	"aws-privesc-01":   true, // CreatePolicyVersion
	"aws-privesc-03":   true, // AttachUserPolicy
	"aws-privesc-04":   true, // AttachRolePolicy
	"aws-privesc-05":   true, // PutUserPolicy
	"aws-privesc-06":   true, // PutRolePolicy
	"aws-privesc-20":   true, // CreateUser + AttachUserPolicy
	"aws-privesc-21":   true, // AttachGroupPolicy
	"aws-privesc-22":   true, // PutGroupPolicy
	"gcp-privesc-01":   true, // projects.setIamPolicy
	"gcp-privesc-10":   true, // roles.update
	"azure-privesc-01": true, // roleAssignments/write
	"azure-privesc-02": true, // roleDefinitions/write
	"azure-privesc-10": true, // directory role write
	"azure-privesc-14": true, // create user + assign directory role
	"azure-privesc-15": true, // Owner at subscription scope
}

// permissionDataObserved reports whether the principal's collected permission
// set is present under its provider's metadata key. A GCP partial union retains
// candidates but explicitly withholds completeness; absence is also unknown.
func permissionDataObserved(a asset.Asset) bool {
	switch a.Provider {
	case asset.ProviderGCP:
		_, ok := a.Metadata["permissions"]
		return ok && a.Metadata["permissions_complete"] == "true"
	case asset.ProviderAzure:
		if a.Metadata["role_grants_complete"] != "true" {
			return false
		}
		raw := a.Metadata["role_grants"]
		if raw == "" {
			perms, observed := a.Metadata["permissions"]
			return observed && perms == "" // freshly observed zero assignments
		}
		grants, err := parseAzureRoleGrants(raw)
		if err != nil || grants == nil {
			return false
		}
		for _, grant := range grants {
			if _, known := normalizeAzureScope(grant.Scope); !known || !grant.EvidenceComplete {
				return false
			}
		}
		return true
	default:
		_, ok := a.Metadata["policies"]
		return ok && a.Metadata[MetaAWSOrganizationComplete] == "true"
	}
}

// Graded reports whether CIEM evaluated the principal's permissions: a tier
// other than unknown is stamped AND the permission set it grades is present.
// A collector-flagged admin (source "collector") whose permissions were never
// read carries tier admin but no evaluation, so it is not graded.
func Graded(a asset.Asset) bool {
	tier := a.Metadata[MetaPrivilegeTier]
	return tier != "" && tier != TierUnknown && permissionDataObserved(a)
}

// classifyTiers assigns every IAM asset a tier. tierByAsset holds the
// principals whose permissions evaluated; pathsByAsset their detected paths.
func classifyTiers(assets []asset.Asset, tierByAsset map[string]privilegeTier, pathsByAsset map[string][]PrivescResult, adminEscalationProven map[string]bool) map[string]TierVerdict {
	admins := map[string]bool{}
	scopeHasAdmin := map[string]bool{}
	for _, a := range assets {
		if !isIAMAsset(a.Type) {
			continue
		}
		if tierByAsset[a.ID] == tierAdmin {
			admins[a.ID] = true
			scopeHasAdmin[a.AccountID] = true
		}
	}

	out := make(map[string]TierVerdict)
	for _, a := range assets {
		if !isIAMAsset(a.Type) {
			continue
		}
		tier, evaluated := tierByAsset[a.ID]
		switch {
		case tier == tierAdmin:
			out[a.ID] = TierVerdict{TierAdmin, TierSourceCIEM}
		case !evaluated || !permissionDataObserved(a):
			out[a.ID] = TierVerdict{TierUnknown, TierSourceNoPermData}
		case tier == tierSelfGrant:
			out[a.ID] = TierVerdict{TierCanEscalateToAdmin, TierSourceSelfGrant}
		default:
			verdict := escalationVerdict(pathsByAsset[a.ID], admins, scopeHasAdmin[a.AccountID])
			if (a.Provider == asset.ProviderAzure || a.Provider == asset.ProviderGCP || a.Provider == asset.ProviderAWS && !adminEscalationProven[a.ID]) && verdict.Tier == TierCanEscalateToAdmin {
				// Allow-only role-write candidates do not establish unrestricted
				// self-grant authority. Proven broad writes, when available,
				// already take the tierSelfGrant case above. AWS grants also cannot
				// prove escalation beyond a boundary or organization ceiling.
				verdict.Tier = TierHigh
			}
			out[a.ID] = verdict
		}
	}
	return out
}

// escalationVerdict grades a non-admin principal by its detected paths. The
// lowest rule id decides the source, so the stamp is stable across sweeps.
func escalationVerdict(paths []PrivescResult, admins map[string]bool, scopeHasAdmin bool) TierVerdict {
	if len(paths) == 0 {
		return TierVerdict{TierStandard, TierSourceCIEM}
	}
	sorted := append([]PrivescResult(nil), paths...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Rule.ID < sorted[j].Rule.ID })
	for _, p := range sorted {
		if reachesAdmin(p, admins, scopeHasAdmin) {
			return TierVerdict{TierCanEscalateToAdmin, "ciem:" + p.Rule.ID}
		}
	}
	return TierVerdict{TierHigh, "ciem:" + sorted[0].Rule.ID}
}

// reachesAdmin reports whether a path ends at admin authority: it writes an
// arbitrary grant, names an admin principal as a concrete target, or is
// unbounded (AnyPrincipal) in a scope that holds an admin principal.
func reachesAdmin(p PrivescResult, admins map[string]bool, scopeHasAdmin bool) bool {
	if adminGrantRules[p.Rule.ID] {
		return true
	}
	for _, t := range p.TargetPrincipals {
		if admins[t] {
			return true
		}
	}
	return p.TargetPrincipal == AnyPrincipal && scopeHasAdmin
}

// StampTiers writes each verdict onto the matching asset's metadata. Assets
// without a verdict (not identities) are left untouched.
func StampTiers(assets []asset.Asset, tiers map[string]TierVerdict) {
	for i := range assets {
		v, ok := tiers[assets[i].ID]
		if !ok {
			continue
		}
		meta := make(map[string]string, len(assets[i].Metadata))
		for k, val := range assets[i].Metadata {
			meta[k] = val
		}
		meta[MetaPrivilegeTier] = v.Tier
		meta[MetaPrivilegeTierSource] = v.Source
		assets[i].Metadata = meta
	}
}
