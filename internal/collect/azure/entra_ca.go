package azure

import (
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// globalAdminRoleTemplateID is the Global Administrator directory role
// template, identical in every tenant.
const globalAdminRoleTemplateID = "62e90394-69f5-4237-9190-012177145e10"

// cisAdminRoles are the administrator directory roles (template IDs, the same
// in every tenant) an MFA policy must cover when Conditional Access replaces
// security defaults: the role set of Microsoft's "Require multifactor
// authentication for admins" template, which is the list in CIS's
// administrative-roles MFA recommendation.
var cisAdminRoles = map[string]string{
	globalAdminRoleTemplateID:              "Global Administrator",
	"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
	"c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
	"b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
	"158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
	"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
	"29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
	"f2ef992c-3afb-46b9-b7cf-a126ee74c451": "Global Reader",
	"729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
	"7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
	"e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
	"194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
	"f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
	"fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
	"966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
}

// breakGlassMaxExcludedUsers is the one exclusion a baseline policy may carry:
// Microsoft's emergency-access guidance excludes (normally two) cloud-only
// break-glass accounts from Conditional Access. Excluded groups, roles, guests
// or applications, or more users than this, narrow the policy.
const breakGlassMaxExcludedUsers = 2

// caPolicy is the subset of a Microsoft Graph conditionalAccessPolicy the
// baseline analysis reads.
type caPolicy struct {
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	Conditions  struct {
		Users struct {
			IncludeUsers                 []string        `json:"includeUsers"`
			IncludeRoles                 []string        `json:"includeRoles"`
			ExcludeUsers                 []string        `json:"excludeUsers"`
			ExcludeGroups                []string        `json:"excludeGroups"`
			ExcludeRoles                 []string        `json:"excludeRoles"`
			ExcludeGuestsOrExternalUsers json.RawMessage `json:"excludeGuestsOrExternalUsers"`
		} `json:"users"`
		Applications struct {
			IncludeApplications []string `json:"includeApplications"`
			ExcludeApplications []string `json:"excludeApplications"`
			IncludeUserActions  []string `json:"includeUserActions"`
		} `json:"applications"`
		ClientAppTypes   []string        `json:"clientAppTypes"`
		SignInRiskLevels []string        `json:"signInRiskLevels"`
		UserRiskLevels   []string        `json:"userRiskLevels"`
		Platforms        json.RawMessage `json:"platforms"`
		Devices          json.RawMessage `json:"devices"`
		Locations        *struct {
			IncludeLocations []string `json:"includeLocations"`
		} `json:"locations"`
	} `json:"conditions"`
	GrantControls *struct {
		Operator               string          `json:"operator"`
		BuiltInControls        []string        `json:"builtInControls"`
		AuthenticationStrength json.RawMessage `json:"authenticationStrength"`
	} `json:"grantControls"`
}

// conditionalAccessSettings derives the tenant's Conditional Access baseline
// from a fully read policy list. Only policies in state "enabled" count:
// report-only policies enforce nothing. Each key lists the enforcing policy
// names ("" = an observed none), so the evidence says which policy satisfies
// the control; ca_admin_roles_without_mfa lists the CIS admin roles that no
// baseline MFA policy covers.
func conditionalAccessSettings(policies []caPolicy) map[string]string {
	var mfaAll, mfaAdmins, legacy, risk, deviceReg []string
	adminCovered := set()
	enabled := 0
	for _, p := range policies {
		if p.State != "enabled" {
			continue
		}
		enabled++
		name := p.DisplayName
		if p.requiresMFA() && p.allApps() && !p.narrowed() && !p.excludesBeyondBreakGlass() {
			switch roles := adminRolesIn(p.Conditions.Users.IncludeRoles); {
			case p.allUsers():
				mfaAll = append(mfaAll, name)
				mfaAdmins = append(mfaAdmins, name)
				for id := range cisAdminRoles {
					adminCovered[id] = struct{}{}
				}
			case len(roles) > 0:
				mfaAdmins = append(mfaAdmins, name)
				addAll(adminCovered, roles)
			}
		}
		if p.blocksLegacyAuth() && !p.excludesBeyondBreakGlass() {
			legacy = append(legacy, name)
		}
		if p.allUsers() && p.hasRiskCondition() && (p.requiresMFA() || p.grants("block") || p.grants("passwordChange")) {
			risk = append(risk, name)
		}
		if p.allUsers() && p.requiresMFA() && !p.excludesBeyondBreakGlass() &&
			slices.Contains(p.Conditions.Applications.IncludeUserActions, "urn:user:registerdevice") {
			deviceReg = append(deviceReg, name)
		}
	}
	var uncovered []string
	for id, roleName := range cisAdminRoles {
		if _, ok := adminCovered[id]; !ok {
			uncovered = append(uncovered, roleName)
		}
	}
	return map[string]string{
		"ca_enabled_policy_count":             strconv.Itoa(enabled),
		"ca_mfa_all_users_policies":           joinNames(mfaAll),
		"ca_mfa_admins_policies":              joinNames(mfaAdmins),
		"ca_admin_roles_without_mfa":          joinNames(uncovered),
		"ca_legacy_auth_block_policies":       joinNames(legacy),
		"ca_risk_policies":                    joinNames(risk),
		"ca_device_registration_mfa_policies": joinNames(deviceReg),
	}
}

// adminRolesIn returns the CIS admin role template IDs among includeRoles.
func adminRolesIn(roles []string) []string {
	var out []string
	for _, r := range roles {
		if _, ok := cisAdminRoles[r]; ok {
			out = append(out, r)
		}
	}
	return out
}

// excludesBeyondBreakGlass reports whether the policy excludes anything but
// up to breakGlassMaxExcludedUsers individual users.
func (p caPolicy) excludesBeyondBreakGlass() bool {
	u := p.Conditions.Users
	return len(u.ExcludeUsers) > breakGlassMaxExcludedUsers || len(u.ExcludeGroups) > 0 || len(u.ExcludeRoles) > 0 ||
		present(u.ExcludeGuestsOrExternalUsers) || len(p.Conditions.Applications.ExcludeApplications) > 0
}

func (p caPolicy) allUsers() bool { return slices.Contains(p.Conditions.Users.IncludeUsers, "All") }

func (p caPolicy) allApps() bool {
	return slices.Contains(p.Conditions.Applications.IncludeApplications, "All")
}

func (p caPolicy) grants(control string) bool {
	return p.GrantControls != nil && slices.Contains(p.GrantControls.BuiltInControls, control)
}

// requiresMFA: the built-in "mfa" control or an authentication strength (which
// is always multifactor) that cannot be satisfied any other way. With operator
// OR, a second control (a compliant device, an approved app) would let a
// sign-in through without MFA, so it only counts when it is the sole control
// or the operator is AND.
func (p caPolicy) requiresMFA() bool {
	g := p.GrantControls
	if g == nil || (!p.grants("mfa") && !present(g.AuthenticationStrength)) {
		return false
	}
	for _, c := range g.BuiltInControls {
		if c != "mfa" && !strings.EqualFold(g.Operator, "AND") {
			return false
		}
	}
	return true
}

// narrowed reports whether a condition limits the policy to a subset of
// sign-ins — a risk level, a platform, a device filter, specific client apps,
// or specific locations — so it is not a baseline for everyone.
func (p caPolicy) narrowed() bool {
	c := p.Conditions
	if p.hasRiskCondition() || present(c.Platforms) || deviceFiltered(c.Devices) {
		return true
	}
	if c.Locations != nil && !slices.Contains(c.Locations.IncludeLocations, "All") {
		return true
	}
	return len(c.ClientAppTypes) > 0 && !slices.Contains(c.ClientAppTypes, "all")
}

func (p caPolicy) hasRiskCondition() bool {
	return len(p.Conditions.SignInRiskLevels) > 0 || len(p.Conditions.UserRiskLevels) > 0
}

// blocksLegacyAuth: a block for everyone, every app, on both legacy client app
// types (Exchange ActiveSync and "other clients").
func (p caPolicy) blocksLegacyAuth() bool {
	apps := p.Conditions.ClientAppTypes
	return p.grants("block") && p.allUsers() && p.allApps() &&
		slices.Contains(apps, "exchangeActiveSync") && slices.Contains(apps, "other")
}

// deviceFiltered reports whether conditions.devices carries a device filter.
func deviceFiltered(raw json.RawMessage) bool {
	if !present(raw) {
		return false
	}
	var d struct {
		DeviceFilter json.RawMessage `json:"deviceFilter"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return true // unreadable: do not treat the policy as covering everyone
	}
	return present(d.DeviceFilter)
}

// present reports whether a raw JSON field carried a value (not omitted, not null).
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// joinNames renders policy or principal names sorted and "; "-separated (CA
// policy display names may contain commas).
func joinNames(names []string) string {
	sorted := slices.Clone(names)
	sort.Strings(sorted)
	return strings.Join(slices.Compact(sorted), "; ")
}
