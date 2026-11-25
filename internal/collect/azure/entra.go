package azure

import (
	"context"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Entra ID (Microsoft Graph) tenant settings: CIS Azure Foundations 5.1.x and
// the Entra hardening settings Graph exposes (user consent, app registration,
// guest access, Global Administrator count). Every read is a GET; each one that
// fails — most often a missing application permission or admin consent, which
// Graph answers with 403 — leaves its keys absent, so the checks report the
// setting as unknown, never as passing. A failed Graph read does not mark the
// sweep partial: the tenant asset is still emitted, so no asset goes missing.

// mfaRecord is one row of the authentication-methods registration report.
type mfaRecord struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	UserType          string `json:"userType"`
	IsAdmin           bool   `json:"isAdmin"`
	IsMfaCapable      bool   `json:"isMfaCapable"`
	IsMfaRegistered   bool   `json:"isMfaRegistered"`
}

// entraFacts are the per-user Graph reads the subscription-level joins need
// (CIS 5.3.5, 3.1.1). A nil map means the read failed.
type entraFacts struct {
	disabledUsers map[string]string    // object id → UPN
	mfa           map[string]mfaRecord // object id → registration row
}

// mfaSampleSize caps the user names a finding carries as evidence; the count
// is always exact.
const mfaSampleSize = 25

// graphRead is one tenant-settings read: path, and how its JSON becomes keys.
type graphRead struct {
	name string
	run  func(context.Context) (map[string]string, error)
}

// collectEntra reads the Entra tenant settings into tenant and returns the
// per-user facts for the subscription joins.
func collectEntra(ctx context.Context, g *restClient, tenant *settingsAsset) entraFacts {
	reads := []graphRead{
		{"security defaults", func(ctx context.Context) (map[string]string, error) {
			var v struct {
				IsEnabled *bool `json:"isEnabled"`
			}
			if err := g.getJSON(ctx, "/policies/identitySecurityDefaultsEnforcementPolicy", nil, &v); err != nil {
				return nil, err
			}
			if v.IsEnabled == nil {
				return nil, nil
			}
			return map[string]string{"security_defaults_enabled": strconv.FormatBool(*v.IsEnabled)}, nil
		}},
		{"conditional access policies", func(ctx context.Context) (map[string]string, error) {
			policies, err := listAll[caPolicy](ctx, g, "/identity/conditionalAccess/policies", nil)
			if err != nil {
				return nil, err
			}
			return conditionalAccessSettings(policies), nil
		}},
		{"device registration policy", func(ctx context.Context) (map[string]string, error) {
			var v struct {
				MultiFactorAuthConfiguration string `json:"multiFactorAuthConfiguration"`
			}
			if err := g.getJSON(ctx, "/policies/deviceRegistrationPolicy", nil, &v); err != nil {
				return nil, err
			}
			if v.MultiFactorAuthConfiguration == "" {
				return nil, nil
			}
			return map[string]string{"device_registration_mfa": v.MultiFactorAuthConfiguration}, nil
		}},
		{"authorization policy", func(ctx context.Context) (map[string]string, error) {
			var v authorizationPolicy
			if err := g.getJSON(ctx, "/policies/authorizationPolicy", nil, &v); err != nil {
				return nil, err
			}
			return v.settings(), nil
		}},
		{"subscribed SKUs", func(ctx context.Context) (map[string]string, error) {
			skus, err := listAll[subscribedSku](ctx, g, "/subscribedSkus", nil)
			if err != nil {
				return nil, err
			}
			return licenseSettings(skus), nil
		}},
		{"global administrator assignments", func(ctx context.Context) (map[string]string, error) {
			rows, err := listAll[struct {
				PrincipalID string `json:"principalId"`
			}](ctx, g, "/roleManagement/directory/roleAssignments?$filter=roleDefinitionId%20eq%20%27"+globalAdminRoleTemplateID+"%27", nil)
			if err != nil {
				return nil, err
			}
			principals := set()
			for _, r := range rows {
				principals[r.PrincipalID] = struct{}{}
			}
			ids := sortedKeys(principals)
			return map[string]string{
				"global_admin_count": strconv.Itoa(len(ids)),
				"global_admins":      strings.Join(ids, ","),
			}, nil
		}},
	}
	for _, r := range reads {
		kv, err := r.run(ctx)
		if err != nil {
			logGraphSkip(ctx, r.name, err)
			continue
		}
		tenant.set(kv)
	}

	var facts entraFacts
	if users, err := listAll[struct {
		ID                string `json:"id"`
		UserPrincipalName string `json:"userPrincipalName"`
	}](ctx, g, "/users?$filter=accountEnabled%20eq%20false&$select=id,userPrincipalName&$count=true&$top=999",
		map[string]string{"ConsistencyLevel": "eventual"}); err != nil {
		logGraphSkip(ctx, "disabled users", err)
	} else {
		facts.disabledUsers = make(map[string]string, len(users))
		for _, u := range users {
			facts.disabledUsers[u.ID] = u.UserPrincipalName
		}
	}
	if rows, err := listAll[mfaRecord](ctx, g, "/reports/authenticationMethods/userRegistrationDetails", nil); err != nil {
		logGraphSkip(ctx, "user MFA registration", err)
	} else {
		facts.mfa = make(map[string]mfaRecord, len(rows))
		for _, r := range rows {
			facts.mfa[r.ID] = r
		}
	}
	tenant.set(mfaSettings(facts))
	return facts
}

// mfaSettings renders CIS 5.1.3: enabled member users that are not MFA
// capable. Needs both the registration report and the disabled-user list (a
// disabled account cannot sign in, so it is not a gap); either missing leaves
// the keys absent.
func mfaSettings(f entraFacts) map[string]string {
	if f.mfa == nil || f.disabledUsers == nil {
		return nil
	}
	var members, admins []string
	for id, r := range f.mfa {
		if !strings.EqualFold(r.UserType, "member") || r.IsMfaCapable {
			continue
		}
		if _, disabled := f.disabledUsers[id]; disabled {
			continue
		}
		members = append(members, r.UserPrincipalName)
		if r.IsAdmin {
			admins = append(admins, r.UserPrincipalName)
		}
	}
	return map[string]string{
		"mfa_not_capable_member_count": strconv.Itoa(len(members)),
		"mfa_not_capable_members":      sample(members),
		"mfa_not_capable_admin_count":  strconv.Itoa(len(admins)),
		"mfa_not_capable_admins":       sample(admins),
	}
}

// sample renders up to mfaSampleSize sorted, distinct names.
func sample(names []string) string {
	uniq := set()
	addAll(uniq, names)
	s := sortedKeys(uniq)
	if len(s) > mfaSampleSize {
		s = s[:mfaSampleSize]
	}
	return strings.Join(s, ", ")
}

func logGraphSkip(ctx context.Context, what string, err error) {
	log.FromContext(ctx).Warn().Err(err).Str("read", what).Int("status", statusCode(err)).
		Msg("azure entra read skipped; settings it backs are unknown (check Graph application permissions and admin consent)")
}

// Directory role templates for the guest-user access levels
// (authorizationPolicy.guestUserRoleId).
const (
	guestRoleMember     = "a0b1b346-4d3e-4e8b-98f8-753987be4970" // same access as members
	guestRoleLimited    = "10dae51f-b6af-4016-8d66-8c2a99b929b3" // default
	guestRoleRestricted = "2af84b1e-32c8-42b7-82bc-daa82404023b" // own directory objects only
)

// authorizationPolicy is the tenant-wide Graph authorizationPolicy.
type authorizationPolicy struct {
	AllowInvitesFrom           string `json:"allowInvitesFrom"`
	GuestUserRoleID            string `json:"guestUserRoleId"`
	DefaultUserRolePermissions *struct {
		AllowedToCreateApps             *bool    `json:"allowedToCreateApps"`
		PermissionGrantPoliciesAssigned []string `json:"permissionGrantPoliciesAssigned"`
	} `json:"defaultUserRolePermissions"`
}

// settings renders user consent, app registration and guest settings. A field
// Graph omitted stays absent.
func (p authorizationPolicy) settings() map[string]string {
	out := map[string]string{}
	if p.AllowInvitesFrom != "" {
		out["guest_invites_from"] = p.AllowInvitesFrom
	}
	switch p.GuestUserRoleID {
	case guestRoleMember:
		out["guest_access_level"] = "member"
	case guestRoleLimited:
		out["guest_access_level"] = "limited"
	case guestRoleRestricted:
		out["guest_access_level"] = "restricted"
	}
	if d := p.DefaultUserRolePermissions; d != nil {
		if d.AllowedToCreateApps != nil {
			out["users_can_register_apps"] = strconv.FormatBool(*d.AllowedToCreateApps)
		}
		if d.PermissionGrantPoliciesAssigned != nil {
			var consent []string
			for _, id := range d.PermissionGrantPoliciesAssigned {
				// Only the self-consent policies govern what a user may grant an app.
				if strings.HasPrefix(id, "ManagePermissionGrantsForSelf.") {
					consent = append(consent, strings.TrimPrefix(id, "ManagePermissionGrantsForSelf."))
				}
			}
			out["user_consent_policies"] = joinNames(consent)
		}
	}
	return out
}

// intuneServicePlans are the Intune service plan names (Microsoft's licensing
// service-plan reference): Plan 1 and its volume, government, Education and
// Business Premium (SMB) variants. INTUNE_O365 (basic mobility for Office 365)
// is not Intune and has no Intune diagnostic settings.
var intuneServicePlans = []string{"INTUNE_A", "INTUNE_A_VL", "INTUNE_A_GOV", "INTUNE_EDU", "INTUNE_SMBIZ"}

func intuneLicensed(has map[string]bool) bool {
	for _, p := range intuneServicePlans {
		if has[p] {
			return true
		}
	}
	return false
}

// subscribedSku is one Graph subscribedSku: a purchased license and the
// service plans it carries.
type subscribedSku struct {
	CapabilityStatus string `json:"capabilityStatus"`
	ServicePlans     []struct {
		ServicePlanName    string `json:"servicePlanName"`
		ProvisioningStatus string `json:"provisioningStatus"`
	} `json:"servicePlans"`
}

// licenseSettings records which licensed features the tenant has. Checks use
// them to stay silent where a control needs a license the tenant lacks (risk
// policies need P2; sign-in and Graph activity logs need P1; Intune logs
// need Intune).
func licenseSettings(skus []subscribedSku) map[string]string {
	has := map[string]bool{}
	for _, s := range skus {
		if s.CapabilityStatus != "Enabled" && s.CapabilityStatus != "Warning" {
			continue
		}
		for _, sp := range s.ServicePlans {
			if sp.ProvisioningStatus == "Success" {
				has[sp.ServicePlanName] = true
			}
		}
	}
	return map[string]string{
		"entra_p1_licensed": strconv.FormatBool(has["AAD_PREMIUM"] || has["AAD_PREMIUM_P2"]),
		"entra_p2_licensed": strconv.FormatBool(has["AAD_PREMIUM_P2"]),
		"intune_licensed":   strconv.FormatBool(intuneLicensed(has)),
	}
}
