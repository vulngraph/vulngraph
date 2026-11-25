package checks

// azure_entra.go — Entra ID tenant-wide settings (CIS Azure Foundations 5.1.x,
// 5.6, 6.1.1.7–6.1.1.9) plus the Entra hardening settings Microsoft Graph
// exposes and no CIS Azure v6 control covers (user consent, app registration,
// guest access, Global Administrator count, risk policies).
//
// Each is ONE finding on the azure_tenant_settings asset the Azure collector
// assembles from Microsoft Graph (internal/collect/azure/entra.go), shared by
// every subscription connector in the tenant. A Graph read the app has no
// permission or consent for leaves its keys absent, so every predicate fires
// on an explicit observed value only.

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const tenantSettingsType = "azure_tenant_settings"

func azureEntraChecks() []Check {
	return []Check{
		azureEntraNoMFABaseline,
		azureEntraDeviceJoinNoMFA,
		azureEntraUsersWithoutMFA,
		azureEntraRiskPoliciesMissing,
		azureEntraUserConsentUnrestricted,
		azureEntraUsersCanRegisterApps,
		azureEntraGuestInvitesUnrestricted,
		azureEntraGuestMemberAccess,
		azureEntraGlobalAdminCount,
		azureEntraLogsNotExported,
		azureIntuneLogsNotExported,
		azureSubscriptionTenantTransferAllowed,
	}
}

// mfaBaselineGaps lists what Conditional Access lacks when security defaults
// are off (CIS 5.1.1 accepts either). Nil when defaults are on or unread.
func mfaBaselineGaps(a asset.Asset) []string {
	if a.Metadata["security_defaults_enabled"] != "false" {
		return nil
	}
	var gaps []string
	if observedNone(a, "ca_mfa_all_users_policies") {
		gaps = append(gaps, "no enabled Conditional Access policy requires MFA for all users on all apps")
	}
	if observedNone(a, "ca_legacy_auth_block_policies") {
		gaps = append(gaps, "no enabled Conditional Access policy blocks legacy authentication")
	}
	return gaps
}

var azureEntraNoMFABaseline = Check{
	ID:          "azure-entra-no-mfa-baseline",
	Title:       "Security defaults are off and Conditional Access does not replace them",
	Description: "Entra security defaults are disabled, and the enabled Conditional Access policies do not provide the same baseline: MFA for every user on every app, and a block on legacy authentication (which cannot do MFA). A stolen or sprayed password is then enough to sign in. A policy counts only when it is enabled (not report-only), applies to every app, requires MFA outright (MFA OR-ed with a device or app control does not), is not narrowed to a platform, location, client app, device filter or risk level, and excludes nothing but up to two break-glass user accounts. High when one of the CIS administrator roles (Global Administrator, Privileged Role Administrator, Security Administrator and the rest of Microsoft's admin-MFA template) is not covered.",
	Remediation: "Either enable security defaults (Entra ID → Overview → Properties → Manage security defaults), or create Conditional Access policies (Entra ID → Protection → Conditional Access): \"Require MFA for all users\" (all users, all resources, grant: require MFA, exclude break-glass accounts) and \"Block legacy authentication\" (client apps: Exchange ActiveSync and other clients, grant: block). CLI: `az rest --method get --url https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies` to review.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates:    func(a asset.Asset) bool { return len(mfaBaselineGaps(a)) > 0 },
	// Admin roles left without an MFA policy is the worst case; a tenant that
	// at least forces MFA on every CIS admin role has a narrower gap.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["ca_admin_roles_without_mfa"] == "" {
			return finding.SeverityMedium
		}
		return finding.SeverityHigh
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"gaps":                       strings.Join(mfaBaselineGaps(a), "; "),
			"admin_mfa_policies":         a.Metadata["ca_mfa_admins_policies"],
			"admin_roles_without_mfa":    a.Metadata["ca_admin_roles_without_mfa"],
			"enabled_conditional_access": a.Metadata["ca_enabled_policy_count"],
		}
	},
}

// azureEntraDeviceJoinNoMFA is CIS 5.1.2. Satisfied by the device setting or
// by the Conditional Access "Register or join devices" user action requiring
// MFA (Microsoft's recommended replacement, which requires the setting off).
var azureEntraDeviceJoinNoMFA = Check{
	ID:          "azure-entra-device-join-no-mfa",
	Title:       "Joining or registering a device to Entra does not require MFA",
	Description: "Neither the device setting \"Require Multifactor Authentication to register or join devices\" nor a Conditional Access policy on the \"Register or join devices\" user action requires MFA. A password alone can then join an attacker's device to the tenant, which earns it a device identity that device-based Conditional Access trusts.",
	Remediation: "Create a Conditional Access policy: all users, User actions → Register or join devices, grant: require MFA (and leave Devices → Device settings → \"Require MFA to register or join devices\" at No, as Microsoft recommends with this policy). Without Conditional Access, set that device setting to Yes.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["device_registration_mfa"] == "notRequired" && observedNone(a, "ca_device_registration_mfa_policies")
	},
}

// azureEntraUsersWithoutMFA is CIS 5.1.3: one finding for the tenant, graded
// by whether an admin is among the users without a usable MFA method.
var azureEntraUsersWithoutMFA = Check{
	ID:          "azure-entra-users-without-mfa",
	Title:       "Enabled member users are not MFA capable",
	Description: "Enabled member accounts have not registered a multifactor method that the tenant's policy allows (the Microsoft Graph authentication-methods registration report: isMfaCapable false). Whoever learns such a user's password can sign in — or register their own MFA method first. Guests (who authenticate in their home tenant) and disabled accounts are not counted.",
	Remediation: "Require registration (security defaults, or a Conditional Access policy requiring MFA for all users, which prompts registration) and follow up with the listed users. Entra ID → Protection → Authentication methods → User registration details shows the same report; CLI: `az rest --url https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["mfa_not_capable_member_count"])
		return err == nil && n > 0
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if n, err := strconv.Atoi(a.Metadata["mfa_not_capable_admin_count"]); err == nil && n > 0 {
			return finding.SeverityHigh
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"users_without_mfa":       a.Metadata["mfa_not_capable_member_count"],
			"sample":                  a.Metadata["mfa_not_capable_members"],
			"admins_without_mfa":      a.Metadata["mfa_not_capable_admin_count"],
			"admins_without_mfa_list": a.Metadata["mfa_not_capable_admins"],
		}
	},
}

// azureEntraRiskPoliciesMissing has no CIS Azure v6 control. Only asked of a
// tenant that holds Entra ID P2 (risk conditions need it) and runs
// Conditional Access instead of security defaults.
var azureEntraRiskPoliciesMissing = Check{
	ID:          "azure-entra-risk-policies-missing",
	Title:       "Entra ID P2 tenant has no risk-based Conditional Access policy",
	Description: "The tenant is licensed for Entra ID P2 but no enabled Conditional Access policy acts on sign-in risk or user risk (require MFA, a password change, or block). Identity Protection then flags risky sign-ins — leaked credentials, impossible travel, anonymous IPs — without stopping them. No CIS Azure v6 control; the CIS Microsoft 365 benchmark has risk-policy recommendations whose IDs we have not confirmed.",
	Remediation: "Create Conditional Access policies for all users: sign-in risk High/Medium → require MFA, and user risk High → require password change (Entra ID → Protection → Conditional Access → New policy → Conditions → Sign-in risk / User risk).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["entra_p2_licensed"] == "true" && a.Metadata["security_defaults_enabled"] == "false" &&
			observedNone(a, "ca_risk_policies")
	},
}

// azureEntraUserConsentUnrestricted: the legacy user-consent policy lets any
// user grant any app every permission that does not need admin consent — the
// illicit-consent-grant phishing path.
var azureEntraUserConsentUnrestricted = Check{
	ID:          "azure-entra-user-consent-unrestricted",
	Title:       "Users can consent to any application",
	Description: "The tenant's user consent setting is \"Allow user consent for apps\" (permission grant policy microsoft-user-default-legacy): any user can grant any multi-tenant application delegated access to their mail, files and profile. Consent phishing turns that into persistent data access that survives a password reset. CIS Microsoft 365 Foundations v5.0.0 5.1.5.1 (no CIS Azure v6 control).",
	Remediation: "Entra ID → Enterprise applications → Consent and permissions → User consent settings: \"Allow user consent for apps from verified publishers, for selected permissions\" or \"Do not allow user consent\", and turn on the admin consent workflow.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates: func(a asset.Asset) bool {
		return strings.Contains(a.Metadata["user_consent_policies"], "microsoft-user-default-legacy")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"user_consent_policies": a.Metadata["user_consent_policies"]}
	},
}

var azureEntraUsersCanRegisterApps = Check{
	ID:          "azure-entra-users-can-register-apps",
	Title:       "Any user can register applications",
	Description: "Default user permissions allow every member to register applications. Each registration can hold client secrets and request permissions, so app sprawl outside review grows into unowned credentials. CIS Microsoft 365 Foundations v5.0.0 5.1.2.2 (no CIS Azure v6 control).",
	Remediation: "Entra ID → User settings → \"Users can register applications\": No, and grant the Application Developer role to the people who need it. CLI: `az rest --method patch --url https://graph.microsoft.com/v1.0/policies/authorizationPolicy --body '{\"defaultUserRolePermissions\":{\"allowedToCreateApps\":false}}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["users_can_register_apps"] == "true" },
}

var azureEntraGuestInvitesUnrestricted = Check{
	ID:          "azure-entra-guest-invites-unrestricted",
	Title:       "Anyone in the tenant, guests included, can invite guests",
	Description: "Guest invite restrictions are at \"Anyone in the organization can invite guest users including guests and non-admins\", so an existing guest can bring in further outside accounts without any administrator involved. CIS Microsoft 365 Foundations v5.0.0 5.1.6.3 (no CIS Azure v6 control).",
	Remediation: "Entra ID → External Identities → External collaboration settings → Guest invite restrictions: \"Only users assigned to specific admin roles can invite guest users\" (or at least exclude guests and non-admin members).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["guest_invites_from"] == "everyone" },
}

var azureEntraGuestMemberAccess = Check{
	ID:          "azure-entra-guest-member-access",
	Title:       "Guest users have the same directory access as members",
	Description: "Guest user access is set to \"same access as members\": every guest can enumerate all users, groups, applications and their memberships — a full map of the organisation for whoever controls a guest account. CIS Microsoft 365 Foundations v5.0.0 5.1.6.2 (no CIS Azure v6 control).",
	Remediation: "Entra ID → External Identities → External collaboration settings → Guest user access: \"Guest users have limited access\" or, better, \"Guest user access is restricted to properties and memberships of their own directory objects\".",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["guest_access_level"] == "member" },
}

// azureEntraGlobalAdminCount keeps two to four standing Global Administrators:
// more is privilege sprawl, fewer is one lost account from lockout. A
// role-assignable group counts as one; PIM-eligible admins are not active and
// are not counted.
var azureEntraGlobalAdminCount = Check{
	ID:          "azure-entra-global-admin-count",
	Title:       "Tenant does not have two to four Global Administrators",
	Description: "The number of principals holding an active Global Administrator assignment is outside two to four. More widens standing control of the whole tenant; fewer leaves it one lost account away from needing Microsoft support to recover. CIS Microsoft 365 Foundations v5.0.0 1.1.3 (no CIS Azure v6 control).",
	Remediation: "Keep two to four Global Administrators (including break-glass accounts), move day-to-day work to narrower roles, and make the rest PIM-eligible (Entra ID → Roles and administrators → Global Administrator).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["global_admin_count"])
		return err == nil && (n < 2 || n > 4)
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if n, err := strconv.Atoi(a.Metadata["global_admin_count"]); err == nil && n < 2 {
			return finding.SeverityLow
		}
		return finding.SeverityMedium
	},
	TitleFor: func(a asset.Asset) string {
		if n, err := strconv.Atoi(a.Metadata["global_admin_count"]); err == nil && n < 2 {
			return "Tenant has fewer than two Global Administrators"
		}
		return "Tenant has more than four Global Administrators"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"global_admin_count": a.Metadata["global_admin_count"], "global_admins": a.Metadata["global_admins"]}
	},
}

// missingCategories lists the required categories absent from a comma list.
func missingCategories(have string, required ...string) []string {
	got := map[string]bool{}
	for _, c := range strings.Split(have, ",") {
		got[strings.ToLower(strings.TrimSpace(c))] = true
	}
	var out []string
	for _, r := range required {
		if !got[strings.ToLower(r)] {
			out = append(out, r)
		}
	}
	return out
}

// entraLogGaps is CIS 6.1.1.7/6.1.1.8: AuditLogs always; SignInLogs and
// MicrosoftGraphActivityLogs only when the tenant holds Entra ID P1 (both
// require it). Nil when the diagnostic settings were not read.
func entraLogGaps(a asset.Asset) []string {
	cats, ok := a.Metadata["entra_diag_categories"]
	if !ok {
		return nil
	}
	required := []string{"AuditLogs"}
	if a.Metadata["entra_p1_licensed"] == "true" {
		required = append(required, "SignInLogs", "MicrosoftGraphActivityLogs")
	}
	return missingCategories(cats, required...)
}

var azureEntraLogsNotExported = Check{
	ID:          "azure-entra-logs-not-exported",
	Title:       "Entra ID logs are not exported",
	Description: "No Entra ID diagnostic setting exports the audit log (and, on P1/P2 tenants, the sign-in and Microsoft Graph activity logs). Entra keeps them for 30 days at most, so an investigation that starts later has no record of who signed in or changed the directory.",
	Remediation: "Entra ID → Monitoring → Diagnostic settings → Add: AuditLogs, SignInLogs and MicrosoftGraphActivityLogs to a Log Analytics workspace or storage account.",
	Type:        "logging",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates:    func(a asset.Asset) bool { return len(entraLogGaps(a)) > 0 },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"missing_categories": strings.Join(entraLogGaps(a), ","), "exported": a.Metadata["entra_diag_categories"]}
	},
}

// intuneLogGaps is CIS 6.1.1.9, asked only of tenants licensed for Intune.
func intuneLogGaps(a asset.Asset) []string {
	cats, ok := a.Metadata["intune_diag_workspace_categories"]
	if !ok || a.Metadata["intune_licensed"] != "true" {
		return nil
	}
	return missingCategories(cats, "AuditLogs", "OperationalLogs", "DeviceComplianceOrg", "Devices")
}

var azureIntuneLogsNotExported = Check{
	ID:          "azure-intune-logs-not-exported",
	Title:       "Intune logs are not sent to Log Analytics",
	Description: "The tenant is licensed for Intune but its diagnostic settings do not send the audit, operational, device compliance and device logs to a Log Analytics workspace, so device enrolment and policy changes are not retained for investigation.",
	Remediation: "Intune admin center → Tenant administration → Diagnostic settings → Add: AuditLogs, OperationalLogs, DeviceComplianceOrg and Devices to a Log Analytics workspace.",
	Type:        "logging",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates:    func(a asset.Asset) bool { return len(intuneLogGaps(a)) > 0 },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"missing_categories": strings.Join(intuneLogGaps(a), ",")}
	},
}

// azureSubscriptionTenantTransferAllowed is CIS 5.6: a subscription moved out
// of the tenant leaves every control the tenant applies to it.
var azureSubscriptionTenantTransferAllowed = Check{
	ID:          "azure-subscription-tenant-transfer-allowed",
	Title:       "Subscriptions can be moved into or out of the tenant",
	Description: "The tenant's subscription policy does not block subscriptions leaving the tenant, entering it, or both. A user with Owner on a subscription can then move it to a tenant they control, taking the resources out from under this tenant's identities, policies and monitoring.",
	Remediation: "Azure portal → Subscriptions → Manage policies: set \"Subscription leaving Microsoft Entra tenant\" and \"Subscription entering Microsoft Entra tenant\" to \"Permit no one\" (needs a Global Administrator with elevated access), exempting named users if a migration needs them.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   tenantSettingsType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["subscriptions_leaving_tenant_blocked"] == "false" || a.Metadata["subscriptions_entering_tenant_blocked"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"leaving_blocked":  a.Metadata["subscriptions_leaving_tenant_blocked"],
			"entering_blocked": a.Metadata["subscriptions_entering_tenant_blocked"],
		}
	},
}
