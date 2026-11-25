package checks

// identity_dormant.go — privilege-aware dormancy. A dormant identity is hygiene;
// a dormant ADMIN identity is a standing full-account credential nobody would
// miss if it were taken over. The plain dormancy checks (aws-iam-role-unused,
// gcp-sa-unused, the stale-credential user checks) stay as Low/Medium hygiene
// for ordinary principals and step aside when the principal is a dormant admin,
// so one dormant admin is one finding graded by its privilege, not three or four
// findings about the same idle identity.
//
// Known-ness: dormancy is only ever concluded from an OBSERVED last-use reading.
// A principal whose last-use data is missing is unknown and silent. A principal
// with no recorded use at all counts as dormant only when its age is observed
// past the threshold — a role created yesterday has simply not been used yet.

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// dormantAdminDays is the idle threshold, matching the CIS 90-day
// unused-credential rule the hygiene checks already use.
const dormantAdminDays = 90

// observedOlderThanThreshold reports whether an observed day count is at least
// dormantAdminDays. Unparseable or absent is false: unknown age never proves
// dormancy.
func observedOlderThanThreshold(days string) bool {
	d, err := strconv.Atoi(days)
	return err == nil && d >= dormantAdminDays
}

// How a principal reaches admin, for the dormancy checks.
const (
	reachNone     = ""
	reachAdmin    = "admin"
	reachEscalate = "can_escalate"
)

// adminReach grades a principal for the dormancy checks: reachAdmin when it
// holds admin directly (directAdmin, the collector's verdict, or the CIEM
// privilege_tier stamp), reachEscalate when CIEM found a path from it to
// admin. A dormant principal one step from admin is the same standing
// liability as an admin one. Any other tier — "unknown" and an absent stamp
// included — is reachNone: an unread permission set never proves privilege.
func adminReach(directAdmin bool, a asset.Asset) string {
	switch {
	case directAdmin || a.Metadata["privilege_tier"] == "admin":
		return reachAdmin
	case a.Metadata["privilege_tier"] == "can_escalate_to_admin":
		return reachEscalate
	}
	return reachNone
}

// The collector's admin hint describes identity policy grants. Only CIEM's
// observed effective tier accounts for permission boundaries and SCPs.
func roleAdminReach(a asset.Asset) string {
	if a.Metadata["organization_policy_complete"] != "true" {
		return reachNone
	}
	return adminReach(false, a)
}

func saAdminReach(a asset.Asset) string {
	return adminReach(gcpAdminEquivalent(a.Metadata["roles"]), a)
}

// privilegeEvidence adds the CIEM tier stamp, when present, so a responder
// can see whether the finding is about held or reachable admin.
func privilegeEvidence(a asset.Asset, ev map[string]string) map[string]string {
	for _, k := range []string{"privilege_tier", "privilege_tier_source"} {
		if v := a.Metadata[k]; v != "" {
			ev[k] = v
		}
	}
	return ev
}

// reachTitle picks the title naming whether the principal holds admin or can
// escalate to it.
func reachTitle(reach func(asset.Asset) string, admin, escalate string) func(asset.Asset) string {
	return func(a asset.Asset) string {
		if reach(a) == reachEscalate {
			return escalate
		}
		return admin
	}
}

// dormantAdminRole reports whether an AWS role is admin (or can escalate to
// admin) and observed unused for dormantAdminDays.
//
// last_used_days comes from GetRole's RoleLastUsed, which AWS tracks over a
// trailing ~400-day window; "9999" is the collector's sentinel for "no use in
// that window", so it proves dormancy only once the role's own age
// (created_days) passes the threshold. Service-linked roles are excluded: AWS
// owns and assumes them, so there is nothing for an operator to disable.
func dormantAdminRole(a asset.Asset) bool {
	if roleAdminReach(a) == reachNone || a.Metadata["last_used_observed"] != "true" {
		return false
	}
	if strings.HasPrefix(a.Metadata["path"], "/aws-service-role/") {
		return false
	}
	if a.Metadata["last_used_days"] == "9999" {
		return observedOlderThanThreshold(a.Metadata["created_days"])
	}
	return observedOlderThanThreshold(a.Metadata["last_used_days"])
}

// dormantAdminUser reports whether an AWS user is admin (or can escalate to
// admin), still holds a usable
// credential (inactive=false: a console password or an active key), and none of
// those credentials has been used in dormantAdminDays.
//
// Both channels must be observed: password_last_used_days comes from ListUsers
// (-1 = never), access_key_last_used_days is omitted when any key's
// GetAccessKeyLastUsed failed (-1 = no active key ever used).
func dormantAdminUser(a asset.Asset) bool {
	if roleAdminReach(a) == reachNone || a.Metadata["inactive"] != "false" {
		return false
	}
	console, err := strconv.Atoi(a.Metadata["password_last_used_days"])
	if err != nil {
		return false
	}
	key, err := strconv.Atoi(a.Metadata["access_key_last_used_days"])
	if err != nil {
		return false
	}
	recent := mostRecentUse(console, key)
	if recent < 0 {
		return observedOlderThanThreshold(a.Metadata["created_days"]) // never used: age decides
	}
	return recent >= dormantAdminDays
}

// mostRecentUse returns the smaller of two non-negative day counts, ignoring
// the -1 "never used" sentinel; -1 when both are never.
func mostRecentUse(a, b int) int {
	switch {
	case a < 0:
		return b
	case b < 0:
		return a
	default:
		return min(a, b)
	}
}

// gcpAdminEquivalent reports whether a comma-separated role list holds a
// predefined role that confers project-wide control or the ability to grant
// it. roles/editor counts: it is not Owner, but it writes nearly every resource
// and can act as most service accounts, so a dormant Editor identity is the same
// standing liability. The roles are literals in the switch, not a package
// table, so the required-key scanner harvests them as probe values.
func gcpAdminEquivalent(roles string) bool {
	for _, r := range strings.Split(roles, ",") {
		switch strings.TrimSpace(r) {
		case "roles/owner", "roles/editor", "roles/iam.securityAdmin",
			"roles/resourcemanager.projectIamAdmin", "roles/resourcemanager.folderAdmin",
			"roles/resourcemanager.organizationAdmin":
			return true
		}
	}
	return false
}

// dormantAdminSA reports whether an enabled GCP service account holds an
// admin-equivalent role (or can escalate to admin) and has not authenticated
// in dormantAdminDays.
//
// sa_last_auth_days is omitted when Policy Analyzer was unavailable (unknown);
// -1 means no activity in its observation window. The IAM API exposes no
// service-account creation time, so a -1 counts as dormant only when the
// account's oldest user-managed key proves it has existed past the threshold —
// otherwise a brand-new account would read as dormant.
func dormantAdminSA(a asset.Asset) bool {
	if a.Metadata["disabled"] != "false" || saAdminReach(a) == reachNone {
		return false
	}
	days, err := strconv.Atoi(a.Metadata["sa_last_auth_days"])
	if err != nil {
		return false
	}
	if days < 0 {
		return observedOlderThanThreshold(a.Metadata["key_age_days"])
	}
	return days >= dormantAdminDays
}

// lastUseEvidence renders a last-use day count for a responder, never
// rendering a sentinel as a measurement.
func lastUseEvidence(days string) string {
	if days == "9999" || days == "-1" {
		return "never (no recorded use)"
	}
	return days
}

var awsIAMAdminRoleDormant = Check{
	ID:          "aws-iam-admin-role-dormant",
	Title:       "Admin IAM role has not been used in 90+ days",
	TitleFor:    reachTitle(roleAdminReach, "Admin IAM role has not been used in 90+ days", "IAM role that can escalate to admin has not been used in 90+ days"),
	Description: "This role holds admin-level access (AdministratorAccess or an effective Allow *:*), or holds permissions that let it escalate to admin (a detected CIEM path such as attaching a policy to itself or assuming an admin role; see privilege_tier_source), and AWS records no use of it in at least 90 days, or none at all for a role older than 90 days. A dormant admin role is a full-account credential with no operational owner: whoever can assume it — through its trust policy, a compromised trusted principal, or a forgotten federation — gets everything, and nobody watching normal activity would notice it being used. This finding replaces aws-iam-role-unused and aws-iam-overprivileged-role for the role. Service-linked roles are excluded.",
	Remediation: "Confirm nothing depends on the role (CloudTrail AssumeRole events, the trust policy's principals), then delete it: detach its policies, remove inline policies and instance profiles, `aws iam delete-role --role-name NAME`. If it is a break-glass role, keep it but require MFA in the trust policy, alert on every AssumeRole, and document the owner. For a role that can only escalate to admin, removing the escalating permission is the alternative when the role must stay.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    dormantAdminRole,
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{"last_used_days": lastUseEvidence(a.Metadata["last_used_days"])}
		if v := a.Metadata["created_days"]; v != "" {
			ev["created_days"] = v
		}
		if v := a.Metadata["trust_entry"]; v != "" {
			ev["trust_entry"] = v
		}
		return privilegeEvidence(a, ev)
	},
}

var awsIAMAdminUserDormant = Check{
	ID:          "aws-iam-admin-user-dormant",
	Title:       "Admin IAM user has not used its credentials in 90+ days",
	TitleFor:    reachTitle(roleAdminReach, "Admin IAM user has not used its credentials in 90+ days", "IAM user that can escalate to admin has not used its credentials in 90+ days"),
	Description: "This IAM user holds admin-level access, or holds permissions that let it escalate to admin (a detected CIEM path; see privilege_tier_source), and still has a usable credential (a console password or an active access key), but neither has been used in at least 90 days, or ever for a user older than 90 days. A dormant admin user is a standing full-account credential nobody would miss: a leaked key or password works immediately and its use stands out to no one. This finding replaces the stale-credential checks (aws-iam-user-unused-access-key, aws-iam-user-stale-console, aws-iam-access-key-old) for the user, since removing the user or its admin grant fixes all of them.",
	Remediation: "Confirm the user is unused (`aws iam get-access-key-last-used`, CloudTrail), then deactivate its keys (`aws iam update-access-key --status Inactive`), delete its login profile, and delete the user or detach its admin (or escalating) policies. Humans should reach admin through IAM Identity Center with MFA; workloads through roles.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates:    dormantAdminUser,
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{
			"console_last_used_days":    lastUseEvidence(a.Metadata["password_last_used_days"]),
			"access_key_last_used_days": lastUseEvidence(a.Metadata["access_key_last_used_days"]),
		}
		for _, k := range []string{"console_access", "active_key_count", "created_days"} {
			if v := a.Metadata[k]; v != "" {
				ev[k] = v
			}
		}
		return privilegeEvidence(a, ev)
	},
}

var gcpSAAdminDormant = Check{
	ID:          "gcp-sa-admin-dormant",
	Title:       "Admin-equivalent service account has not authenticated in 90+ days",
	TitleFor:    reachTitle(saAdminReach, "Admin-equivalent service account has not authenticated in 90+ days", "Service account that can escalate to admin has not authenticated in 90+ days"),
	Description: "This enabled service account holds an admin-equivalent role (Owner, Editor, Security Admin or an IAM-admin role at project, folder or organization scope), or holds permissions that let it escalate to admin (a detected CIEM path such as setting the project IAM policy or minting tokens for an Owner account; see privilege_tier_source), and Policy Analyzer records no authentication by it in at least 90 days. A dormant admin identity is a standing project-wide credential with no operational owner: anyone who can impersonate it or holds one of its keys inherits that control unnoticed. A service account with no activity in the observation window is counted only when one of its keys proves it is older than 90 days, since the API reports no creation time. This finding replaces gcp-sa-unused and gcp-sa-user-managed-key for the account.",
	Remediation: "Confirm the account is unused (Policy Analyzer → service account last authentication, audit logs), then disable it (`gcloud iam service-accounts disable SA_EMAIL`), delete its user-managed keys, and after a grace period remove its role bindings and delete it. If something still needs it, replace the admin (or escalating) role with a narrowly scoped one.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_service_account",
	Violates:    dormantAdminSA,
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{
			"last_auth_days": lastUseEvidence(a.Metadata["sa_last_auth_days"]),
			"roles":          a.Metadata["roles"],
		}
		if v := a.Metadata["key_age_days"]; v != "" {
			ev["key_age_days"] = v
		}
		return privilegeEvidence(a, ev)
	},
}
