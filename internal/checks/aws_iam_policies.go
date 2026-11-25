package checks

// aws_iam_policies.go — admin and wildcard grants read from IAM policy
// documents the collector already fetches (CIS AWS 2.6/2.7/2.14, FSBP
// IAM.1/IAM.6/IAM.21/KMS.1/KMS.2), and the root user's MFA type and use.
//
// One finding per root cause: a customer-managed policy granting *:* is
// reported on the policy, and the principals holding admin only through such
// policies step aside for it; a dormant admin, an over-privileged role with
// Access Advisor evidence and an IAM Identity Center role step aside for the
// checks that already report them.

import (
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsIAMPolicyChecks() []Check {
	return []Check{
		awsIAMPolicyFullAdmin,
		awsIAMPolicyServiceWildcard,
		awsIAMPolicyKMSDecryptAll,
		awsIAMUserInlineKMSDecryptAll,
		awsIAMRoleInlineKMSDecryptAll,
		awsIAMUserFullAdmin,
		awsIAMRoleFullAdmin,
		awsIAMRootVirtualMFA,
		awsIAMRootRecentlyUsed,
		awsIAMUserCloudShellFullAccess,
		awsIAMRoleCloudShellFullAccess,
	}
}

// cloudShellFullAccess is CIS AWS 2.20; an admin principal steps aside, its
// admin grant already covers everything CloudShell offers.
func cloudShellFullAccess(a asset.Asset) bool {
	return a.Metadata["cloudshell_full_access"] == "true" && roleAdminReach(a) != reachAdmin
}

const cloudShellDescription = "The AWSCloudShellFullAccess managed policy is attached. It allows uploading and downloading files to and from a CloudShell environment, a file-transfer path out of the account that bypasses the network controls around it. CIS AWS 2.20."

const cloudShellRemediation = "Detach AWSCloudShellFullAccess (`aws iam detach-user-policy` / `detach-role-policy --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess`) and, if CloudShell is needed, grant a custom policy that denies cloudshell:GetFileDownloadUrls and cloudshell:GetFileUploadUrls."

var awsIAMUserCloudShellFullAccess = Check{
	ID:          "aws-iam-user-cloudshell-full-access",
	Title:       "IAM user has AWSCloudShellFullAccess attached",
	Description: cloudShellDescription,
	Remediation: cloudShellRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates:    cloudShellFullAccess,
}

var awsIAMRoleCloudShellFullAccess = Check{
	ID:          "aws-iam-role-cloudshell-full-access",
	Title:       "IAM role has AWSCloudShellFullAccess attached",
	Description: cloudShellDescription,
	Remediation: cloudShellRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    cloudShellFullAccess,
}

// dateProbes stand in for an absent timestamp key when Evaluable asks whether
// a clock-reading predicate could have fired: one long past and one far in
// the future, so neither "old enough" nor "recent" silence on an unread date
// is ever taken for a clean resource. Harvested literals cannot do this — no
// fixed date stays recent.
var dateProbes = []string{"2000-01-01T00:00:00Z", "9999-12-31T00:00:00Z"}

// daysSinceTimestamp is the whole days from an RFC3339 timestamp to now; ok is
// false when the value does not parse (absent, or the "" never sentinel).
func daysSinceTimestamp(v string) (int, bool) {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return 0, false
	}
	return int(time.Since(t).Hours() / 24), true
}

// customerPolicy is a customer-managed policy the FSBP IAM.1/IAM.21/KMS.1
// rules grade: one used only as a permissions boundary is excluded
// (excludePermissionBoundaryPolicy, their default) — a boundary caps, it
// grants nothing.
func customerPolicy(a asset.Asset) bool {
	boundaryOnly := a.Metadata["attachment_count"] == "0" && a.Metadata["boundary_usage_count"] != "0" && a.Metadata["boundary_usage_count"] != ""
	return a.Metadata["managed_by"] == "customer" && !boundaryOnly
}

// unattachedPolicyLow grades a policy attached to nobody Low: it grants no one
// anything until someone attaches it.
func unattachedPolicyLow(attached finding.Severity) func(asset.Asset) finding.Severity {
	return func(a asset.Asset) finding.Severity {
		if a.Metadata["attachment_count"] == "0" {
			return finding.SeverityLow
		}
		return attached
	}
}

var awsIAMPolicyFullAdmin = Check{
	ID:          "aws-iam-policy-full-admin",
	Title:       "Customer-managed IAM policy grants full administrator access",
	Description: "This customer-managed policy has a statement allowing Action \"*\" on Resource \"*\", so every user, group and role it is attached to can do anything in the account, including granting itself more. Least privilege starts with not having a home-made AdministratorAccess. A policy attached to nobody is graded Low; one used only as a permissions boundary is not reported (it caps, it grants nothing). CIS AWS 2.14, FSBP IAM.1.",
	Remediation: "Replace the *:* statement with the actions and resources the attached principals actually use (IAM Access Analyzer policy generation from CloudTrail helps), then `aws iam create-policy-version --policy-arn ARN --policy-document file://scoped.json --set-as-default`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_policy",
	Violates:    func(a asset.Asset) bool { return customerPolicy(a) && a.Metadata["full_admin"] == "true" },
	SeverityFor: unattachedPolicyLow(finding.SeverityHigh),
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["attachment_count"] == "0" {
			return "Unattached customer-managed IAM policy grants full administrator access"
		}
		return "Customer-managed IAM policy grants full administrator access"
	},
}

var awsIAMPolicyServiceWildcard = Check{
	ID:          "aws-iam-policy-service-wildcard",
	Title:       "Customer-managed IAM policy allows every action of a service",
	Description: "This customer-managed policy allows \"service:*\" actions (see service_wildcard_actions), granting every current and future action of those services, including their administrative and data-destroying ones. FSBP IAM.21.",
	Remediation: "List the specific actions the attached principals need for each wildcarded service and replace the service:* entries with them.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_policy",
	Violates: func(a asset.Asset) bool {
		return customerPolicy(a) && a.Metadata["service_wildcard_actions"] != "" && a.Metadata["full_admin"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"service_wildcard_actions": a.Metadata["service_wildcard_actions"]}
	},
}

var awsIAMPolicyKMSDecryptAll = Check{
	ID:          "aws-iam-policy-kms-decrypt-all",
	Title:       "Customer-managed IAM policy allows decrypting with every KMS key",
	Description: "This customer-managed policy allows kms:Decrypt or kms:ReEncryptFrom on Resource \"*\", so its principals can decrypt data protected by any KMS key whose key policy defers to IAM — the usual default. A full-admin policy is reported by aws-iam-policy-full-admin instead. FSBP KMS.1.",
	Remediation: "Scope the statement's Resource to the key ARNs the principals need, or add a kms:ViaService / kms:EncryptionContext condition.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_policy",
	Violates: func(a asset.Asset) bool {
		return customerPolicy(a) && a.Metadata["kms_decrypt_all_resources"] == "true" && a.Metadata["full_admin"] == "false"
	},
	SeverityFor: unattachedPolicyLow(finding.SeverityMedium),
}

// inlineKMSDecryptAll is FSBP KMS.2 on a principal; an admin principal steps
// aside, since its admin finding is the broader grant.
func inlineKMSDecryptAll(a asset.Asset) bool {
	return a.Metadata["inline_kms_decrypt_all"] == "true" && roleAdminReach(a) != reachAdmin
}

const inlineKMSDescription = "An inline policy on this principal allows kms:Decrypt or kms:ReEncryptFrom on Resource \"*\", so it can decrypt data protected by any KMS key whose key policy defers to IAM — the usual default. FSBP KMS.2."

const inlineKMSRemediation = "Scope the inline statement's Resource to the key ARNs the principal needs (or add a kms:ViaService condition), or replace the inline policy with a scoped managed policy."

var awsIAMUserInlineKMSDecryptAll = Check{
	ID:          "aws-iam-user-inline-kms-decrypt-all",
	Title:       "IAM user inline policy allows decrypting with every KMS key",
	Description: inlineKMSDescription,
	Remediation: inlineKMSRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates:    inlineKMSDecryptAll,
}

var awsIAMRoleInlineKMSDecryptAll = Check{
	ID:          "aws-iam-role-inline-kms-decrypt-all",
	Title:       "IAM role inline policy allows decrypting with every KMS key",
	Description: inlineKMSDescription,
	Remediation: inlineKMSRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    inlineKMSDecryptAll,
}

// heldAdminNotReportedElsewhere is a principal whose effective permissions
// resolve to *:* (the observed CIEM tier) and that no more specific
// check already reports: not through customer-managed policies alone (the
// policy carries it), and not dormant (aws-iam-admin-*-dormant).
func heldAdminNotReportedElsewhere(a asset.Asset) bool {
	return roleAdminReach(a) == reachAdmin && a.Metadata["full_admin_customer_policy_only"] != "true"
}

var awsIAMUserFullAdmin = Check{
	ID:          "aws-iam-user-full-admin",
	Title:       "IAM user holds full administrator access",
	Description: "This IAM user's effective permissions resolve to Allow *:* (AdministratorAccess, or an inline or managed policy with Action \"*\"). IAM users sign in with long-lived credentials — a password or access keys — so any credential it holds now or is given later is a full-account credential that can leak. CIS AWS 2.14: no principal should hold full admin through its own policies. A dormant admin user is reported by aws-iam-admin-user-dormant, and one whose admin comes only from a customer-managed policy by aws-iam-policy-full-admin.",
	Remediation: "Move human administrators to IAM Identity Center with MFA, and workloads to roles; then detach the admin policy from the user and delete its keys. If it is break-glass, keep its credentials offline, require MFA and alert on every use.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates:    func(a asset.Asset) bool { return heldAdminNotReportedElsewhere(a) && !dormantAdminUser(a) },
}

var awsIAMRoleFullAdmin = Check{
	ID:          "aws-iam-role-full-admin",
	Title:       "IAM role holds full administrator access",
	Description: "This role's effective permissions resolve to Allow *:*, so whoever can assume it controls the account. CIS AWS 2.14. Not reported here: service-linked roles (AWS owns them), IAM Identity Center roles (aws-sso-permission-set-admin reports the permission set), dormant admin roles (aws-iam-admin-role-dormant), roles with Access Advisor usage evidence (aws-iam-overprivileged-role), and roles whose admin comes only from a customer-managed policy (aws-iam-policy-full-admin).",
	Remediation: "Replace the admin grant with a policy scoped to what the role's workload does (IAM Access Analyzer can generate one from CloudTrail), and keep admin roles to a small, MFA-gated break-glass set.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates: func(a asset.Asset) bool {
		path := a.Metadata["path"]
		if strings.HasPrefix(path, "/aws-service-role/") || strings.HasPrefix(path, "/aws-reserved/sso.amazonaws.com/") {
			return false
		}
		return heldAdminNotReportedElsewhere(a) && !dormantAdminRole(a) && !overprivilegedAdminRole(a)
	},
}

var awsIAMRootVirtualMFA = Check{
	ID:          "aws-iam-root-virtual-mfa",
	Title:       "AWS root user is protected by a virtual MFA device",
	Description: "The root user's MFA is a virtual (authenticator app) device. CIS AWS 2.6 and FSBP IAM.6 ask for a hardware device, which cannot be cloned off a phone or backed up into someone else's cloud account. The root user still has MFA; no MFA at all is aws-iam-root-no-mfa.",
	Remediation: "Sign in as root → Security credentials → assign a hardware MFA device (FIDO security key or hardware TOTP token), then remove the virtual device. Store the device and its recovery details securely.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["root"] == "true" && a.Metadata["mfa_enabled"] == "true" && a.Metadata["root_virtual_mfa"] == "true"
	},
}

// rootRecentUseDays is the window within which root use is reported (CIS 2.7:
// do not use root for daily administration).
const rootRecentUseDays = 30

var awsIAMRootRecentlyUsed = Check{
	ID:          "aws-iam-root-recently-used",
	Title:       "AWS root user was used in the last 30 days",
	Description: "The credential report shows the root user's password or an access key was used within the last 30 days. Root cannot be limited by IAM policies or permission boundaries, so routine work as root means the account's most powerful credential is in daily circulation. If nobody expected this use, treat it as a possible compromise.",
	Remediation: "Confirm who used root and why (CloudTrail userIdentity.type = Root). Move the task to an IAM Identity Center or IAM role; keep root for the handful of tasks only root can do, with hardware MFA, and delete any root access keys.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	TableProbes: dateProbes,
	Violates: func(a asset.Asset) bool {
		if a.Metadata["root"] != "true" {
			return false
		}
		d, ok := daysSinceTimestamp(a.Metadata["root_last_used"])
		return ok && d < rootRecentUseDays
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"root_last_used": a.Metadata["root_last_used"]}
	},
}
