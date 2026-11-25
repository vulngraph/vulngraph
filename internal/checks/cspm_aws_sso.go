package checks

// cspm_aws_sso.go — AWS IAM Identity Center (SSO) posture. Keys on
// sso_permission_set metadata the Identity Center collector emits
// (internal/collect/aws/identitycenter.go): grants_admin, account_count,
// assignee_count.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// awsSSOPermissionSetAdmin flags an Identity Center permission set that grants
// administrator access (AdministratorAccess managed policy or an inline
// wildcard-action Allow). This is the human path to admin the trust-policy
// CanAssume graph cannot see: anyone assigned this permission set can federate
// into an admin role in every account it is provisioned to. High severity —
// it is the widest standing human privilege in the org.
var awsSSOPermissionSetAdmin = Check{
	ID:          "aws-sso-permission-set-admin",
	Title:       "IAM Identity Center permission set grants administrator access",
	Description: "This AWS IAM Identity Center (SSO) permission set grants administrator access — either the AdministratorAccess managed policy or an inline policy allowing Action \"*\". Every user or group assigned it can federate into an admin-equivalent role in each account the permission set is provisioned to. This is the dominant human path to admin and, unlike sts:AssumeRole trust chains, is invisible to role-assumption analysis. Keep admin permission sets to a small, audited set of break-glass principals.",
	Remediation: "Review the permission set's assignments (who holds it and in how many accounts) and its policies. Replace blanket AdministratorAccess with least-privilege permission sets scoped to the tasks each group actually performs; reserve admin for a small break-glass group with strong MFA and session logging.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "sso_permission_set",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["grants_admin"] == "true"
	},
}
