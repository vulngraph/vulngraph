package checks

// aws_iam_groups.go — IAM groups, IAM server certificates and the AWS Support
// role (CIS AWS 2.14, 2.15, 2.17, 2.20; FSBP KMS.2 on groups). A group check
// reports its configured policy grants, not any member's effective authority.
// A customer-managed *:* policy is reported on the policy; an admin grant
// covers CloudShell and KMS.

import (
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsIAMCISChecks() []Check {
	return []Check{
		awsIAMGroupFullAdmin,
		awsIAMGroupCloudShellFullAccess,
		awsIAMGroupInlineKMSDecryptAll,
		awsIAMServerCertificateExpired,
		awsIAMNoSupportRole,
		awsIAMUserCredentialUnused45d,
	}
}

var awsIAMGroupFullAdmin = Check{
	ID:          "aws-iam-group-full-admin",
	Title:       "IAM group grants full administrator access",
	Description: "This group's policies grant Allow *:* (AdministratorAccess, or an inline or AWS-managed policy with Action \"*\"). A member's effective authority also depends on organization policies, permission boundaries and other applicable restrictions. CIS AWS 2.14. A group whose admin grant comes only from a customer-managed policy is reported by aws-iam-policy-full-admin instead.",
	Remediation: "Move administrators to IAM Identity Center with MFA; then detach the admin policy (`aws iam detach-group-policy --group-name NAME --policy-arn ARN`, `aws iam delete-group-policy` for an inline one) and grant the group only what its members use.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_group",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["admin"] == "true" && a.Metadata["full_admin_customer_policy_only"] != "true"
	},
	// An empty group grants nobody anything today.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["member_count"] == "0" {
			return finding.SeverityLow
		}
		return finding.SeverityHigh
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"member_count": a.Metadata["member_count"]}
	},
}

var awsIAMGroupCloudShellFullAccess = Check{
	ID:          "aws-iam-group-cloudshell-full-access",
	Title:       "IAM group has AWSCloudShellFullAccess attached",
	Description: cloudShellDescription,
	Remediation: "Detach AWSCloudShellFullAccess (`aws iam detach-group-policy --group-name NAME --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess`) and, if CloudShell is needed, grant a custom policy that denies cloudshell:GetFileDownloadUrls and cloudshell:GetFileUploadUrls.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_group",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cloudshell_full_access"] == "true" && a.Metadata["admin"] != "true"
	},
}

var awsIAMGroupInlineKMSDecryptAll = Check{
	ID:          "aws-iam-group-inline-kms-decrypt-all",
	Title:       "IAM group inline policy allows decrypting with every KMS key",
	Description: "An inline policy on this group allows kms:Decrypt or kms:ReEncryptFrom on Resource \"*\", so every member can decrypt data protected by any KMS key whose key policy defers to IAM — the usual default. FSBP KMS.2.",
	Remediation: inlineKMSRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_group",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["inline_kms_decrypt_all"] == "true" && a.Metadata["admin"] != "true"
	},
}

var awsIAMServerCertificateExpired = Check{
	ID:          "aws-iam-server-certificate-expired",
	Title:       "IAM server certificate has expired",
	Description: "An SSL/TLS certificate stored in IAM is past its expiration date. A load balancer or CloudFront distribution still pointing at it serves an invalid certificate, and a stale private key kept in IAM is one more key to leak. CIS AWS 2.17.",
	Remediation: "Confirm nothing uses it, then `aws iam delete-server-certificate --server-certificate-name NAME`. Issue replacements through ACM, which renews them automatically.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_server_certificate",
	TableProbes: dateProbes,
	Violates: func(a asset.Asset) bool {
		t, err := time.Parse(time.RFC3339, a.Metadata["expiration"])
		return err == nil && time.Now().After(t)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"expiration": a.Metadata["expiration"]}
	},
}

var awsIAMNoSupportRole = Check{
	ID:          "aws-iam-no-support-role",
	Title:       "No IAM role can open AWS Support cases",
	Description: "No role has the AWSSupportAccess managed policy attached, so during an incident only root or an administrator can open and manage AWS Support cases. CIS AWS 2.15 asks for a dedicated, least-privilege support role.",
	Remediation: "Create a role for your incident responders and attach the policy: `aws iam create-role --role-name aws-support --assume-role-policy-document file://trust.json` then `aws iam attach-role-policy --role-name aws-support --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["support_role_count"] == "0" },
}
