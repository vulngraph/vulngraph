package checks

// aws_organizations.go — AWS Organizations posture (CIS AWS 2.1.1, 2.1.2,
// 2.1.5, 2.1.6), read only by the connector of the management (or
// Organizations delegated-admin) account. A sweep that never reaches that
// account emits no aws_organization / aws_org_account asset, so these stay
// unknown rather than passing.
//
// One finding per root cause: a policy type switched off at the root is one
// organization finding, and the per-account guardrail checks step aside for
// it rather than firing on every account.

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsOrganizationsChecks() []Check {
	return []Check{
		awsOrgRootAccessNotCentralized,
		awsOrgPolicyManagementNotDelegated,
		awsOrgSecurityServicesNotDelegated,
		awsOrgGuardrailPolicyTypeDisabled,
		awsOrgAccountNoSCPGuardrail,
		awsOrgAccountNoRCPGuardrail,
	}
}

var awsOrgRootAccessNotCentralized = Check{
	ID:          "aws-org-root-access-not-centralized",
	Title:       "Organization does not manage member-account root access centrally",
	Description: "Centralized root access is not fully enabled (iam:ListOrganizationsFeatures): without RootCredentialsManagement every member account keeps its own root password, access keys and MFA to secure and audit, and without RootSessions privileged root-only tasks need those credentials rather than a short-lived session from the management account. CIS AWS 2.1.1.",
	Remediation: "IAM console (management account) → Root access management → Enable, with both Root credentials management and Privileged root actions in member accounts; or `aws organizations enable-aws-service-access --service-principal iam.amazonaws.com` then `aws iam enable-organizations-root-credentials-management` and `aws iam enable-organizations-root-sessions`. Then delete member-account root credentials.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_organization",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["root_credentials_management"] == "false" || a.Metadata["root_sessions"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"root_credentials_management": a.Metadata["root_credentials_management"],
			"root_sessions":               a.Metadata["root_sessions"],
		}
	},
}

var awsOrgPolicyManagementNotDelegated = Check{
	ID:          "aws-org-policy-management-not-delegated",
	Title:       "Organizations policy management is not delegated to a member account",
	Description: "The organization's resource policy does not delegate policy management (organizations:CreatePolicy/UpdatePolicy/AttachPolicy…) to a member account, so day-to-day SCP and RCP work has to be done signed in to the management account — the one account that guardrails cannot restrict. CIS AWS 2.1.5.",
	Remediation: "Organizations console (management account) → Settings → Delegated administrator for AWS Organizations → Delegate, granting the policy actions to a security-tooling account; or `aws organizations put-resource-policy --content file://delegation.json`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_organization",
	Violates:    func(a asset.Asset) bool { return a.Metadata["policy_management_delegated"] == "false" },
}

var awsOrgSecurityServicesNotDelegated = Check{
	ID:          "aws-org-security-services-not-delegated",
	Title:       "Organization security services are administered from the management account",
	Description: "These security services have trusted access enabled and support a delegated administrator, but none is registered (see undelegated_security_services), so administering them means working in the management account. CIS AWS 2.1.6 asks for each integrated service to be run from a dedicated delegated-admin account.",
	Remediation: "Register a delegated administrator per service, e.g. `aws organizations register-delegated-administrator --account-id SECURITY_ACCOUNT --service-principal guardduty.amazonaws.com` (most services also offer this in their own console's settings).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_organization",
	Violates:    func(a asset.Asset) bool { return a.Metadata["undelegated_security_services"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"undelegated_security_services": a.Metadata["undelegated_security_services"]}
	},
}

var awsOrgGuardrailPolicyTypeDisabled = Check{
	ID:          "aws-org-guardrail-policy-type-disabled",
	Title:       "Organization has a guardrail policy type switched off",
	Description: "Service control policies or resource control policies are not enabled at the organization root, so no account can carry that kind of guardrail: SCPs cap what principals in member accounts may do, RCPs cap what anyone may do to their resources. CIS AWS 2.1.2.",
	Remediation: "Organizations console → Policies → Service control policies / Resource control policies → Enable; or `aws organizations enable-policy-type --root-id ROOT_ID --policy-type SERVICE_CONTROL_POLICY` (and RESOURCE_CONTROL_POLICY). Then attach guardrails to the OUs.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_organization",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["scp_enabled"] == "false" || a.Metadata["rcp_enabled"] == "false"
	},
	TitleFor: func(a asset.Asset) string {
		var off []string
		if a.Metadata["scp_enabled"] == "false" {
			off = append(off, "service control policies")
		}
		if a.Metadata["rcp_enabled"] == "false" {
			off = append(off, "resource control policies")
		}
		return "Organization has " + strings.Join(off, " and ") + " switched off"
	},
}

var awsOrgAccountNoSCPGuardrail = Check{
	ID:          "aws-org-account-no-scp-guardrail",
	Title:       "Organization account has no service control policy beyond FullAWSAccess",
	Description: "Only the default FullAWSAccess SCP applies to this account (attached to it, its OUs and the root), so nothing at the organization level limits what its principals can do — leaving the organization, disabling CloudTrail or GuardDuty, or working in unapproved regions. CIS AWS 2.1.2.",
	Remediation: "Attach a guardrail SCP to the account's OU (deny organizations:LeaveOrganization, deny disabling security services, region deny): `aws organizations attach-policy --policy-id p-… --target-id ou-…`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_org_account",
	// A policy type off at the root is the organization finding.
	Violates: func(a asset.Asset) bool {
		return a.Metadata["scp_guardrail"] == "false" && a.Metadata["scp_enabled"] != "false"
	},
}

var awsOrgAccountNoRCPGuardrail = Check{
	ID:          "aws-org-account-no-rcp-guardrail",
	Title:       "Organization account has no resource control policy beyond RCPFullAWSAccess",
	Description: "Only the default RCPFullAWSAccess RCP applies to this account, so nothing at the organization level stops one of its resource policies from granting access to identities outside the organization — the data-perimeter guardrail SCPs cannot provide. CIS AWS 2.1.2.",
	Remediation: "Attach a data-perimeter RCP to the account's OU (e.g. deny s3:*, sts:AssumeRole, kms:*, secretsmanager:*, sqs:* unless aws:PrincipalOrgID matches): `aws organizations attach-policy --policy-id p-… --target-id ou-…`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_org_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["rcp_guardrail"] == "false" && a.Metadata["rcp_enabled"] != "false"
	},
}
