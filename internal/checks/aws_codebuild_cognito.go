package checks

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CodeBuild project and report-group posture (FSBP CodeBuild.1-4/7) and
// Cognito user- and identity-pool posture (FSBP Cognito.2-6), from
// codebuild:BatchGetProjects / BatchGetReportGroups and
// cognito-idp:DescribeUserPool / cognito-identity:DescribeIdentityPool.

// ── CodeBuild ────────────────────────────────────────────────────────────────

var awsCodeBuildSourceURLCredentials = Check{
	ID:          "aws-codebuild-source-url-credentials",
	Title:       "CodeBuild project source URL contains credentials",
	Description: "A source repository URL of the project (primary or secondary) embeds a user name and password or a personal access token (https://user:secret@host/...). Project configuration is readable by anyone with codebuild:BatchGetProjects and is printed in build logs and console views, so the repository credential is effectively shared with everyone who can read CodeBuild — and it grants whatever that account can do in the source provider, often push access.",
	Remediation: "Console: CodeBuild → project → Edit → Source → Disconnect, then connect with OAuth or an AWS CodeConnections connection and set the URL to the bare repository path. CLI: `aws codebuild update-project --name NAME --source type=BITBUCKET,location=https://bitbucket.org/ORG/REPO.git` after `aws codebuild import-source-credentials`. Revoke the exposed password or token in the source provider.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "codebuild_project",
	Violates:    func(a asset.Asset) bool { return a.Metadata["source_url_credentials"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"sources": a.Metadata["source_url_credentials"]}
	},
}

var awsCodeBuildPlaintextAWSCredentials = Check{
	ID:          "aws-codebuild-plaintext-aws-credentials",
	Title:       "CodeBuild project holds AWS credentials in plaintext environment variables",
	Description: "The build environment sets AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY as a PLAINTEXT environment variable. The value is stored in the project definition, returned to anyone with codebuild:BatchGetProjects and visible in the console, and it authenticates as an IAM principal from anywhere on the internet.",
	Remediation: "Remove the variables (Console: CodeBuild → project → Edit → Environment → Additional configuration → Environment variables). Let builds use the project's service role instead; if a separate credential is unavoidable, store it in Secrets Manager or Parameter Store and reference it with type SECRETS_MANAGER / PARAMETER_STORE (`aws codebuild update-project --name NAME --environment file://env.json`). Deactivate and rotate the exposed access key.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "codebuild_project",
	Violates:    func(a asset.Asset) bool { return a.Metadata["plaintext_aws_credential_env"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"variables": a.Metadata["plaintext_aws_credential_env"]}
	},
}

var awsCodeBuildS3LogsUnencrypted = Check{
	ID:          "aws-codebuild-s3-logs-unencrypted",
	Title:       "CodeBuild project writes unencrypted build logs to S3",
	Description: "The project ships build logs to S3 with encryption explicitly disabled. Build logs routinely contain dependency URLs, environment details and occasionally echoed secrets; unencrypted objects lose the KMS access control and audit trail an encrypted log would have.",
	Remediation: "Console: CodeBuild → project → Edit → Logs → S3 logs → clear \"Disable S3 log encryption\". CLI: `aws codebuild update-project --name NAME --logs-config 's3Logs={status=ENABLED,location=BUCKET/prefix,encryptionDisabled=false}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "codebuild_project",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["s3_logs_status"] == "ENABLED" && a.Metadata["s3_logs_encryption_disabled"] == "true"
	},
}

var awsCodeBuildLoggingDisabled = Check{
	ID:          "aws-codebuild-logging-disabled",
	Title:       "CodeBuild project has no build logging",
	Description: "Both CloudWatch Logs and S3 logging are disabled for the project, so no record of what a build ran — commands, fetched dependencies, deploy steps — survives the build container.",
	Remediation: "Console: CodeBuild → project → Edit → Logs → enable CloudWatch logs (or S3 logs). CLI: `aws codebuild update-project --name NAME --logs-config 'cloudWatchLogs={status=ENABLED}'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "codebuild_project",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cloudwatch_logs_status"] == "DISABLED" && a.Metadata["s3_logs_status"] == "DISABLED"
	},
}

var awsCodeBuildReportExportUnencrypted = Check{
	ID:          "aws-codebuild-report-export-unencrypted",
	Title:       "CodeBuild report group exports unencrypted results to S3",
	Description: "The report group exports test and coverage reports to S3 with encryption disabled, so the exported objects carry no KMS access control or decrypt audit trail.",
	Remediation: "Console: CodeBuild → Report groups → group → Edit → clear \"Disable artifact encryption\" (optionally choose a KMS key). CLI: `aws codebuild update-report-group --arn ARN --export-config 'exportConfigType=S3,s3Destination={bucket=BUCKET,encryptionDisabled=false}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "codebuild_report_group",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["export_type"] == "S3" && a.Metadata["export_encryption_disabled"] == "true"
	},
}

// ── Cognito ──────────────────────────────────────────────────────────────────

var awsCognitoIdentityPoolGuestAccess = Check{
	ID:          "aws-cognito-identity-pool-guest-access",
	Title:       "Cognito identity pool hands AWS credentials to unauthenticated users",
	Description: "The identity pool allows unauthenticated (guest) identities: anyone who knows the pool id — which ships inside every client app — can call GetId and GetCredentialsForIdentity and receive temporary AWS credentials for the pool's unauthenticated role, without signing in. What those credentials can do depends on that role's policies, which this check does not grade, so it is reported at Medium.",
	Remediation: "Console: Cognito → Identity pools → pool → User access → Guest access → Deactivate. CLI: `aws cognito-identity update-identity-pool --identity-pool-id ID --identity-pool-name NAME --no-allow-unauthenticated-identities`. If guest access is required, scope the unauthenticated role to the minimum actions and resources.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "cognito_identity_pool",
	Violates:    func(a asset.Asset) bool { return a.Metadata["allow_unauthenticated_identities"] == "true" },
}

// Security Hub's Cognito.3 defaults: at least 8 characters, every character
// class required, temporary passwords valid at most 7 days.
const (
	cognitoMinPasswordLength   = 8
	cognitoMaxTempPasswordDays = 7
)

func cognitoPasswordWeaknesses(a asset.Asset) []string {
	var out []string
	if n, err := strconv.Atoi(a.Metadata["password_min_length"]); err == nil && n < cognitoMinPasswordLength {
		out = append(out, "minimum length "+strconv.Itoa(n)+" < 8")
	}
	// Literal lookups so the required-key scanner sees every key.
	if a.Metadata["password_require_uppercase"] == "false" {
		out = append(out, "does not require uppercase")
	}
	if a.Metadata["password_require_lowercase"] == "false" {
		out = append(out, "does not require lowercase")
	}
	if a.Metadata["password_require_numbers"] == "false" {
		out = append(out, "does not require numbers")
	}
	if a.Metadata["password_require_symbols"] == "false" {
		out = append(out, "does not require symbols")
	}
	if n, err := strconv.Atoi(a.Metadata["temporary_password_validity_days"]); err == nil && n > cognitoMaxTempPasswordDays {
		out = append(out, "temporary passwords valid "+strconv.Itoa(n)+" days > 7")
	}
	return out
}

var awsCognitoWeakPasswordPolicy = Check{
	ID:          "aws-cognito-weak-password-policy",
	Title:       "Cognito user pool password policy is weak",
	Description: "The user pool's password policy allows passwords shorter than 8 characters, does not require upper- and lowercase letters, numbers and symbols, or keeps administrator-issued temporary passwords valid for more than 7 days. User pools usually front internet-facing sign-in, where weak passwords are exposed to credential stuffing and guessing.",
	Remediation: "Console: Cognito → User pools → pool → Authentication methods → Password policy → Edit. CLI: `aws cognito-idp update-user-pool --user-pool-id ID --policies 'PasswordPolicy={MinimumLength=12,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true,RequireSymbols=true,TemporaryPasswordValidityDays=7}'` (update-user-pool resets unspecified settings to defaults — pass the pool's current configuration).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "cognito_user_pool",
	Violates:    func(a asset.Asset) bool { return len(cognitoPasswordWeaknesses(a)) > 0 },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"weaknesses": strings.Join(cognitoPasswordWeaknesses(a), "; ")}
	},
}

var awsCognitoUserPoolNoMFA = Check{
	ID:          "aws-cognito-user-pool-no-mfa",
	Title:       "Cognito user pool with password-only sign-in has MFA turned off",
	Description: "Users of the pool sign in with a password alone (no passwordless first factor is offered) and MFA is OFF, so a phished, reused or guessed password is enough to take over an account. Federated users authenticate at their identity provider and are not affected.",
	Remediation: "Console: Cognito → User pools → pool → Authentication methods → Multi-factor authentication → Edit → Require MFA (or Optional). CLI: `aws cognito-idp set-user-pool-mfa-config --user-pool-id ID --mfa-configuration ON --software-token-mfa-configuration Enabled=true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "cognito_user_pool",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["mfa_configuration"] == "OFF" && a.Metadata["password_only_sign_in"] == "true"
	},
}

var awsCognitoThreatProtectionNotEnforced = Check{
	ID:          "aws-cognito-threat-protection-not-enforced",
	Title:       "Cognito user pool does not fully enforce threat protection",
	Description: "Threat protection (adaptive authentication and compromised-credential detection) is off for the pool, or runs in audit mode rather than full-function enforcement for standard (FSBP Cognito.1) or custom (Cognito.4) authentication flows, so risky sign-ins are at most logged, not blocked or challenged. One finding per pool covers both flows. Threat protection needs the Plus feature plan, so this is graded Low.",
	Remediation: "Console: Cognito → User pools → pool → Threat protection → Activate, set enforcement to Full function for standard and custom authentication. CLI: `aws cognito-idp update-user-pool --user-pool-id ID --user-pool-add-ons 'AdvancedSecurityMode=ENFORCED,AdvancedSecurityAdditionalFlows={CustomAuthMode=ENFORCED}'` (pass the pool's current configuration with it).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "cognito_user_pool",
	Violates: func(a asset.Asset) bool {
		standard := a.Metadata["threat_protection_mode"]
		if standard == "" {
			return false
		}
		if standard != "ENFORCED" {
			return true
		}
		custom, ok := a.Metadata["threat_protection_custom_auth_mode"]
		return ok && custom != "ENFORCED"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"threat_protection_mode":             a.Metadata["threat_protection_mode"],
			"threat_protection_custom_auth_mode": a.Metadata["threat_protection_custom_auth_mode"],
		}
	},
}

var awsCognitoNoDeletionProtection = Check{
	ID:          "aws-cognito-no-deletion-protection",
	Title:       "Cognito user pool has deletion protection off",
	Description: "The user pool can be deleted in one call. Deleting a pool destroys every user, credential and app-client configuration in it irrecoverably, locking all users out of the applications it serves.",
	Remediation: "Console: Cognito → User pools → pool → Settings → Deletion protection → Activate. CLI: `aws cognito-idp update-user-pool --user-pool-id ID --deletion-protection ACTIVE` (pass the pool's current configuration with it).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "cognito_user_pool",
	Violates:    func(a asset.Asset) bool { return a.Metadata["deletion_protection"] == "INACTIVE" },
}

func awsCodeBuildCognitoChecks() []Check {
	return []Check{
		awsCodeBuildSourceURLCredentials,
		awsCodeBuildPlaintextAWSCredentials,
		awsCodeBuildS3LogsUnencrypted,
		awsCodeBuildLoggingDisabled,
		awsCodeBuildReportExportUnencrypted,
		awsCognitoIdentityPoolGuestAccess,
		awsCognitoWeakPasswordPolicy,
		awsCognitoUserPoolNoMFA,
		awsCognitoThreatProtectionNotEnforced,
		awsCognitoNoDeletionProtection,
	}
}
