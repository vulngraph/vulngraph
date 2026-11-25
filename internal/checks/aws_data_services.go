package checks

// aws_data_services.go — KMS, S3 bucket policy, Secrets Manager, ACM and SSM
// posture from fields the AWS collector already reads (CIS AWS 3.1.1, FSBP
// KMS.3, S3.5, S3.6, SecretsManager.2/3/4, ACM.2, SSM.1).

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsDataServiceChecks() []Check {
	return []Check{
		awsKMSKeyPendingDeletion,
		awsS3NoTLSEnforcement,
		awsS3PolicyCrossAccountWrite,
		awsSecretRotationOverdue,
		awsSecretNotRotated90d,
		awsSecretUnused,
		awsACMRSAKeyTooShort,
		awsEC2NotSSMManaged,
	}
}

var awsKMSKeyPendingDeletion = Check{
	ID:          "aws-kms-key-pending-deletion",
	Title:       "KMS key is scheduled for deletion",
	Description: "This customer-managed KMS key is pending deletion. When the waiting period ends the key material is destroyed and everything encrypted under it — volumes, snapshots, buckets, secrets, database storage — becomes permanently unreadable. Scheduling deletion of keys still in use is also a known ransomware tactic.",
	Remediation: "Confirm nothing still uses the key (CloudTrail Decrypt events, kms:ListGrants, the services that reference it). If anything does, `aws kms cancel-key-deletion --key-id KEY_ID` and re-enable it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "kms_key",
	Violates: func(a asset.Asset) bool {
		switch a.Metadata["key_state"] {
		case "PendingDeletion", "PendingReplicaDeletion":
			return true
		}
		return false
	},
}

var awsS3NoTLSEnforcement = Check{
	ID:          "aws-s3-no-tls-enforcement",
	Title:       "S3 bucket policy does not deny requests without TLS",
	Description: "The bucket has no policy statement denying requests made over plain HTTP (aws:SecureTransport = false), so a client can read or write it without TLS. CIS AWS 3.1.1, FSBP S3.5.",
	Remediation: "Add a statement to the bucket policy: Effect Deny, Principal \"*\", Action \"s3:*\", Resource the bucket and bucket/*, Condition {\"Bool\": {\"aws:SecureTransport\": \"false\"}}.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates:    func(a asset.Asset) bool { return a.Metadata["policy_tls_enforced"] == "false" },
}

var awsS3PolicyCrossAccountWrite = Check{
	ID:          "aws-s3-policy-cross-account-write",
	Title:       "S3 bucket policy lets other accounts change its access or encryption",
	Description: "The bucket policy allows another AWS account, or everyone (Principal \"*\", or an Allow with NotPrincipal) with no condition that restricts the caller, one of s3:PutBucketPolicy, s3:DeleteBucketPolicy, s3:PutBucketAcl, s3:PutObjectAcl or s3:PutEncryptionConfiguration. An outside account can then rewrite who may read the bucket, make objects public, or swap the encryption key. FSBP S3.6.",
	Remediation: "Remove those actions from the statements that name other accounts, Principal \"*\" or NotPrincipal; grant other accounts only the object actions they need, and scope with aws:PrincipalOrgID where possible.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates:    func(a asset.Asset) bool { return a.Metadata["policy_cross_account_write"] == "true" },
}

// Secrets Manager thresholds: FSBP SecretsManager.3/4 defaults, and a day of
// slack before a missed scheduled rotation counts as failed.
const (
	secretMaxRotationAgeDays = 90
	secretUnusedDays         = 90
	secretRotationGraceDays  = 1
)

// secretRotationAgeDays is days since the last rotation, or since creation
// for a secret never rotated.
func secretRotationAgeDays(a asset.Asset) (int, bool) {
	if d, ok := daysSinceTimestamp(a.Metadata["last_rotated"]); ok {
		return d, true
	}
	if observedNone(a, "last_rotated") {
		return daysSinceTimestamp(a.Metadata["created_at"])
	}
	return 0, false
}

// secretRotationOverdue: rotation is on and the schedule's rotation did not
// happen — the secret is older than its interval, or the date the schedule
// (rate or cron) next called for has passed. Either way the rotation Lambda
// is failing. A schedule with neither fact readable is unknown.
func secretRotationOverdue(a asset.Asset) bool {
	if a.Metadata["rotation_enabled"] != "true" {
		return false
	}
	if since, ok := daysSinceTimestamp(a.Metadata["next_rotation"]); ok && since > secretRotationGraceDays {
		return true
	}
	interval, err := strconv.Atoi(a.Metadata["rotation_interval_days"])
	if err != nil {
		return false
	}
	age, ok := secretRotationAgeDays(a)
	return ok && age > interval+secretRotationGraceDays
}

var awsSecretRotationOverdue = Check{
	ID:          "aws-secretsmanager-rotation-overdue",
	Title:       "Secrets Manager secret has missed its scheduled rotation",
	Description: "Automatic rotation is enabled, but the rotation its schedule calls for has not happened: the secret was last rotated (or, never rotated, created) longer ago than its rotation interval, or the next rotation date Secrets Manager scheduled has passed (this is how a cron schedule is graded). The rotation function is failing, so the credential everyone believes is short-lived is not. FSBP SecretsManager.2.",
	Remediation: "Check the rotation Lambda's CloudWatch logs and the secret's RotationEnabled/LastRotatedDate; fix the function (network access to the database, permissions, the secret's version stages), then `aws secretsmanager rotate-secret --secret-id ARN`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "secretsmanager_secret",
	TableProbes: dateProbes,
	Violates:    secretRotationOverdue,
}

var awsSecretNotRotated90d = Check{
	ID:          "aws-secretsmanager-not-rotated-90d",
	Title:       "Secrets Manager secret has not rotated in 90+ days",
	Description: "Automatic rotation is enabled but the secret has not rotated in at least 90 days, because its interval is longer than that or its schedule cannot be read. FSBP SecretsManager.4. A secret with rotation off is aws-secretsmanager-no-rotation; one that missed a shorter schedule is aws-secretsmanager-rotation-overdue.",
	Remediation: "Shorten the rotation schedule to 90 days or less: `aws secretsmanager rotate-secret --secret-id ARN --rotation-rules AutomaticallyAfterDays=90`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "secretsmanager_secret",
	TableProbes: dateProbes,
	Violates: func(a asset.Asset) bool {
		if a.Metadata["rotation_enabled"] != "true" || secretRotationOverdue(a) {
			return false
		}
		age, ok := secretRotationAgeDays(a)
		return ok && age >= secretMaxRotationAgeDays
	},
}

var awsSecretUnused = Check{
	ID:          "aws-secretsmanager-unused",
	Title:       "Secrets Manager secret has not been read in 90+ days",
	Description: "Nothing has retrieved this secret's value in at least 90 days (or ever, for a secret older than that). An unused credential is still a valid one: it should be deleted rather than left for someone to find. FSBP SecretsManager.3.",
	Remediation: "Confirm no workload depends on it, revoke the credential at its source (database user, API key), then `aws secretsmanager delete-secret --secret-id ARN --recovery-window-in-days 30`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "secretsmanager_secret",
	TableProbes: dateProbes,
	Violates: func(a asset.Asset) bool {
		if d, ok := daysSinceTimestamp(a.Metadata["last_accessed"]); ok {
			return d >= secretUnusedDays
		}
		if !observedNone(a, "last_accessed") {
			return false
		}
		d, ok := daysSinceTimestamp(a.Metadata["created_at"])
		return ok && d >= secretUnusedDays
	},
}

var awsACMRSAKeyTooShort = Check{
	ID:          "aws-acm-rsa-key-too-short",
	Title:       "ACM certificate uses an RSA key shorter than 2048 bits",
	Description: "This certificate's RSA key is under 2048 bits (RSA_1024, imported — ACM no longer issues them). 1024-bit RSA is within reach of well-resourced attackers and rejected by current browsers and TLS libraries. FSBP ACM.2.",
	Remediation: "Issue or import a replacement with RSA 2048+ or ECDSA P-256, switch the load balancers and distributions using it (in_use_by), then delete the old certificate.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "acm_certificate",
	Violates: func(a asset.Asset) bool {
		bits, ok := strings.CutPrefix(a.Metadata["key_algorithm"], "RSA_")
		if !ok {
			return false
		}
		n, err := strconv.Atoi(bits)
		return err == nil && n < 2048
	},
}

var awsEC2NotSSMManaged = Check{
	ID:          "aws-ec2-not-ssm-managed",
	Title:       "Running EC2 instance is not managed by Systems Manager",
	Description: "This running instance is not registered with AWS Systems Manager (no SSM agent reporting, or no instance profile allowing it), so it gets no Patch Manager patching, no Session Manager access without open SSH, and no software inventory — graph cannot see its installed packages either. FSBP SSM.1. An instance whose SSM state could not be read (access denied, SSM unavailable) is not reported.",
	Remediation: "Attach an instance profile with the AmazonSSMManagedInstanceCore policy (or enable Default Host Management Configuration for the region) and make sure the SSM agent is installed and can reach the SSM endpoints.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["state"] == "running" && a.Metadata["ssm_managed"] == "false"
	},
}
