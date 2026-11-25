package checks

// cspm_expanded.go — second batch of CSPM checks, independently written.
// These checks depend on metadata added to collectors in the same release cycle.
// They implement CIS Benchmark controls. No third-party check code or prose is
// incorporated.

import (
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// ── S3 (batch 2) ─────────────────────────────────────────────────────────────

var awsS3MFADeleteDisabled = Check{
	ID:          "aws-s3-mfa-delete-disabled",
	Title:       "S3 bucket versioning is enabled but MFA Delete is not",
	Description: "Versioning is active on this bucket but MFA Delete is not enforced. Without MFA Delete, any principal with s3:DeleteObjectVersion can permanently purge object versions — including ransomware or a compromised access key — without a second factor.",
	Remediation: "Enable MFA Delete: `aws s3api put-bucket-versioning --bucket BUCKET --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::ACCOUNT:mfa/DEVICE TOTP'`. Requires root credentials.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates: func(a asset.Asset) bool {
		v := a.Metadata["versioning"]
		if v == "Disabled" || v == "disabled" || v == "" {
			return false // versioning off — MFA Delete is irrelevant
		}
		// Explicit "Disabled" only. bucketVersioningAndMFA omits both keys when
		// GetBucketVersioning errors, and != "Enabled" would read that absence
		// as a violation — the same trap the versioning arm above is protected
		// from by testing positive enum values.
		return a.Metadata["mfa_delete"] == "Disabled"
	},
}

var awsS3WebsiteEnabled = Check{
	ID:          "aws-s3-website-enabled",
	Title:       "S3 bucket has static website hosting enabled",
	Description: "Static website hosting is enabled on this bucket. Website-enabled buckets serve content over an unauthenticated HTTP endpoint and, if combined with a permissive bucket policy, expose all objects publicly. Attackers may also abuse the endpoint for phishing or storage of malicious content.",
	Remediation: "If website hosting is unintentional, disable it: `aws s3api delete-bucket-website --bucket BUCKET`. If intentional, ensure the bucket policy grants only the minimum objects required and audit the content regularly.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["website"] == "true"
	},
}

// ── RDS (batch 2) ─────────────────────────────────────────────────────────────

var awsRDSNoBackup = Check{
	ID:          "aws-rds-no-backup",
	Title:       "RDS instance has automated backups disabled",
	Description: "The automated backup retention period for this RDS instance is 0 (no automated snapshots at all) or below the 7 days AWS FSBP RDS.11 requires. Without backups, a logical corruption, accidental DROP, or ransomware attack cannot be recovered beyond the current state of the instance; a short window loses that ability for anything noticed late. Read replicas (which take no backups of their own) and Aurora / Multi-AZ cluster members (whose retention is a cluster setting) are not graded here.",
	Remediation: "Set a backup retention period of at least 7 days: `aws rds modify-db-instance --db-instance-identifier ID --backup-retention-period 7`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		// Only a parsed retention — a missing period means the collector never
		// read one, not that backups are off.
		n, err := strconv.Atoi(a.Metadata["backup_retention"])
		return err == nil && n < rdsMinBackupRetentionDays &&
			a.Metadata["read_replica_source"] == "" && !rdsClusterMember(a)
	},
	// No backups at all is the High case; a short window is retention hygiene.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["backup_retention"] == "0" {
			return finding.SeverityHigh
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["backup_retention"] == "0" {
			return "RDS instance has automated backups disabled"
		}
		return "RDS instance keeps automated backups for less than 7 days"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"backup_retention_days": a.Metadata["backup_retention"]}
	},
}

// rdsMinBackupRetentionDays is FSBP RDS.11's minimum retention.
const rdsMinBackupRetentionDays = 7

// rdsClusterMember reports an instance whose availability, deletion
// protection and backups are cluster settings: an Aurora instance, or any
// instance carrying a DB cluster identifier (Aurora, Multi-AZ DB clusters,
// Neptune and DocumentDB, which DescribeDBInstances also returns). Their
// instance-level MultiAZ and DeletionProtection are false by design, so
// grading them per instance reports the cluster's settings once per member,
// wrongly. An UNREAD membership (db_cluster_id absent) counts as a member, so
// the instance checks stay silent rather than guess.
func rdsClusterMember(a asset.Asset) bool {
	return !observedNone(a, "db_cluster_id") || strings.HasPrefix(a.Metadata["engine"], "aurora")
}

var awsRDSNoDeletionProtection = Check{
	ID:          "aws-rds-no-deletion-protection",
	Title:       "RDS instance does not have deletion protection enabled",
	Description: "Deletion protection is disabled on this RDS instance. Any IAM principal with rds:DeleteDBInstance can permanently destroy the database and all its automated backups without a separate safeguard.",
	Remediation: "Enable deletion protection: `aws rds modify-db-instance --db-instance-identifier ID --deletion-protection`. Use IAM conditions to further restrict who can disable it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		// Cluster members carry protection on the cluster (FSBP RDS.7), not here.
		return a.Metadata["deletion_protection"] == "false" && !rdsClusterMember(a)
	},
}

var awsRDSNoMultiAZ = Check{
	ID:          "aws-rds-no-multi-az",
	Title:       "RDS instance is not configured for Multi-AZ deployment",
	Description: "This RDS instance is deployed in a single Availability Zone. A hardware failure, AZ-level outage, or maintenance window will cause downtime. Multi-AZ maintains a synchronous standby replica and performs automatic failover, typically under two minutes.",
	Remediation: "Enable Multi-AZ: `aws rds modify-db-instance --db-instance-identifier ID --multi-az --apply-immediately`. Note: this involves a brief failover if applied to a running instance.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		// Cluster members report MultiAZ=false by design: availability is the
		// cluster's (FSBP RDS.5 excludes them; RDS.15 grades the cluster).
		return a.Metadata["multi_az"] == "false" && !rdsClusterMember(a)
	},
}

// There is no separate default-port check: its predicate would be a strict
// subset of aws-rds-publicly-accessible's (cspm_extra.go), firing on the same
// instances. The port is a severity input on that check instead.

// ── Lambda ────────────────────────────────────────────────────────────────────

var awsLambdaPublicAccess = Check{
	ID:          "aws-lambda-public-access",
	Title:       "Lambda function resource policy allows public invocation",
	Description: "The function's resource-based policy grants invoke permissions to everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller, making it directly invocable from the internet without authentication. An attacker can trigger arbitrary executions, exhaust concurrency quotas, or exploit the function's downstream permissions.",
	Remediation: "Remove the statement granting Principal \"*\" (or the Allow with NotPrincipal) from the resource policy: `aws lambda remove-permission --function-name NAME --statement-id STMT`. Restrict invocation to specific AWS accounts, roles, or VPC endpoints.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "lambda_function",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access"] == asset.PublicAccessConfirmed
	},
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsLambdaNoVPC = Check{
	ID:          "aws-lambda-no-vpc",
	Title:       "Lambda function is not deployed inside a VPC",
	Description: "This Lambda function runs outside a VPC and can reach the public internet directly. Functions outside a VPC cannot access private resources (RDS, ElastiCache, internal APIs) without NAT, and they bypass VPC flow logs, making network activity invisible to security monitoring.",
	Remediation: "Configure the function to run in a VPC with private subnets. Add a NAT Gateway if outbound internet access is required. Attach a security group with the minimum egress rules needed.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "lambda_function",
	Violates: func(a asset.Asset) bool {
		return observedNone(a, "vpc_id")
	},
}

// awsLambdaDeprecatedRuntime grades a function against the dated runtime
// table in aws_lifecycle.go (lambdaRuntimeDeprecation), so a runtime starts
// firing the day AWS deprecates it rather than when someone edits a list.
//
// Medium, High when the function is invocable from the internet (a function
// URL with AuthType NONE, or a public resource policy): an unpatched runtime
// is exploitable only through a runtime CVE, and reachability is what makes
// that near-term — the grading aws-ec2-os-end-of-life uses for VMs.
var awsLambdaDeprecatedRuntime = Check{
	ID:          "aws-lambda-deprecated-runtime",
	Title:       "Lambda function uses a deprecated runtime",
	Description: "This function runs on a runtime past its AWS deprecation date. AWS no longer applies security patches to a deprecated runtime or its OS, the function is not eligible for technical support, and AWS later blocks updating it — leaving the execution environment exposed to every CVE disclosed after the date.",
	Remediation: "Upgrade the function to a supported runtime and test it: `aws lambda update-function-configuration --function-name NAME --runtime nodejs22.x` (or python3.13, java21, dotnet10, ruby3.4, provided.al2023).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "lambda_function",
	Violates:    lambdaRuntimeDeprecated,
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["public"] == "true" || a.Metadata["public_access"] == asset.PublicAccessConfirmed {
			return finding.SeverityHigh
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"runtime":          a.Metadata["runtime"],
			"deprecation_date": lambdaRuntimeDeprecation[a.Metadata["runtime"]].Format(time.DateOnly),
		}
	},
	TableProbes: tableKeys(lambdaRuntimeDeprecation),
}

// ── Resource-based policy public exposure (KMS/SQS/SNS/ECR/Secrets Manager) ────
//
// Each of these mirrors awsLambdaPublicAccess: the collector (internal/collect/
// aws/resourcepolicy.go) already does the deny-aware open-principal grading
// against a per-service list of actions that actually confer meaningful access
// (not mere metadata disclosure), so the check itself is just the same
// public_access == confirmed test S3/Lambda use.

var awsKMSKeyPolicyPublic = Check{
	ID:          "aws-kms-key-policy-public",
	Title:       "KMS key policy grants decrypt access to any principal",
	Description: "This KMS key's resource-based key policy grants kms:Decrypt to everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller. Any AWS account holding a ciphertext encrypted under this key — or any caller who can reach the API — can decrypt it, regardless of what IAM identity policies say. AWS grants access via the union of identity and resource policy, so a locked-down role means nothing if the key itself is this open.",
	Remediation: "Remove the statement granting Principal \"*\" (or the Allow with NotPrincipal) from the key policy: `aws kms put-key-policy --key-id ID --policy-name default --policy file://policy.json`. Scope Principal to specific account/role ARNs, and if cross-account access is intended, add a Condition on aws:SourceAccount or aws:PrincipalOrgID.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "kms_key",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access"] == asset.PublicAccessConfirmed
	},
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsSQSQueuePolicyPublic = Check{
	ID:          "aws-sqs-queue-policy-public",
	Title:       "SQS queue policy allows public send/receive",
	Description: "This queue's resource-based policy grants sqs:ReceiveMessage or sqs:SendMessage to everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller. Any caller can read queue messages (data exfiltration) or inject arbitrary messages (poisoning downstream consumers), without any AWS credentials.",
	Remediation: "Remove the statement granting Principal \"*\" (or the Allow with NotPrincipal) from the queue policy: `aws sqs set-queue-attributes --queue-url URL --attributes Policy=file://policy.json`. Scope Principal to specific account/role ARNs, or add a Condition on aws:SourceAccount/aws:SourceArn for the standard cross-service pattern (e.g. S3 event notifications).",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "sqs_queue",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access"] == asset.PublicAccessConfirmed
	},
	// The tier is a constant the key derivation cannot read: without it an
	// unread policy would count as evaluated-clean and close the finding.
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsSNSTopicPolicyPublic = Check{
	ID:          "aws-sns-topic-policy-public",
	Title:       "SNS topic policy allows public subscribe/publish",
	Description: "This topic's resource-based policy grants sns:Subscribe or sns:Publish to everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller. Any caller can subscribe an arbitrary endpoint to receive every message published to the topic (data exfiltration), or publish messages that downstream subscribers will process as trusted (message injection).",
	Remediation: "Remove the statement granting Principal \"*\" (or the Allow with NotPrincipal) from the topic policy: `aws sns set-topic-attributes --topic-arn ARN --attribute-name Policy --attribute-value file://policy.json`. Scope Principal to specific account/role ARNs, or add a Condition on aws:SourceAccount/aws:SourceArn for the standard cross-service pattern.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "sns_topic",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access"] == asset.PublicAccessConfirmed
	},
	// The tier is a constant the key derivation cannot read: without it an
	// unread policy would count as evaluated-clean and close the finding.
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsECRRepositoryPolicyPublic = Check{
	ID:          "aws-ecr-repository-policy-public",
	Title:       "ECR repository policy allows public image pull",
	Description: "This repository's resource-based policy grants ecr:BatchGetImage or ecr:GetDownloadUrlForLayer to everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller. Anyone can pull every image in the repository — including any embedded secrets, proprietary source, or internal tooling baked into the layers — without any AWS credentials.",
	Remediation: "Remove the statement granting Principal \"*\" (or the Allow with NotPrincipal) from the repository policy: `aws ecr set-repository-policy --repository-name NAME --policy-text file://policy.json`. Scope Principal to specific account/role ARNs.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecr_repository",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access"] == asset.PublicAccessConfirmed
	},
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsSecretsManagerResourcePolicyPublic = Check{
	ID:          "aws-secretsmanager-resource-policy-public",
	Title:       "Secrets Manager resource policy allows public GetSecretValue",
	Description: "This secret's resource-based policy grants secretsmanager:GetSecretValue to everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller. Any caller can retrieve the secret's plaintext value — credentials, API keys, or tokens — without any AWS credentials of their own.",
	Remediation: "Remove the statement granting Principal \"*\" (or the Allow with NotPrincipal) from the resource policy: `aws secretsmanager delete-resource-policy --secret-id ID` then reattach a scoped policy with `put-resource-policy`. Scope Principal to specific account/role ARNs.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "secretsmanager_secret",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access"] == asset.PublicAccessConfirmed
	},
	TableProbes: []string{asset.PublicAccessConfirmed},
}

// ── IAM (batch 2) ─────────────────────────────────────────────────────────────

// awsIAMAccessKeyOld is ONE finding per user graded by age tier (see
// accessKeyAgeSeverity), never one check per tier: the finding id does not
// include severity, so a key aging past a tier re-grades the same row.
var awsIAMAccessKeyOld = Check{
	ID:          "aws-iam-access-key-old",
	Title:       "IAM user has an access key older than 90 days",
	Description: "This IAM user has an active access key that was created more than 90 days ago. Long-lived access keys increase the blast radius of a credential leak — the older the key, the more likely it has been inadvertently committed to source control, logged, or shared. Severity is High when the user is an admin or the key is older than a year, Medium otherwise. A dormant admin user is reported by aws-iam-admin-user-dormant instead.",
	Remediation: "Rotate the key: create a new access key, update all consumers, then deactivate and delete the old key. Automate rotation using AWS Secrets Manager or enforce it via an IAM policy with a condition on `aws:TokenIssueTime`. For an admin key, replace it with a role rather than rotating it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	SeverityFor: accessKeyAgeSeverity,
	TitleFor:    accessKeyAgeTitle,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		return keyOlderThan(a.Metadata["access_key_age_days"], keyRotationDays) && !dormantAdminUser(a)
	},
}

var awsIAMRoleUnused = Check{
	ID:          "aws-iam-role-unused",
	Title:       "IAM role has not been used in more than 90 days",
	Description: "This IAM role has had no recorded API activity in over 90 days, or has never been used and is more than 90 days old. Stale roles accumulate unused permissions that widen the blast radius if the role is ever assumed by a compromised principal. AWS Access Advisor tracks last-used dates per service.",
	Remediation: "Review the role's policy and last-usage data. If no legitimate consumer exists, delete the role. If it is needed infrequently, reduce its permissions to the minimum required and add a usage-based alert.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates: func(a asset.Asset) bool {
		v := a.Metadata["last_used_days"]
		if v == "" || dormantAdminRole(a) {
			return false // a dormant admin role is aws-iam-admin-role-dormant's finding
		}
		// "9999" is the collector's never-used sentinel (no use inside GetRole's
		// ~400-day window), not a day count: such a role is stale once the role
		// itself is older than 90 days, the same rule dormantAdminRole applies.
		if v == "9999" {
			v = a.Metadata["created_days"]
		}
		days, err := strconv.Atoi(v)
		if err != nil {
			return false
		}
		return days > 90
	},
}

var awsIAMPublicTrustPolicy = Check{
	ID:          "aws-iam-public-trust-policy",
	Title:       "IAM role trust policy allows any principal to assume it",
	Description: "This role's trust policy contains an Allow statement with Principal \"*\" and no condition that pins the caller's organization, account or network — any AWS account (or in some configurations, anyone on the internet) can call sts:AssumeRole on it. A condition on TLS, MFA or an sts:ExternalId does not narrow who that is: a caller from any account can satisfy it. Combined with the role's permissions this is a direct account-takeover or confused-deputy path.",
	Remediation: "Scope the trust policy Principal to specific account IDs, IAM roles, or federated identity providers. Never use Principal: \"*\" without a Condition that pins the caller (e.g. aws:PrincipalOrgID or aws:PrincipalAccount); an ExternalId protects a role only when the Principal already names the trusted account.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_trust"] == "true"
	},
}

var gcpCloudRunUnauthenticated = Check{
	ID:          "gcp-cloudrun-unauthenticated",
	Title:       "Cloud Run service allows unauthenticated public access",
	Description: "This Cloud Run service permits unauthenticated invocations (allUsers/allAuthenticatedUsers has run.invoker). Anyone on the internet can invoke the service, reaching the container code and any backend it can access via its service account.",
	Remediation: "Remove the allUsers/allAuthenticatedUsers IAM binding for roles/run.invoker, or set ingress to 'internal' / 'internal-and-cloud-load-balancing' and front it with an authenticating load balancer (IAP).",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudrun_service",
	// Only fires on a confirmed allUsers invoker binding — the network-ingress
	// case is covered at low severity by gcp-cloudrun-public. Dormant until the
	// collector observes the IAM binding (public_access=confirmed).
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access"] == asset.PublicAccessConfirmed
	},
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsIAMRootActiveKey = Check{
	ID:          "aws-iam-root-active-key",
	Title:       "AWS root account has an active access key",
	Description: "The root account has an active access key. Root credentials have unrestricted access to every AWS service and cannot be scoped by IAM policies. A leaked root key enables complete account takeover with no recourse short of contacting AWS support.",
	Remediation: "Delete all root access keys immediately: sign in as root → My Security Credentials → Access keys → Delete. Use IAM users or roles with least-privilege policies for all programmatic access.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		// Only the account root (collectRootAccount sets root=true), and gate on
		// key *count*, not age — a brand-new root key has age 0 but count ≥ 1.
		if a.Metadata["root"] != "true" {
			return false
		}
		n, _ := strconv.Atoi(a.Metadata["active_key_count"])
		return n > 0
	},
}

var awsIAMRootNoMFA = Check{
	ID:          "aws-iam-root-no-mfa",
	Title:       "AWS root account has no MFA",
	Description: "The root user has no multi-factor authentication. Root credentials have unrestricted access to every AWS service and cannot be scoped by IAM policies; without MFA, a leaked or guessed root password gives an attacker complete, irrevocable account takeover. An account whose credential report shows no root password (AWS Organizations centralized root access) has no root sign-in to protect and is not reported. When the report does not say whether root has a password (it was unreadable, or its root row reads not_supported), the finding is still raised and its title says the password status is unknown.",
	Remediation: "Enable MFA on the root user immediately: sign in as root → My Security Credentials → Multi-factor authentication (MFA) → assign a device. Prefer a hardware MFA device stored securely, and avoid using the root user for day-to-day work.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	// Only the account root (collectRootAccount sets root=true, mfa_enabled).
	// console_access is the credential report's root password_enabled; only an
	// observed "false" (no root password) suppresses the finding.
	Violates: func(a asset.Asset) bool {
		return a.Metadata["root"] == "true" && a.Metadata["console_access"] != "false" && a.Metadata["mfa_enabled"] == "false"
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["console_access"] == "true" {
			return "AWS root account has no MFA"
		}
		return "AWS root account has no MFA (root password status unknown)"
	},
}

// ── EBS / KMS ─────────────────────────────────────────────────────────────────

var awsEBSUnencrypted = Check{
	ID:          "aws-ebs-unencrypted",
	Title:       "EBS volume is not encrypted",
	Description: "This EBS volume is not encrypted at rest. Unencrypted volumes are readable if a snapshot is shared accidentally, the volume is attached to a compromised instance, or the underlying hardware is removed from the data centre.",
	Remediation: "Enable EBS default encryption for the region: `aws ec2 enable-ebs-encryption-by-default`. For existing unencrypted volumes: create an encrypted snapshot, then restore to a new encrypted volume and update the attachment.",
	Type:        "misconfiguration",
	// Medium, not High: the data is sound but the threat model needs a
	// precondition this check can't see. The snapshot-exfil path is already
	// covered at Critical by aws-ebs-snapshot-public; the physical-media path
	// isn't a reachable attack against a hyperscaler; and remediation requires a
	// per-volume outage, which a cross-asset join (in-use + internet-exposed)
	// could justify but this check framework deliberately doesn't support. Flat
	// Medium is the honest grade without that join.
	Severity:  finding.SeverityMedium,
	Provider:  asset.ProviderAWS,
	AssetType: "ebs_volume",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["encrypted"] == "false"
	},
}

// awsKMSRotationGraded reports whether a key's own rotation setting can be
// turned on: only a symmetric encryption key (SYMMETRIC_DEFAULT) whose material
// KMS generated (origin AWS_KMS) outside a custom key store, and that is not a
// multi-Region replica. Asymmetric, HMAC, imported-material and
// custom-key-store keys cannot rotate automatically, and GetKeyRotationStatus
// reports false for them; a replica follows its primary's setting. Grading
// either would demand an impossible fix.
func awsKMSRotationGraded(a asset.Asset) bool {
	return a.Metadata["key_spec"] == "SYMMETRIC_DEFAULT" && a.Metadata["key_origin"] == "AWS_KMS" &&
		observedNone(a, "custom_key_store_id") &&
		(observedNone(a, "multi_region_key_type") || a.Metadata["multi_region_key_type"] == "PRIMARY")
}

var awsKMSRotationDisabled = Check{
	ID:          "aws-kms-rotation-disabled",
	Title:       "KMS customer-managed key does not have automatic rotation enabled",
	Description: "Automatic annual key rotation is disabled for this KMS customer-managed key (CMK). Without rotation, the same cryptographic material is used indefinitely, increasing the risk that a key material compromise goes undetected. Only symmetric encryption keys with KMS-generated key material outside a custom key store are graded: asymmetric, HMAC, imported-material and custom-key-store keys cannot rotate automatically. A multi-Region key is graded on its primary only, since a replica follows the primary's rotation setting.",
	Remediation: "Enable automatic rotation: `aws kms enable-key-rotation --key-id KEY_ID`. Rotation generates new key material annually; AWS retains old versions to decrypt data encrypted before the rotation.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "kms_key",
	// Only a usable key: rotating a disabled key or one pending deletion
	// protects nothing (CIS 4.6), and the latter is aws-kms-key-pending-deletion.
	Violates: func(a asset.Asset) bool {
		return a.Metadata["key_state"] == "Enabled" && awsKMSRotationGraded(a) && a.Metadata["rotation_enabled"] == "false"
	},
}

// ── GCP Compute ───────────────────────────────────────────────────────────────

var gcpGCENoOSLogin = Check{
	ID:          "gcp-gce-no-oslogin",
	Title:       "GCE instance does not have OS Login enabled",
	Description: "OS Login is not enabled on this instance. Without OS Login, SSH access relies on metadata-managed SSH keys that are not centrally audited, cannot be revoked via IAM, and bypass 2FA enforcement. OS Login binds SSH authentication to Google IAM, providing centralised key management and audit logs.",
	Remediation: "Enable OS Login at the instance level: set the metadata key `enable-oslogin=TRUE`. To enforce it project-wide, set the same key in project metadata and remove any metadata-managed SSH keys from the instance.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates: func(a asset.Asset) bool {
		// Explicit "false" only: resolveGCEControl omits the key when it's
		// genuinely unknown, and != "true" would wrongly flag those too.
		return a.Metadata["oslogin"] == "false"
	},
}

var gcpGCESerialPortEnabled = Check{
	ID:          "gcp-gce-serial-port-enabled",
	Title:       "GCE instance has interactive serial port access enabled",
	Description: "Interactive serial port access is enabled on this instance. The serial console provides low-level access to the instance without requiring SSH keys or network connectivity. An attacker with compute.instances.getSerialPortOutput or compute.instances.useSerialPort permission can interact with the instance at the kernel level.",
	Remediation: "Disable serial port access: set the instance metadata key `serial-port-enable=false`. Enforce it project-wide via an Organisation Policy: `constraints/compute.disableSerialPortAccess`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["serial_port_enabled"] == "true"
	},
}

var gcpGCEProjectSSHKeys = Check{
	ID:          "gcp-gce-project-ssh-keys",
	Title:       "GCE instance does not block project-wide SSH keys",
	Description: "This instance does not block project-level SSH keys, meaning any key added to the project metadata can authenticate to the instance. Project-wide SSH keys widen the blast radius of a key compromise and make it difficult to audit who can access individual instances.",
	Remediation: "Block project-wide SSH keys on the instance: set the metadata key `block-project-ssh-keys=true`. Manage instance access with OS Login or individual instance-level SSH keys instead.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["project_ssh_keys_blocked"] == "false"
	},
}

// ── GCP CloudSQL (batch 2) ────────────────────────────────────────────────────

var gcpCloudSQLNoDeletionProtection = Check{
	ID:          "gcp-cloudsql-no-deletion-protection",
	Title:       "Cloud SQL instance does not have deletion protection enabled",
	Description: "Deletion protection is disabled on this Cloud SQL instance. Any principal with cloudsql.instances.delete permission can permanently destroy the database. Accidental or malicious deletion of a production database is one of the highest-impact data loss scenarios.",
	Remediation: "Enable deletion protection in the Cloud Console or with the CLI: `gcloud sql instances patch INSTANCE --deletion-protection`. Also consider restricting cloudsql.instances.delete via IAM Conditions.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["deletion_protection_enabled"] == "false"
	},
}

var gcpCloudSQLBinaryLogDisabled = Check{
	ID:          "gcp-cloudsql-binary-log-disabled",
	Title:       "Cloud SQL MySQL instance has binary logging disabled",
	Description: "Binary logging is disabled on this MySQL Cloud SQL instance. Binary logs are required for point-in-time recovery (PITR) — without them, a restoration can only go back to a full backup window, potentially losing hours of transactions. Binary logs also support replication and forensic analysis after an incident.",
	Remediation: "Enable binary logging via the Cloud Console (Backups → Enable point-in-time recovery) or: `gcloud sql instances patch INSTANCE --enable-bin-log`. Note: this requires a restart.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		// The collector stores the engine string under "version" (e.g. MYSQL_8_0),
		// not "engine". Binary logging is a MySQL concept; skip Postgres/SQL Server.
		if !strings.Contains(strings.ToLower(a.Metadata["version"]), "mysql") {
			return false
		}
		// Present-and-empty only: the collector writes log_bin as "true" or ""
		// and omits it entirely when the API returned no BackupConfiguration.
		return observedNone(a, "log_bin")
	},
}

// ── GCP GCS ───────────────────────────────────────────────────────────────────

var gcpGCSUniformAccessDisabled = Check{
	ID:          "gcp-gcs-uniform-access-disabled",
	Title:       "GCS bucket does not have uniform bucket-level access enabled",
	Description: "Uniform bucket-level access (formerly Bucket Policy Only) is not enabled. When disabled, object-level ACLs can coexist with bucket IAM policies, making it easy to accidentally grant public access to individual objects without the bucket policy showing it. Uniform access enforces IAM exclusively, removing the ACL complexity.",
	Remediation: "Enable uniform bucket-level access: `gcloud storage buckets update gs://BUCKET --uniform-bucket-level-access`. Note: once enabled, ACLs are locked and cannot be set on individual objects.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcs_bucket",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["uniform_access"] == "false"
	},
}

var gcpGCSVersioningDisabled = Check{
	ID:          "gcp-gcs-versioning-disabled",
	Title:       "GCS bucket versioning is disabled",
	Description: "Object versioning is not enabled on this GCS bucket. Without versioning, overwritten or deleted objects cannot be recovered. This increases the impact of ransomware, accidental deletion, and runaway deployment pipelines that overwrite production assets.",
	Remediation: "Enable versioning: `gcloud storage buckets update gs://BUCKET --versioning`. Configure a lifecycle policy to expire non-current versions to control storage costs.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcs_bucket",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["versioning"] == "false"
	},
}

var gcpGCSLoggingDisabled = Check{
	ID:          "gcp-gcs-logging-disabled",
	Title:       "GCS bucket access logging is disabled",
	Description: "Usage logging is not enabled for this GCS bucket. Without access logs, there is no record of which principals accessed or modified objects — making it impossible to detect data exfiltration, investigate a breach, or demonstrate compliance with data-access regulations.",
	Remediation: "Enable usage logging: `gcloud storage buckets update gs://BUCKET --log-bucket=LOG_BUCKET --log-object-prefix=PREFIX`. Ensure the log bucket itself has appropriate retention and access controls.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcs_bucket",
	Violates: func(a asset.Asset) bool {
		// logging_bucket, not "logging" (that key is an enabled/disabled enum on
		// s3_bucket). Value is the destination log bucket's name; present-and-empty
		// means "observed, and there is none" — a missing key means nothing is known.
		return observedNone(a, "logging_bucket")
	},
}

// ── Azure WebApp ──────────────────────────────────────────────────────────────

var azureWebAppNoHTTPSOnly = Check{
	ID:          "azure-webapp-no-https-only",
	Title:       "Azure Web App does not enforce HTTPS",
	Description: "The HTTPS Only setting is disabled on this Web App, allowing clients to connect over plain HTTP. Credentials, session tokens, and sensitive data transmitted over HTTP are visible to network attackers and intermediate proxies.",
	Remediation: "Enable HTTPS Only in the Azure Portal (Settings → TLS/SSL settings → HTTPS Only: On) or: `az webapp update --name APP --resource-group RG --set httpsOnly=true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_webapp",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["https_only"] == "false"
	},
}

var azureWebAppNoTLS12 = Check{
	ID:          "azure-webapp-no-tls12",
	Title:       "Azure Web App minimum TLS version is below 1.2",
	Description: "This Web App accepts TLS connections below version 1.2. TLS 1.0 and 1.1 have known cryptographic weaknesses (BEAST, POODLE, DROWN) and are prohibited by PCI-DSS 3.2+ and NIST SP 800-52 Rev 2. Older TLS versions allow downgrade attacks and use weak cipher suites.",
	Remediation: "Set minimum TLS version to 1.2 or higher: `az webapp config set --name APP --resource-group RG --min-tls-version 1.2`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_webapp",
	Violates: func(a asset.Asset) bool {
		v := a.Metadata["min_tls_version"]
		if v == "" {
			return false // no data — skip rather than false-positive
		}
		// Compare as strings: "1.0" < "1.2", "1.1" < "1.2", "1.2" == "1.2", "1.3" > "1.2"
		return v < "1.2"
	},
}

// There is no Web App client-certificate check: mutual TLS is an architectural
// choice, not a control every Web App is expected to have — a public,
// browser-facing app can't require client certificates at all. The transport
// risk is covered by azure-webapp-no-https-only and azure-webapp-no-tls12.

// awsEBSSnapshotPublic flags an EBS snapshot shared with the "all" group — a
// direct data-exfiltration path: anyone on the internet can restore the snapshot
// into their own account and read the entire disk (databases, secrets, keys).
// This is how real breaches start; Critical.
var awsEBSSnapshotPublic = Check{
	ID:          "aws-ebs-snapshot-public",
	Title:       "EBS snapshot is publicly shared",
	Description: "This EBS snapshot grants CreateVolumePermission to the 'all' group, meaning any AWS account can create a volume from it and read every byte of the source disk — filesystems, databases, application secrets, and private keys. Public snapshots are a well-worn data-exfiltration and breach vector.",
	Remediation: "Remove public access immediately: `aws ec2 modify-snapshot-attribute --snapshot-id SNAP --attribute createVolumePermission --operation-type remove --group-names all`. Audit CloudTrail for CreateVolume calls from unknown accounts while it was public.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "ebs_snapshot",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

// awsRDSSnapshotPublic flags a manual DB snapshot shared with the "all" group.
// Anyone can restore a public DB snapshot into their account and read the entire
// database — the RDS analogue of a public EBS snapshot. Critical.
var awsRDSSnapshotPublic = Check{
	ID:          "aws-rds-snapshot-public",
	Title:       "RDS snapshot is publicly shared",
	Description: "This manual RDS DB snapshot is shared with the 'all' group, so any AWS account can restore it and read the entire database — every table, and any secrets stored in it. Public DB snapshots are a direct data-exfiltration and breach vector.",
	Remediation: "Remove public access immediately: `aws rds modify-db-snapshot-attribute --db-snapshot-identifier SNAP --attribute-name restore --values-to-remove all`. Audit CloudTrail for RestoreDBInstanceFromDBSnapshot calls from unknown accounts while it was public.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_snapshot",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

// azureDiskInternetExportable flags a managed disk that can be exported over the
// public internet (public network access enabled + AllowAll network policy).
// Anyone with a SAS URI can read the whole disk — a data-exfiltration path.
var azureDiskInternetExportable = Check{
	ID:          "azure-disk-internet-exportable",
	Title:       "Managed disk is exportable over the internet",
	Description: "This managed disk has public network access enabled with an AllowAll network policy, so its data can be exported via a SAS URI reachable from the public internet — filesystems, databases, and secrets on the disk all leak to anyone who obtains (or is granted) the URI.",
	Remediation: "Set the disk's network access policy to DenyAll or AllowPrivate and disable public network access, then export only over private endpoints when needed.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_disk",
	Violates:    func(a asset.Asset) bool { return a.Metadata["internet_exportable"] == "true" },
}

// awsAMIPublic flags an AMI shared publicly. Public AMIs routinely leak baked-in
// credentials, source code, and configuration to anyone who launches them.
var awsAMIPublic = Check{
	ID:          "aws-ami-public",
	Title:       "AMI is publicly shared",
	Description: "This Amazon Machine Image is public, so anyone can launch an instance from it. AMIs frequently contain baked-in secrets (API keys, database credentials), proprietary source code, and internal configuration — all of which leak to anyone who launches the image.",
	Remediation: "Make the AMI private: `aws ec2 modify-image-attribute --image-id AMI --launch-permission '{\"Remove\":[{\"Group\":\"all\"}]}'`. Rotate any credentials that may have been baked into the image.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "ami",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

// gcpImagePublic flags a Compute image shared with allUsers/allAuthenticatedUsers
// — anyone can create a disk from it and read baked-in secrets, code, and config.
var gcpImagePublic = Check{
	ID:          "gcp-image-public",
	Title:       "Compute image is publicly shared",
	Description: "This Compute Engine image grants an IAM role to allUsers or allAuthenticatedUsers, so anyone can create a disk from it and read its contents — baked-in credentials, source code, and internal configuration all leak.",
	Remediation: "Remove the public IAM binding: `gcloud compute images remove-iam-policy-binding IMAGE --member=allUsers --role=roles/compute.imageUser` (and allAuthenticatedUsers). Rotate any secrets baked into the image.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_image",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

// gcpSnapshotPublic flags a disk snapshot shared publicly — the GCP analogue of a
// public EBS snapshot: anyone can restore it and read the entire source disk.
var gcpSnapshotPublic = Check{
	ID:          "gcp-snapshot-public",
	Title:       "Disk snapshot is publicly shared",
	Description: "This persistent-disk snapshot grants an IAM role to allUsers or allAuthenticatedUsers, so any principal can create a disk from it and read every byte of the source volume — filesystems, databases, secrets, and keys. A direct data-exfiltration and breach vector.",
	Remediation: "Remove the public IAM binding: `gcloud compute snapshots remove-iam-policy-binding SNAPSHOT --member=allUsers --role=roles/compute.storageAdmin` (and allAuthenticatedUsers). Audit access logs for reads while it was public.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_disk_snapshot",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

// cspmExpandedChecks returns all checks defined in this file for registration
// via Default(). Kept as a function (not init) so tests can inspect the list.
func cspmExpandedChecks() []Check {
	return []Check{
		// EBS snapshot / AMI / RDS snapshot public sharing (data exfiltration)
		awsEBSSnapshotPublic,
		awsRDSSnapshotPublic,
		awsAMIPublic,
		azureDiskInternetExportable,
		// GCP image / disk snapshot public sharing (data exfiltration)
		gcpImagePublic,
		gcpSnapshotPublic,
		// S3 (batch 2)
		awsS3MFADeleteDisabled,
		awsS3WebsiteEnabled,
		// RDS (batch 2)
		awsRDSNoBackup,
		awsRDSNoDeletionProtection,
		awsRDSNoMultiAZ,
		// Lambda
		awsLambdaPublicAccess,
		awsLambdaNoVPC,
		awsLambdaDeprecatedRuntime,
		// Resource-based policy public exposure (KMS/SQS/SNS/ECR/Secrets Manager)
		awsKMSKeyPolicyPublic,
		awsSQSQueuePolicyPublic,
		awsSNSTopicPolicyPublic,
		awsECRRepositoryPolicyPublic,
		awsSecretsManagerResourcePolicyPublic,
		// IAM (batch 2)
		awsIAMAccessKeyOld,
		awsIAMRoleUnused,
		awsIAMRootActiveKey,
		awsIAMPublicTrustPolicy,
		// GCP serverless exposure
		gcpCloudRunUnauthenticated,
		// EBS / KMS
		awsEBSUnencrypted,
		awsKMSRotationDisabled,
		// GCP Compute
		gcpGCENoOSLogin,
		gcpGCESerialPortEnabled,
		gcpGCEProjectSSHKeys,
		// GCP CloudSQL (batch 2)
		gcpCloudSQLNoDeletionProtection,
		gcpCloudSQLBinaryLogDisabled,
		// GCP GCS
		gcpGCSUniformAccessDisabled,
		gcpGCSVersioningDisabled,
		gcpGCSLoggingDisabled,
		// Azure WebApp
		azureWebAppNoHTTPSOnly,
		azureWebAppNoTLS12,
	}
}
