package checks

// aws_backup_dynamodb.go — AWS Backup vaults and plans, DynamoDB tables and
// DAX clusters (AWS FSBP Backup.1, DynamoDB.1/2/3/6/7). Public vault and
// table policies are exposure; the rest is Low/Info resilience and
// encryption posture.

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var awsBackupVaultPolicyPublic = Check{
	ID:          "aws-backup-vault-policy-public",
	Title:       "Backup vault access policy is open to any principal",
	Description: "The vault's access policy allows everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller, to copy recovery points out, restore them, delete them, shorten their retention or rewrite the policy. Anyone in any account can then take a full copy of the backed-up data or destroy the backups a ransomware recovery depends on.",
	Remediation: "Remove the statement granting Principal \"*\" (or the Allow with NotPrincipal) or add an aws:PrincipalOrgID condition to it (console: AWS Backup > Backup vaults > vault > Access policy > Edit; CLI: `aws backup put-backup-vault-access-policy --backup-vault-name VAULT --policy file://policy.json`, or `delete-backup-vault-access-policy`). Add an explicit Deny on backup:DeleteRecoveryPoint for everyone but a break-glass role.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "backup_vault",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_access"] == asset.PublicAccessConfirmed },
	// The tier constant lives outside this package, so the key derivation
	// cannot harvest it as a probe; without it an unread policy would read as
	// evaluated-clean and close an open finding.
	TableProbes: []string{asset.PublicAccessConfirmed},
}

// positiveCount parses a non-negative count key; ok is false when absent.
func positiveCount(a asset.Asset, key string) (int, bool) {
	n, err := strconv.Atoi(a.Metadata[key])
	return n, err == nil
}

var awsBackupRecoveryPointsUnencrypted = Check{
	ID:          "aws-backup-recovery-points-unencrypted",
	Title:       "Backup vault holds unencrypted recovery points",
	Description: "Some recovery points in this vault are not encrypted at rest — typically backups of unencrypted EBS volumes or RDS instances, which inherit their source's encryption. One finding per vault; the count is in the evidence. FSBP Backup.1.",
	Remediation: "Encrypt the source resources so new backups inherit it, then copy the existing recovery points to a vault with a KMS key (console: AWS Backup > recovery point > Copy; CLI: `aws backup start-copy-job --recovery-point-arn RP --source-backup-vault-name VAULT --destination-backup-vault-arn ENCRYPTED_VAULT --iam-role-arn ROLE`) and delete the unencrypted ones.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "backup_vault",
	Violates: func(a asset.Asset) bool {
		n, ok := positiveCount(a, "unencrypted_recovery_points")
		return ok && n > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"unencrypted_recovery_points": a.Metadata["unencrypted_recovery_points"]}
	},
}

var awsBackupVaultNotLocked = Check{
	ID:          "aws-backup-vault-not-locked",
	Title:       "Backup vault has no Vault Lock",
	Description: "AWS Backup Vault Lock is not configured, so anyone with the vault's delete permissions — including an attacker holding an admin role — can delete recovery points or shorten their retention. Hygiene: many teams rely on cross-account copies instead.",
	Remediation: "Console: AWS Backup > Backup vaults > vault > Create vault lock. CLI: `aws backup put-backup-vault-lock-configuration --backup-vault-name VAULT --min-retention-days 7 --max-retention-days 365` (add --changeable-for-days to start in governance mode).",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "backup_vault",
	Violates: func(a asset.Asset) bool {
		// Only standard vaults take a lock; logically air-gapped and
		// restore-access vaults are locked by construction.
		return a.Metadata["locked"] == "false" && a.Metadata["vault_type"] == "BACKUP_VAULT"
	},
}

var awsBackupNoPlan = Check{
	ID:          "aws-backup-no-plan",
	Title:       "Region holds backups but has no backup plan",
	Description: "This region's backup vaults hold recovery points, but no AWS Backup plan exists to take new ones: the backups are one-off or left over from a deleted plan, and age out without replacement. A region that has never used AWS Backup (no vaults, or only empty ones) is not reported.",
	Remediation: "Create a plan and assign resources (console: AWS Backup > Backup plans > Create; CLI: `aws backup create-backup-plan --backup-plan file://plan.json` then `aws backup create-backup-selection`), or delete the stale recovery points if the region is retired.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_backup_settings",
	Violates: func(a asset.Asset) bool {
		plans, okPlans := positiveCount(a, "backup_plans")
		points, okPoints := positiveCount(a, "recovery_points")
		return okPlans && okPoints && plans == 0 && points > 0
	},
}

var awsDynamoDBTablePolicyPublic = Check{
	ID:          "aws-dynamodb-table-policy-public",
	Title:       "DynamoDB table policy grants any principal access to its items",
	Description: "The table's resource-based policy allows everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller, to read or write items (GetItem, Query, Scan, PutItem, PartiQL and similar) or export the table. Anyone with AWS credentials in any account can read or change the data.",
	Remediation: "Replace Principal \"*\" (or the Allow with NotPrincipal) with the accounts and roles that need access, or add an aws:PrincipalOrgID condition to the statement (console: DynamoDB > table > Permissions > Edit; CLI: `aws dynamodb put-resource-policy --resource-arn TABLE_ARN --policy file://policy.json`, or `delete-resource-policy`).",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "dynamodb_table",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_access"] == asset.PublicAccessConfirmed },
	// The tier constant lives outside this package, so the key derivation
	// cannot harvest it as a probe; without it an unread policy would read as
	// evaluated-clean and close an open finding.
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsDynamoDBNoAutoScaling = Check{
	ID:          "aws-dynamodb-no-autoscaling",
	Title:       "Provisioned DynamoDB table does not auto scale",
	Description: "The table uses provisioned capacity with no Application Auto Scaling target for its read or write capacity, so a traffic spike is throttled instead of absorbed. On-demand tables pass. FSBP DynamoDB.1 (table capacity; global secondary indexes are not graded).",
	Remediation: "Switch to on-demand (console: DynamoDB > table > Additional settings > Edit capacity; CLI: `aws dynamodb update-table --table-name T --billing-mode PAY_PER_REQUEST`) or register targets: `aws application-autoscaling register-scalable-target --service-namespace dynamodb --resource-id table/T --scalable-dimension dynamodb:table:ReadCapacityUnits --min-capacity 5 --max-capacity 100` (and WriteCapacityUnits) plus a target-tracking policy.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dynamodb_table",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["billing_mode"] == "PROVISIONED" &&
			(a.Metadata["read_autoscaling"] == "false" || a.Metadata["write_autoscaling"] == "false")
	},
}

var awsDynamoDBNoPITR = Check{
	ID:          "aws-dynamodb-no-pitr",
	Title:       "DynamoDB table has point-in-time recovery disabled",
	Description: "Point-in-time recovery is off, so an accidental or malicious write or delete can only be undone from an on-demand backup, if one exists. FSBP DynamoDB.2.",
	Remediation: "Console: DynamoDB > table > Backups > Point-in-time recovery > Edit. CLI: `aws dynamodb update-continuous-backups --table-name T --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dynamodb_table",
	Violates:    func(a asset.Asset) bool { return a.Metadata["point_in_time_recovery"] == "DISABLED" },
}

var awsDynamoDBNoDeletionProtection = Check{
	ID:          "aws-dynamodb-no-deletion-protection",
	Title:       "DynamoDB table does not have deletion protection",
	Description: "Deletion protection is off, so any principal with dynamodb:DeleteTable can drop the table and its data in one call. FSBP DynamoDB.6.",
	Remediation: "Console: DynamoDB > table > Additional settings > Deletion protection > Turn on. CLI: `aws dynamodb update-table --table-name T --deletion-protection-enabled`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dynamodb_table",
	Violates:    func(a asset.Asset) bool { return a.Metadata["deletion_protection"] == "false" },
}

var awsDAXNotEncryptedAtRest = Check{
	ID:          "aws-dax-not-encrypted-at-rest",
	Title:       "DAX cluster is not encrypted at rest",
	Description: "The DynamoDB Accelerator cluster was created without server-side encryption, so the cached table items on its nodes are stored in clear. Fixed at creation. FSBP DynamoDB.3.",
	Remediation: "Create a cluster with encryption (console: DynamoDB > DAX > Create cluster > Encryption at rest; CLI: `aws dax create-cluster ... --sse-specification Enabled=true`), point clients at it and delete the old cluster.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dax_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["sse_status"] == "DISABLED" },
}

var awsDAXNotEncryptedInTransit = Check{
	ID:          "aws-dax-not-encrypted-in-transit",
	Title:       "DAX cluster endpoint does not use TLS",
	Description: "The cluster endpoint's encryption type is NONE, so items travel between clients and the cache unencrypted inside the VPC. Fixed at creation. FSBP DynamoDB.7.",
	Remediation: "Create a cluster with TLS (console: DynamoDB > DAX > Create cluster > Encryption in transit; CLI: `aws dax create-cluster ... --cluster-endpoint-encryption-type TLS`), switch clients to the TLS endpoint and delete the old cluster.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dax_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["endpoint_encryption_type"] == "NONE" },
}
