package checks

// aws_data_posture.go — storage, database and key-management settings that
// no other check here covered: backup vault encryption and
// existence, CloudTrail bucket MFA Delete, the CloudWatch cross-account
// sharing role, DocumentDB/Neptune Multi-AZ, KMS key state and scope,
// OpenSearch slow logs, RDS default ports and retired engine versions, and S3
// default encryption.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsDataPostureChecks() []Check {
	return []Check{
		awsBackupVaultNotEncrypted,
		awsBackupNoVault,
		awsCloudTrailBucketNoMFADelete,
		awsCloudWatchCrossAccountRole,
		awsDocDBClusterSingleAZ,
		awsKMSCMKNotEnabled,
		awsKMSCMKMultiRegion,
		awsNeptuneClusterSingleAZ,
		awsOpenSearchSlowLogsDisabled,
		awsRDSClusterDefaultPort,
		awsRDSInstanceRetiredEngineVersion,
		awsS3NoDefaultEncryption,
		awsS3NotKMSEncrypted,
	}
}

var awsBackupVaultNotEncrypted = Check{
	ID:          "aws-backup-vault-not-encrypted",
	Title:       "AWS Backup vault has no encryption key",
	Description: "The vault listing reports no KMS key for the vault, so the recovery points stored in it are not encrypted at rest and a copy of the backing storage exposes every backed-up resource.",
	Remediation: "A vault's key is fixed at creation. Console: AWS Backup > Backup vaults > Create backup vault with an encryption key, point the backup plans at it, then copy or let age out the old recovery points. CLI: `aws backup create-backup-vault --backup-vault-name NEW --encryption-key-arn KEY_ARN`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "backup_vault",
	Violates: func(a asset.Asset) bool {
		return observedNone(a, "encryption_key_arn") && a.Metadata["vault_type"] != "LOGICALLY_AIR_GAPPED_BACKUP_VAULT"
	},
}

var awsBackupNoVault = Check{
	ID:          "aws-backup-no-vault",
	Title:       "Region has no AWS Backup vault",
	Description: "The region has no AWS Backup vault at all, so nothing in it can be backed up through AWS Backup and a deletion or ransomware event has no recovery point to restore from.",
	Remediation: "Console: AWS Backup > Backup vaults > Create backup vault (with a KMS key), then create a backup plan that targets it. CLI: `aws backup create-backup-vault --backup-vault-name NAME --encryption-key-arn KEY_ARN --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_backup_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["backup_vaults"] == "0" },
}

var awsCloudTrailBucketNoMFADelete = Check{
	ID:          "aws-cloudtrail-bucket-no-mfa-delete",
	Title:       "CloudTrail log bucket does not require MFA to delete objects",
	Description: "The S3 bucket an active trail delivers to does not have MFA Delete enabled, so anyone holding the bucket owner's credentials can permanently remove audit log versions without a second factor. Trails delivering to a bucket outside this sweep's inventory (a log-archive account) are not graded.",
	Remediation: "MFA Delete can only be enabled by the bucket owner's root user, on a versioned bucket. CLI (root credentials): `aws s3api put-bucket-versioning --bucket TRAIL_BUCKET --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa \"ROOT_MFA_ARN CODE\"`. There is no console option.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_cloudtrail",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["is_logging"] == "true" && a.Metadata["s3_bucket_mfa_delete"] == "Disabled"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"s3_bucket": a.Metadata["s3_bucket"]}
	},
}

const cloudWatchCrossAccountRoleName = "CloudWatch-CrossAccountSharingRole"

var awsCloudWatchCrossAccountRole = Check{
	ID:          "aws-iam-cloudwatch-cross-account-sharing-role",
	Title:       "CloudWatch cross-account sharing is enabled",
	Description: "The account has the CloudWatch-CrossAccountSharingRole role that CloudWatch creates when cross-account observability sharing is switched on, so other accounts can read this account's metrics, dashboards and alarms.",
	Remediation: "Console: CloudWatch > Settings > Cross-account sharing > remove the accounts that no longer need access, then delete the role in IAM. CLI: `aws iam delete-role --role-name CloudWatch-CrossAccountSharingRole` (detach its policies first).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    func(a asset.Asset) bool { return a.Name == cloudWatchCrossAccountRoleName },
}

var awsDocDBClusterSingleAZ = Check{
	ID:          "aws-docdb-cluster-single-az",
	Title:       "DocumentDB cluster does not have instances in multiple Availability Zones",
	Description: "The cluster reports Multi-AZ false, so all its instances sit in one Availability Zone and an AZ outage takes the cluster down until an instance is created elsewhere.",
	Remediation: "Console: DocumentDB > Clusters > the cluster > Actions > Add instances, in a different Availability Zone. CLI: `aws docdb create-db-instance --db-cluster-identifier ID --db-instance-identifier ID-replica --db-instance-class CLASS --engine docdb --availability-zone OTHER_AZ`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "docdb_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["multi_az"] == "false" },
}

var awsNeptuneClusterSingleAZ = Check{
	ID:          "aws-neptune-cluster-single-az",
	Title:       "Neptune cluster does not have instances in multiple Availability Zones",
	Description: "The cluster reports Multi-AZ false, so all its instances sit in one Availability Zone and an AZ outage takes the graph database down until an instance is created elsewhere.",
	Remediation: "Console: Neptune > Databases > the cluster > Actions > Add reader, in a different Availability Zone. CLI: `aws neptune create-db-instance --db-cluster-identifier ID --db-instance-identifier ID-reader --db-instance-class CLASS --engine neptune --availability-zone OTHER_AZ`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "neptune_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["multi_az"] == "false" },
}

// awsKMSCMKNotEnabled leaves PendingDeletion to aws-kms-key-pending-deletion.
var awsKMSCMKNotEnabled = Check{
	ID:          "aws-kms-cmk-not-enabled",
	Title:       "KMS customer-managed key is disabled or unusable",
	Description: "The customer-managed key is Disabled, Unavailable or pending import, so it is not being used for encryption and is cost and review noise at best, a broken dependency at worst. Keys scheduled for deletion (including replica deletion) are reported by aws-kms-key-pending-deletion instead, and transient Creating or Updating states are not reported.",
	Remediation: "If the key is still needed: console KMS > Customer managed keys > the key > Key actions > Enable; CLI: `aws kms enable-key --key-id KEY_ID`. If not, schedule it for deletion: `aws kms schedule-key-deletion --key-id KEY_ID --pending-window-in-days 30`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "kms_key",
	Violates: func(a asset.Asset) bool {
		return slices.Contains([]string{"Disabled", "Unavailable", "PendingImport"}, a.Metadata["key_state"])
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"key_state": a.Metadata["key_state"]}
	},
}

var awsKMSCMKMultiRegion = Check{
	ID:          "aws-kms-cmk-multi-region",
	Title:       "KMS customer-managed key is a multi-Region key",
	Description: "An enabled customer-managed key is a multi-Region key (primary or replica), so its key material is replicated into other Regions and the key policy of each replica widens where the key can be used. Multi-Region keys are justified only for cross-Region encryption use cases.",
	Remediation: "A key cannot be converted back to single-Region. Console: KMS > Customer managed keys > create a single-Region key, re-encrypt the data under it, then schedule the multi-Region key for deletion. CLI: `aws kms create-key`, then `aws kms schedule-key-deletion --key-id KEY_ID --pending-window-in-days 30`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "kms_key",
	Violates: func(a asset.Asset) bool {
		keyType, observed := a.Metadata["multi_region_key_type"]
		return a.Metadata["key_state"] == "Enabled" && observed && keyType != ""
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"multi_region_key_type": a.Metadata["multi_region_key_type"]}
	},
}

var awsOpenSearchSlowLogsDisabled = Check{
	ID:          "aws-opensearch-slow-logs-disabled",
	Title:       "OpenSearch domain does not publish both slow logs to CloudWatch Logs",
	Description: "The domain does not publish its search slow logs, its index slow logs, or both, to CloudWatch Logs, so slow or abusive queries and indexing leave no record for performance or incident work.",
	Remediation: "Console: OpenSearch Service > Domains > DOMAIN > Logs > enable Search slow logs and Index slow logs with a CloudWatch log group. CLI: `aws opensearch update-domain-config --domain-name DOMAIN --log-publishing-options 'SEARCH_SLOW_LOGS={CloudWatchLogsLogGroupArn=ARN,Enabled=true},INDEX_SLOW_LOGS={CloudWatchLogsLogGroupArn=ARN,Enabled=true}'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["search_slow_logs_enabled"] == "false" || a.Metadata["index_slow_logs_enabled"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"search_slow_logs_enabled": a.Metadata["search_slow_logs_enabled"],
			"index_slow_logs_enabled":  a.Metadata["index_slow_logs_enabled"],
		}
	},
}

// rdsClusterDefaultPorts maps an engine default port to the engine-name
// fragments that use it; an engine matches when its name contains a fragment.
var rdsClusterDefaultPorts = map[int][]string{
	3306:  {"mysql", "mariadb", "aurora-mysql"},
	5432:  {"postgres", "aurora-postgresql"},
	1521:  {"oracle"},
	1433:  {"sqlserver"},
	50000: {"db2"},
}

func rdsClusterOnDefaultPort(a asset.Asset) bool {
	port, err := strconv.Atoi(a.Metadata["port"])
	engine := strings.ToLower(a.Metadata["engine"])
	if err != nil || engine == "" {
		return false
	}
	for _, fragment := range rdsClusterDefaultPorts[port] {
		if strings.Contains(engine, fragment) {
			return true
		}
	}
	return false
}

var awsRDSClusterDefaultPort = Check{
	ID:          "aws-rds-cluster-default-port",
	Title:       "RDS DB cluster listens on its engine's default port",
	Description: "The cluster accepts connections on the well-known port of its engine (3306, 5432, 1521, 1433 or 50000), which is the first port automated scanners and credential-stuffing tools try against a database endpoint.",
	Remediation: "Console: RDS > Databases > the cluster > Modify > Database port, then update clients and security groups. CLI: `aws rds modify-db-cluster --db-cluster-identifier ID --port 3307 --apply-immediately` (the cluster restarts).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates:    rdsClusterOnDefaultPort,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"engine": a.Metadata["engine"], "port": a.Metadata["port"]}
	},
}

// rdsRetiredVersionEngines are the engines whose version catalogue maps to
// community end-of-life; the other engines (Oracle, SQL Server, Db2, custom
// engine versions) name versions the catalogue does not list reliably.
var rdsRetiredVersionEngines = []string{"mysql", "mariadb", "postgres"}

var awsRDSInstanceRetiredEngineVersion = Check{
	ID:          "aws-rds-instance-retired-engine-version",
	Title:       "RDS instance runs an engine version RDS no longer offers",
	Description: "A MySQL, MariaDB or PostgreSQL instance's engine version is missing from the versions RDS currently offers for that engine in the region, so it is deprecated or past end of standard support. Other engines are not evaluated. Instances on paid extended support can still be patched; check the version's support dates before treating this as unpatched.",
	Remediation: "Console: RDS > Databases > the instance > Modify > DB engine version, choose a supported version. CLI: `aws rds describe-db-engine-versions --engine ENGINE` to list them, then `aws rds modify-db-instance --db-instance-identifier ID --engine-version VERSION --allow-major-version-upgrade --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["engine_version_available"] == "false" && slices.Contains(rdsRetiredVersionEngines, a.Metadata["engine"])
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"engine": a.Metadata["engine"], "engine_version": a.Metadata["engine_version"]}
	},
}

var awsS3NoDefaultEncryption = Check{
	ID:          "aws-s3-no-default-encryption",
	Title:       "S3 bucket has no default encryption configuration",
	Description: "The bucket has no server-side encryption configuration, so the encryption of its objects depends on each writer requesting it and its policy and key choice cannot be audited from the bucket.",
	Remediation: "Console: S3 > the bucket > Properties > Default encryption > Edit, choose SSE-S3 or SSE-KMS. CLI: `aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "encryption") },
}

var awsS3NotKMSEncrypted = Check{
	ID:          "aws-s3-not-kms-encrypted",
	Title:       "S3 bucket default encryption does not use KMS",
	Description: "The bucket's default encryption is absent or is SSE-S3 (AES256) rather than SSE-KMS, so access to the data cannot be controlled or audited through a customer-managed key's policy and CloudTrail Decrypt events.",
	Remediation: "Console: S3 > the bucket > Properties > Default encryption > Edit > AWS KMS key. CLI: `aws s3api put-bucket-encryption --bucket BUCKET --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"KEY_ARN\"}}]}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates: func(a asset.Asset) bool {
		algorithm, observed := a.Metadata["encryption"]
		return observed && algorithm != "aws:kms" && algorithm != "aws:kms:dsse"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"encryption": a.Metadata["encryption"]}
	},
}
