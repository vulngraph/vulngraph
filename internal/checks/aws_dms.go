package checks

// aws_dms.go — AWS Database Migration Service posture (FSBP DMS.1, DMS.6-13)
// from dms:DescribeReplicationInstances / DescribeReplicationTasks /
// DescribeEndpoints. A replication instance holds the credentials to both
// ends of a migration and streams every row through itself, but it accepts no
// client logins of its own, so its public flag is network reachability (the
// possible tier) rather than open data; the rest is transport, authentication
// and operational hygiene.

import (
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsDMSChecks() []Check {
	return []Check{
		awsDMSReplicationInstancePublic,
		awsDMSAutoMinorUpgradeDisabled,
		awsDMSReplicationInstanceSingleAZ,
		awsDMSTaskTargetLoggingDisabled,
		awsDMSTaskSourceLoggingDisabled,
		awsDMSEndpointNoSSL,
		awsDMSNeptuneEndpointNoIAMAuth,
		awsDMSMongoDBEndpointNoAuth,
		awsDMSRedisEndpointNoTLS,
	}
}

var awsDMSReplicationInstancePublic = Check{
	ID:          "aws-dms-replication-instance-public",
	Title:       "DMS replication instance is publicly accessible",
	Description: "The replication instance was created with PubliclyAccessible=true, so it has a public IP address. It carries the credentials for its source and target databases and every migrated row passes through it; a public address puts that host on the internet when the endpoints are reachable privately (VPN, Direct Connect, peering). Network reachability only — there is no login on the instance itself — so it is graded Low. FSBP DMS.1.",
	Remediation: "Public access cannot be changed in place. Console: DMS → Replication instances → Create replication instance in the same VPC with \"Publicly accessible\" cleared, move the tasks to it, delete the old one. CLI: `aws dms create-replication-instance --replication-instance-identifier NEW --replication-instance-class CLASS --no-publicly-accessible ...`, `aws dms modify-replication-task` / recreate the tasks on it, then `aws dms delete-replication-instance --replication-instance-arn OLD_ARN`.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_replication_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["publicly_accessible"] == "true" },
}

var awsDMSAutoMinorUpgradeDisabled = Check{
	ID:          "aws-dms-auto-minor-upgrade-disabled",
	Title:       "DMS replication instance does not apply minor engine upgrades automatically",
	Description: "Automatic minor version upgrade is off, so DMS engine patches (bug and security fixes) are applied only when someone upgrades the instance by hand. FSBP DMS.6.",
	Remediation: "Console: DMS → Replication instances → Modify → enable \"Automatic version upgrade\". CLI: `aws dms modify-replication-instance --replication-instance-arn ARN --auto-minor-version-upgrade --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_replication_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["auto_minor_version_upgrade"] == "false" },
}

var awsDMSReplicationInstanceSingleAZ = Check{
	ID:          "aws-dms-replication-instance-single-az",
	Title:       "DMS replication instance is not Multi-AZ",
	Description: "The replication instance runs in a single Availability Zone with no standby, so an AZ or host failure stops every task on it until it is replaced. Availability only. FSBP DMS.13.",
	Remediation: "Console: DMS → Replication instances → Modify → set \"High Availability\" to Multi-AZ. CLI: `aws dms modify-replication-instance --replication-instance-arn ARN --multi-az --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_replication_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["multi_az"] == "false" },
}

const dmsLoggingRemediation = "Console: DMS → Database migration tasks → Modify → Task settings → enable CloudWatch logs and set the listed components to Default (or a debug level). CLI: stop the task, `aws dms modify-replication-task --replication-task-arn ARN --replication-task-settings file://settings.json` with `Logging.EnableLogging=true` and each component's Severity `LOGGER_SEVERITY_DEFAULT`, then restart it."

var awsDMSTaskTargetLoggingDisabled = Check{
	ID:          "aws-dms-task-target-logging-disabled",
	Title:       "DMS replication task does not log target-database activity",
	Description: "Task logging is off, or the TARGET_APPLY / TARGET_LOAD components log below LOGGER_SEVERITY_DEFAULT, so the errors and warnings raised while data and DDL are written to the target leave no CloudWatch record. FSBP DMS.7.",
	Remediation: dmsLoggingRemediation,
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_replication_task",
	Violates:    func(a asset.Asset) bool { return a.Metadata["target_logging_enabled"] == "false" },
}

var awsDMSTaskSourceLoggingDisabled = Check{
	ID:          "aws-dms-task-source-logging-disabled",
	Title:       "DMS replication task does not log source-database activity",
	Description: "Task logging is off, or the SOURCE_CAPTURE / SOURCE_UNLOAD components log below LOGGER_SEVERITY_DEFAULT, so full-load unloads and change capture from the source leave no CloudWatch record. FSBP DMS.8.",
	Remediation: dmsLoggingRemediation,
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_replication_task",
	Violates:    func(a asset.Asset) bool { return a.Metadata["source_logging_enabled"] == "false" },
}

// dmsSSLModeEngines are the endpoint engines whose transport encryption is
// the endpoint's SslMode. The others either always use TLS (Redshift, S3,
// DynamoDB, Kinesis, OpenSearch, Neptune — HTTPS APIs) or carry it in their
// own settings block (Kafka SecurityProtocol; Redis, graded by DMS.12), so an
// SslMode of "none" on them says nothing about the wire.
var dmsSSLModeEngines = []string{
	"aurora", "aurora-postgresql", "azuredb", "azure-sql-managed-instance", "babelfish",
	"db2", "db2-zos", "docdb", "mariadb", "mongodb", "mysql", "oracle", "postgres",
	"sqlserver", "sybase",
}

var awsDMSEndpointNoSSL = Check{
	ID:          "aws-dms-endpoint-no-ssl",
	Title:       "DMS endpoint connects to its database without SSL",
	Description: "The endpoint's SSL mode is none, so the replication instance talks to this database in clear text: the database credentials and every migrated row cross the network unencrypted, often between networks (on-premises to AWS). FSBP DMS.9. Endpoints whose engine has no SslMode setting (Redshift, S3, DynamoDB, Kinesis, Kafka, OpenSearch, Neptune, Redis) are not graded here.",
	Remediation: "Console: DMS → Endpoints → Modify → set SSL mode to require (or verify-ca / verify-full with a CA certificate). CLI: `aws dms modify-endpoint --endpoint-arn ARN --ssl-mode require` (import the database CA with `aws dms import-certificate` for verify-*), then test the connection.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_endpoint",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["ssl_mode"] == "none" && slices.Contains(dmsSSLModeEngines, a.Metadata["engine"])
	},
	TableProbes: dmsSSLModeEngines,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"engine": a.Metadata["engine"], "ssl_mode": "none"}
	},
}

var awsDMSNeptuneEndpointNoIAMAuth = Check{
	ID:          "aws-dms-neptune-endpoint-no-iam-auth",
	Title:       "DMS Neptune endpoint does not use IAM authorization",
	Description: "The Neptune target endpoint has IAM authorization off, so writes to the graph are not tied to the endpoint's service-access role and the Neptune cluster must accept unauthenticated loads. FSBP DMS.10.",
	Remediation: "Enable IAM authentication on the Neptune cluster, then Console: DMS → Endpoints → Modify → Neptune settings → enable IAM authorization with a service access role. CLI: `aws dms modify-endpoint --endpoint-arn ARN --neptune-settings IamAuthEnabled=true,ServiceAccessRoleArn=ROLE_ARN,S3BucketName=BUCKET,S3BucketFolder=PREFIX`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_endpoint",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["engine"] == "neptune" && a.Metadata["neptune_iam_auth_enabled"] == "false"
	},
}

var awsDMSMongoDBEndpointNoAuth = Check{
	ID:          "aws-dms-mongodb-endpoint-no-auth",
	Title:       "DMS MongoDB endpoint connects without authentication",
	Description: "The MongoDB endpoint's authentication type is \"no\": DMS reads the database without credentials, which means the MongoDB server itself accepts unauthenticated clients. FSBP DMS.11.",
	Remediation: "Enable authentication on the MongoDB server, then Console: DMS → Endpoints → Modify → MongoDB settings → Authentication mode password, mechanism SCRAM-SHA-1 (MongoDB 3.x+). CLI: `aws dms modify-endpoint --endpoint-arn ARN --username USER --password PASS --mongo-db-settings AuthType=password,AuthMechanism=scram_sha_1,AuthSource=admin`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_endpoint",
	Violates:    func(a asset.Asset) bool { return a.Metadata["mongodb_auth_type"] == "no" },
}

var awsDMSRedisEndpointNoTLS = Check{
	ID:          "aws-dms-redis-endpoint-no-tls",
	Title:       "DMS Redis endpoint connects without TLS",
	Description: "The Redis OSS target endpoint uses the plaintext security protocol, so migrated data and the Redis auth token cross the network unencrypted. FSBP DMS.12.",
	Remediation: "Enable in-transit encryption on the Redis target, then Console: DMS → Endpoints → Modify → Redis settings → SSL security protocol ssl-encryption. CLI: `aws dms modify-endpoint --endpoint-arn ARN --redis-settings SslSecurityProtocol=ssl-encryption,ServerName=HOST,Port=6379`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "dms_endpoint",
	Violates:    func(a asset.Asset) bool { return a.Metadata["redis_ssl_security_protocol"] == "plaintext" },
}
