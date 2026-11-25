package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Amazon DocumentDB and Neptune cluster posture (FSBP DocumentDB.1/2/4/5/6,
// Neptune.1/2/4/5/6/7/8). Both run on the RDS control plane, so the same
// rds:DescribeDBClusters read feeds them, under their own asset types and
// controls. Severity follows the RDS cluster checks.

func awsDocDBNeptuneChecks() []Check {
	return []Check{
		awsDocDBClusterNotEncrypted,
		awsDocDBClusterShortBackupRetention,
		awsDocDBClusterNoAuditLogExport,
		awsDocDBClusterNoDeletionProtection,
		awsDocDBClusterTLSNotRequired,
		awsNeptuneClusterNotEncrypted,
		awsNeptuneClusterNoAuditLogExport,
		awsNeptuneClusterNoDeletionProtection,
		awsNeptuneClusterShortBackupRetention,
		awsNeptuneClusterNoIAMAuth,
		awsNeptuneClusterNoCopyTagsToSnapshot,
	}
}

// ── DocumentDB ───────────────────────────────────────────────────────────────

var awsDocDBClusterNotEncrypted = Check{
	ID:          "aws-docdb-cluster-not-encrypted",
	Title:       "DocumentDB cluster storage is not encrypted at rest",
	Description: "The DocumentDB cluster was created without storage encryption, so its volume, backups and snapshots hold every document in clear for anyone with access to the storage or a snapshot copy. FSBP DocumentDB.1.",
	Remediation: "Encryption can only be chosen at creation. Console: DocumentDB > Snapshots > take a snapshot > Restore with encryption enabled (a KMS key). CLI: `aws docdb create-db-cluster-snapshot`, then `aws docdb restore-db-cluster-from-snapshot --kms-key-id KEY ...`, move clients and delete the unencrypted cluster.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "docdb_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["storage_encrypted"] == "false" },
}

var awsDocDBClusterShortBackupRetention = Check{
	ID:          "aws-docdb-cluster-short-backup-retention",
	Title:       "DocumentDB cluster keeps automated backups for less than 7 days",
	Description: "The cluster's backup retention period is below the 7 days FSBP DocumentDB.2 requires (DocumentDB defaults to 1 day), so a corruption noticed later than that cannot be restored to a point before it.",
	Remediation: "Console: DocumentDB > Clusters > the cluster > Modify > Backup retention period >= 7 days. CLI: `aws docdb modify-db-cluster --db-cluster-identifier ID --backup-retention-period 7 --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "docdb_cluster",
	Violates:    clusterBackupRetentionShort,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"backup_retention_days": a.Metadata["backup_retention"]}
	},
}

var awsDocDBClusterNoAuditLogExport = Check{
	ID:          "aws-docdb-cluster-no-audit-log-export",
	Title:       "DocumentDB cluster does not publish audit logs to CloudWatch Logs",
	Description: "The cluster does not export its audit log to CloudWatch Logs, so authentication attempts, dropped collections and other audited events leave no durable record. FSBP DocumentDB.4.",
	Remediation: "Set audit_logs = enabled in the cluster parameter group, then Console: DocumentDB > the cluster > Modify > Log exports > Audit. CLI: `aws docdb modify-db-cluster --db-cluster-identifier ID --cloudwatch-logs-export-configuration '{\"EnableLogTypes\":[\"audit\"]}' --apply-immediately`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "docdb_cluster",
	Violates: func(a asset.Asset) bool {
		exported, ok := logExported(a, "audit")
		return ok && !exported
	},
}

var awsDocDBClusterNoDeletionProtection = Check{
	ID:          "aws-docdb-cluster-no-deletion-protection",
	Title:       "DocumentDB cluster does not have deletion protection enabled",
	Description: "Deletion protection is off, so any principal with rds:DeleteDBCluster can delete the cluster in one call. FSBP DocumentDB.5.",
	Remediation: "Console: DocumentDB > Clusters > the cluster > Modify > Enable deletion protection. CLI: `aws docdb modify-db-cluster --db-cluster-identifier ID --deletion-protection --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "docdb_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["deletion_protection"] == "false" },
}

var awsDocDBClusterTLSNotRequired = Check{
	ID:          "aws-docdb-cluster-tls-not-required",
	Title:       "DocumentDB cluster does not enforce a current TLS version",
	Description: "The cluster parameter group's tls setting is disabled or the permissive \"enabled\" (which still accepts TLS 1.0/1.1), or the group is not applied to every instance. FSBP DocumentDB.6 passes only tls1.2+, tls1.3+ or fips-140-3.",
	Remediation: "Console: DocumentDB > Parameter groups > the cluster parameter group > tls = tls1.2+, then reboot each instance. CLI: `aws docdb modify-db-cluster-parameter-group --db-cluster-parameter-group-name GROUP --parameters ParameterName=tls,ParameterValue=tls1.2+,ApplyMethod=pending-reboot`, then `aws docdb reboot-db-instance --db-instance-identifier ID` per instance.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "docdb_cluster",
	Violates: func(a asset.Asset) bool {
		tls, ok := a.Metadata["tls"]
		if !ok {
			return false
		}
		return tls == "disabled" || tls == "enabled" || a.Metadata["parameter_group_in_sync"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"tls": a.Metadata["tls"], "parameter_group_in_sync": a.Metadata["parameter_group_in_sync"]}
	},
}

// ── Neptune ──────────────────────────────────────────────────────────────────

var awsNeptuneClusterNotEncrypted = Check{
	ID:          "aws-neptune-cluster-not-encrypted",
	Title:       "Neptune cluster storage is not encrypted at rest",
	Description: "The Neptune cluster was created without storage encryption, so the graph data, backups and snapshots are held in clear for anyone with access to the storage or a snapshot copy. FSBP Neptune.1; automated cluster snapshots inherit this setting (Neptune.6).",
	Remediation: "Encryption can only be chosen at creation. Console: Neptune > Snapshots > take a snapshot > Restore with encryption enabled. CLI: `aws neptune create-db-cluster-snapshot`, then `aws neptune restore-db-cluster-from-snapshot --kms-key-id KEY ...`, move clients and delete the unencrypted cluster.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "neptune_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["storage_encrypted"] == "false" },
}

var awsNeptuneClusterNoAuditLogExport = Check{
	ID:          "aws-neptune-cluster-no-audit-log-export",
	Title:       "Neptune cluster does not publish audit logs to CloudWatch Logs",
	Description: "The cluster does not export its audit log to CloudWatch Logs, so queries and access to the graph leave no durable record. FSBP Neptune.2.",
	Remediation: "Set neptune_enable_audit_log = 1 in the cluster parameter group, then Console: Neptune > the cluster > Modify > Log exports > Audit. CLI: `aws neptune modify-db-cluster --db-cluster-identifier ID --cloudwatch-logs-export-configuration '{\"EnableLogTypes\":[\"audit\"]}' --apply-immediately`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "neptune_cluster",
	Violates: func(a asset.Asset) bool {
		exported, ok := logExported(a, "audit")
		return ok && !exported
	},
}

var awsNeptuneClusterNoDeletionProtection = Check{
	ID:          "aws-neptune-cluster-no-deletion-protection",
	Title:       "Neptune cluster does not have deletion protection enabled",
	Description: "Deletion protection is off, so any principal with rds:DeleteDBCluster can delete the cluster in one call. FSBP Neptune.4.",
	Remediation: "Console: Neptune > Databases > the cluster > Modify > Enable deletion protection. CLI: `aws neptune modify-db-cluster --db-cluster-identifier ID --deletion-protection --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "neptune_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["deletion_protection"] == "false" },
}

var awsNeptuneClusterShortBackupRetention = Check{
	ID:          "aws-neptune-cluster-short-backup-retention",
	Title:       "Neptune cluster keeps automated backups for less than 7 days",
	Description: "The cluster's backup retention period is below the 7 days FSBP Neptune.5 requires, so a corruption noticed later than that cannot be restored to a point before it.",
	Remediation: "Console: Neptune > Databases > the cluster > Modify > Backup retention period >= 7 days. CLI: `aws neptune modify-db-cluster --db-cluster-identifier ID --backup-retention-period 7 --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "neptune_cluster",
	Violates:    clusterBackupRetentionShort,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"backup_retention_days": a.Metadata["backup_retention"]}
	},
}

var awsNeptuneClusterNoIAMAuth = Check{
	ID:          "aws-neptune-cluster-no-iam-auth",
	Title:       "Neptune cluster does not use IAM database authentication",
	Description: "IAM database authentication is off, so requests to the graph are not signed with SigV4 by an IAM principal and access cannot be granted, revoked or audited through IAM. FSBP Neptune.7.",
	Remediation: "Console: Neptune > Databases > the cluster > Modify > IAM DB authentication > Enable. CLI: `aws neptune modify-db-cluster --db-cluster-identifier ID --enable-iam-database-authentication --apply-immediately`, then sign client requests with SigV4.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "neptune_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["iam_auth_enabled"] == "false" },
}

var awsNeptuneClusterNoCopyTagsToSnapshot = Check{
	ID:          "aws-neptune-cluster-no-copy-tags-to-snapshot",
	Title:       "Neptune cluster does not copy tags to snapshots",
	Description: "CopyTagsToSnapshot is off, so the cluster's snapshots lose its ownership and classification tags. FSBP Neptune.8.",
	Remediation: "Console: Neptune > Databases > the cluster > Modify > Copy tags to snapshots. CLI: `aws neptune modify-db-cluster --db-cluster-identifier ID --copy-tags-to-snapshot --apply-immediately`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "neptune_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["copy_tags_to_snapshot"] == "false" },
}
