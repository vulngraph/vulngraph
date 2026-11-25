package checks

import (
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// RDS DB cluster posture (Aurora MySQL/PostgreSQL and Multi-AZ DB clusters,
// asset type rds_cluster) from rds:DescribeDBClusters and the cluster
// parameter group: AWS FSBP RDS.7/12/14/15/16/24/27/34/35/37/45/47/48/50 and
// CIS AWS 3.2.1/3.2.4. Cluster-member instances are excluded from the
// matching instance checks (rdsClusterMember), so each setting is reported
// once, on the cluster that owns it. Encryption is Medium like
// aws-rds-not-encrypted; the rest is resilience, logging and hygiene that
// teams routinely waive, so Low or Info — a cluster's real exposure is graded
// on its instances (aws-rds-publicly-accessible).

func awsRDSClusterChecks() []Check {
	return []Check{
		awsRDSClusterNotEncrypted,
		awsRDSClusterNoDeletionProtection,
		awsRDSClusterNoIAMAuth,
		awsRDSClusterNoBacktracking,
		awsRDSClusterSingleAZ,
		awsRDSClusterNoCopyTagsToSnapshot,
		awsRDSClusterDefaultMasterUsername,
		awsRDSClusterShortBackupRetention,
		awsRDSClusterAutoMinorUpgradeDisabled,
		awsAuroraMySQLNoAuditLogExport,
		awsAuroraPostgreSQLNoLogExport,
		awsAuroraMySQLAuditLoggingDisabled,
		awsRDSProxyTLSNotRequired,
		awsRDSGlobalClusterUnsupportedVersion,
	}
}

// clusterBackupRetentionShort reports a parsed cluster backup retention below
// the 7 days FSBP RDS.50 / DocumentDB.2 / Neptune.5 require.
func clusterBackupRetentionShort(a asset.Asset) bool {
	n, err := strconv.Atoi(a.Metadata["backup_retention"])
	return err == nil && n < rdsMinBackupRetentionDays
}

// logExported reports whether an observed log-export list contains logType;
// ok is false when the list was not read.
func logExported(a asset.Asset, logType string) (exported, ok bool) {
	raw, ok := a.Metadata["log_exports"]
	if !ok {
		return false, false
	}
	return slices.Contains(strings.Split(raw, ","), logType), true
}

// auroraServerlessV1 is an Aurora Serverless v1 cluster (EngineMode
// serverless), which supports neither log exports, backtracking nor IAM
// authentication — FSBP does not grade it for them.
func auroraServerlessV1(a asset.Asset) bool { return a.Metadata["engine_mode"] == "serverless" }

var awsRDSClusterNotEncrypted = Check{
	ID:          "aws-rds-cluster-not-encrypted",
	Title:       "RDS DB cluster storage is not encrypted at rest",
	Description: "The Aurora or Multi-AZ DB cluster has storage encryption disabled, so its volume, automated backups and snapshots hold every table in clear for anyone with access to the underlying storage or a copy of a snapshot. FSBP RDS.27, CIS AWS 3.2.1; automated cluster snapshots inherit this setting (RDS.4).",
	Remediation: "Encryption can only be chosen at creation. Console: RDS > Snapshots > take a cluster snapshot > Actions > Copy snapshot with encryption enabled > Restore. CLI: `aws rds create-db-cluster-snapshot`, `aws rds copy-db-cluster-snapshot --kms-key-id KEY ...`, `aws rds restore-db-cluster-from-snapshot ...`, then move clients and delete the unencrypted cluster.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["storage_encrypted"] == "false" },
}

var awsRDSClusterNoDeletionProtection = Check{
	ID:          "aws-rds-cluster-no-deletion-protection",
	Title:       "RDS DB cluster does not have deletion protection enabled",
	Description: "Deletion protection is off, so any principal with rds:DeleteDBCluster can delete the cluster (and, unless a final snapshot is requested, its automated backups) in one call. FSBP RDS.7.",
	Remediation: "Console: RDS > Databases > the cluster > Modify > Enable deletion protection. CLI: `aws rds modify-db-cluster --db-cluster-identifier ID --deletion-protection --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["deletion_protection"] == "false" },
}

// rdsClusterIAMAuthEngines are the cluster engines that support IAM database
// authentication.
var rdsClusterIAMAuthEngines = []string{"aurora", "aurora-mysql", "aurora-postgresql", "mysql", "postgres"}

var awsRDSClusterNoIAMAuth = Check{
	ID:          "aws-rds-cluster-no-iam-auth",
	Title:       "RDS DB cluster does not use IAM database authentication",
	Description: "IAM database authentication is disabled on the cluster, so every connection to it and its instances authenticates with a long-lived database password rather than a short-lived IAM token tied to an auditable principal. FSBP RDS.12 (and RDS.10 for the cluster's instances).",
	Remediation: "Console: RDS > Databases > the cluster > Modify > Database authentication > Password and IAM database authentication. CLI: `aws rds modify-db-cluster --db-cluster-identifier ID --enable-iam-database-authentication --apply-immediately`, then grant `rds_iam` (PostgreSQL) or create users with AWSAuthenticationPlugin (MySQL).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["iam_auth_enabled"] == "false" && !auroraServerlessV1(a) &&
			slices.Contains(rdsClusterIAMAuthEngines, a.Metadata["engine"])
	},
	TableProbes: rdsClusterIAMAuthEngines,
}

var awsRDSClusterNoBacktracking = Check{
	ID:          "aws-rds-cluster-no-backtracking",
	Title:       "Aurora MySQL cluster does not have backtracking enabled",
	Description: "Backtracking is off (BacktrackWindow 0), so recovering from a bad write or a destructive statement means a point-in-time restore into a new cluster instead of rewinding this one in minutes. FSBP RDS.14. Global database members are not graded: Aurora does not support backtracking for them.",
	Remediation: "Backtracking cannot be enabled on an existing cluster. Console: RDS > the cluster > Actions > Restore to point in time (or create a clone) with Enable Backtrack and a target window. CLI: `aws rds restore-db-cluster-to-point-in-time --source-db-cluster-identifier ID --db-cluster-identifier NEW --backtrack-window 86400 --use-latest-restorable-time`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates: func(a asset.Asset) bool {
		_, global := a.Metadata["global_cluster_id"]
		return a.Metadata["engine"] == "aurora-mysql" && a.Metadata["backtrack_window"] == "0" &&
			!auroraServerlessV1(a) && !global
	},
}

var awsRDSClusterSingleAZ = Check{
	ID:          "aws-rds-cluster-single-az",
	Title:       "RDS DB cluster has instances in only one Availability Zone",
	Description: "The cluster's DB instances all sit in one Availability Zone (MultiAZ false), so an AZ outage or the writer's failure leaves no reader in another zone to promote — the cluster is unavailable until a new instance is created. FSBP RDS.15, CIS AWS 3.2.4.",
	Remediation: "Console: RDS > Databases > the cluster > Actions > Add reader, in a different Availability Zone. CLI: `aws rds create-db-instance --db-cluster-identifier ID --db-instance-identifier ID-reader --engine ENGINE --db-instance-class CLASS --availability-zone OTHER_AZ`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	// Aurora Serverless v1 has no instances to place (its capacity moves
	// between zones on its own), and a cluster with no members — a headless
	// secondary of a global database — has no instance in any zone to spread.
	Violates: func(a asset.Asset) bool {
		return a.Metadata["multi_az"] == "false" && !auroraServerlessV1(a) && a.Metadata["member_count"] != "0"
	},
}

var awsRDSClusterNoCopyTagsToSnapshot = Check{
	ID:          "aws-rds-cluster-no-copy-tags-to-snapshot",
	Title:       "RDS DB cluster does not copy tags to snapshots",
	Description: "CopyTagsToSnapshot is off, so the cluster's snapshots lose its ownership and classification tags — and with them any tag-based access control or retention policy. FSBP RDS.16 (Aurora), RDS.47 (RDS for PostgreSQL clusters), RDS.48 (RDS for MySQL clusters).",
	Remediation: "Console: RDS > Databases > the cluster > Modify > Copy tags to snapshots. CLI: `aws rds modify-db-cluster --db-cluster-identifier ID --copy-tags-to-snapshot --apply-immediately`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["copy_tags_to_snapshot"] == "false" },
}

var awsRDSClusterDefaultMasterUsername = Check{
	ID:          "aws-rds-cluster-default-master-username",
	Title:       "RDS DB cluster uses a default administrator username",
	Description: "The cluster's master user is named after an engine default (admin, postgres, root or sa). Knowing the administrator's name halves a password-guessing attack; a custom name removes that head start. FSBP RDS.24.",
	Remediation: "The master username cannot be changed in place: create a new administrative user with a custom name (`CREATE USER ...` with the needed grants), move automation to it and restrict the default account; give new clusters a custom `--master-username`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates: func(a asset.Asset) bool {
		return slices.Contains(rdsDefaultMasterUsernames, strings.ToLower(a.Metadata["master_username"]))
	},
	TableProbes: rdsDefaultMasterUsernames,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"master_username": a.Metadata["master_username"]}
	},
}

var awsRDSClusterShortBackupRetention = Check{
	ID:          "aws-rds-cluster-short-backup-retention",
	Title:       "RDS DB cluster keeps automated backups for less than 7 days",
	Description: "The cluster's backup retention period is below the 7 days FSBP RDS.50 requires, so a corruption or destructive change noticed later than that cannot be restored to a point before it.",
	Remediation: "Console: RDS > Databases > the cluster > Modify > Backup retention period >= 7 days. CLI: `aws rds modify-db-cluster --db-cluster-identifier ID --backup-retention-period 7 --apply-immediately`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates:    clusterBackupRetentionShort,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"backup_retention_days": a.Metadata["backup_retention"]}
	},
}

var awsRDSClusterAutoMinorUpgradeDisabled = Check{
	ID:          "aws-rds-cluster-auto-minor-upgrade-disabled",
	Title:       "RDS DB cluster does not apply minor engine upgrades automatically",
	Description: "Automatic minor version upgrade is off on the cluster, so engine security patches released as minor versions reach it only when someone upgrades by hand. FSBP RDS.35.",
	Remediation: "Console: RDS > Databases > the cluster > Modify > Auto minor version upgrade. CLI: `aws rds modify-db-cluster --db-cluster-identifier ID --auto-minor-version-upgrade --apply-immediately`, or confirm a manual patching process covers it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["auto_minor_version_upgrade"] == "false" },
}

// auroraMySQLAuditDisabled reports an Aurora MySQL cluster whose Advanced
// Auditing is not effectively on (FSBP RDS.45): server_audit_logging is not 1,
// server_audit_events is empty, or the parameter group is not applied to
// every member. An unread parameter group decides nothing.
func auroraMySQLAuditDisabled(a asset.Asset) bool {
	logging, ok := a.Metadata["server_audit_logging"]
	if a.Metadata["engine"] != "aurora-mysql" || !ok {
		return false
	}
	return logging != "1" || observedNone(a, "server_audit_events") || a.Metadata["parameter_group_in_sync"] == "false"
}

var awsAuroraMySQLAuditLoggingDisabled = Check{
	ID:          "aws-rds-aurora-mysql-audit-logging-disabled",
	Title:       "Aurora MySQL cluster has database audit logging disabled",
	Description: "Advanced Auditing is not in effect in the cluster parameter group (server_audit_logging is not 1, server_audit_events is empty, or the group is not applied to every instance), so logins, queries and schema changes are not recorded at all — there is nothing to export or investigate. FSBP RDS.45; a cluster in this state is not also reported for its missing audit-log export (RDS.34).",
	Remediation: "Console: RDS > Parameter groups > the cluster parameter group > set server_audit_logging = 1 and server_audit_events = CONNECT,QUERY_DCL,QUERY_DDL (at least), then reboot or apply to every instance, and export the audit log (Modify > Log exports > Audit log). CLI: `aws rds modify-db-cluster-parameter-group --db-cluster-parameter-group-name GROUP --parameters ParameterName=server_audit_logging,ParameterValue=1,ApplyMethod=immediate ParameterName=server_audit_events,ParameterValue=CONNECT,ApplyMethod=immediate`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates:    auroraMySQLAuditDisabled,
	EvidenceFor: func(a asset.Asset) map[string]string {
		exported, _ := logExported(a, "audit")
		return map[string]string{
			"server_audit_logging":    a.Metadata["server_audit_logging"],
			"server_audit_events":     a.Metadata["server_audit_events"],
			"parameter_group_in_sync": a.Metadata["parameter_group_in_sync"],
			"audit_log_exported":      strconv.FormatBool(exported),
		}
	},
}

var awsAuroraMySQLNoAuditLogExport = Check{
	ID:          "aws-rds-aurora-mysql-no-audit-log-export",
	Title:       "Aurora MySQL cluster does not publish audit logs to CloudWatch Logs",
	Description: "The cluster records audit events but does not export the audit log to CloudWatch Logs, so the record stays on the instances, rotates away and is lost with them. FSBP RDS.34 (Aurora Serverless v1 is not graded). A cluster with auditing switched off entirely is reported by aws-rds-aurora-mysql-audit-logging-disabled instead.",
	Remediation: "Console: RDS > Databases > the cluster > Modify > Log exports > Audit log. CLI: `aws rds modify-db-cluster --db-cluster-identifier ID --cloudwatch-logs-export-configuration '{\"EnableLogTypes\":[\"audit\"]}' --apply-immediately`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates: func(a asset.Asset) bool {
		exported, ok := logExported(a, "audit")
		return a.Metadata["engine"] == "aurora-mysql" && ok && !exported && !auroraServerlessV1(a) && !auroraMySQLAuditDisabled(a)
	},
}

var awsAuroraPostgreSQLNoLogExport = Check{
	ID:          "aws-rds-aurora-postgresql-no-log-export",
	Title:       "Aurora PostgreSQL cluster does not publish its logs to CloudWatch Logs",
	Description: "The cluster does not export the postgresql log to CloudWatch Logs, so connection failures, errors and slow or suspicious statements are kept only on the instances and lost with them. FSBP RDS.37.",
	Remediation: "Console: RDS > Databases > the cluster > Modify > Log exports > PostgreSQL log. CLI: `aws rds modify-db-cluster --db-cluster-identifier ID --cloudwatch-logs-export-configuration '{\"EnableLogTypes\":[\"postgresql\"]}' --apply-immediately`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_cluster",
	Violates: func(a asset.Asset) bool {
		exported, ok := logExported(a, "postgresql")
		return a.Metadata["engine"] == "aurora-postgresql" && ok && !exported && !auroraServerlessV1(a)
	},
}

var awsRDSProxyTLSNotRequired = Check{
	ID:          "aws-rds-proxy-tls-not-required",
	Title:       "RDS proxy does not require TLS",
	Description: "The proxy accepts unencrypted client connections (RequireTLS false), so credentials and query traffic between applications and the proxy can cross the network in clear. FSBP RDS.43.",
	Remediation: "Console: RDS > Proxies > the proxy > Edit > Require Transport Layer Security. CLI: `aws rds modify-db-proxy --db-proxy-name NAME --require-tls`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_proxy",
	Violates:    func(a asset.Asset) bool { return a.Metadata["require_tls"] == "false" },
}

// auroraMySQLMinSupported and auroraMySQLLTS are FSBP RDS.51's fixed
// parameters (minSupportedEngineVersion 3.08.0; long-term-support releases
// 3.04.0-3.04.3), as published in the Security Hub control reference.
var (
	auroraMySQLMinSupported = [3]int{3, 8, 0}
	auroraMySQLLTS          = []string{"8.0.mysql_aurora.3.04.0", "8.0.mysql_aurora.3.04.1", "8.0.mysql_aurora.3.04.2", "8.0.mysql_aurora.3.04.3"}
)

// auroraMySQLUnsupportedProbes are example versions the predicate grades
// unsupported, so an absent engine_version is never read as evaluated-clean.
var auroraMySQLUnsupportedProbes = []string{"5.7.mysql_aurora.2.11.2", "8.0.mysql_aurora.3.05.2", "5.6.10a"}

// auroraMySQLVersionUnsupported reports an Aurora MySQL engine version below
// the minimum supported release that is not a long-term-support release.
// Aurora MySQL 1 (MySQL 5.6, "5.6.10a" or "5.6.mysql_aurora.1.x") has no
// mysql_aurora 3 part and is long past support. ok is false for a version it
// cannot parse, which is never graded.
func auroraMySQLVersionUnsupported(v string) (unsupported, ok bool) {
	if slices.Contains(auroraMySQLLTS, v) {
		return false, true
	}
	_, rel, found := strings.Cut(v, "mysql_aurora.")
	if !found {
		return strings.HasPrefix(v, "5.6."), strings.HasPrefix(v, "5.6.")
	}
	parts := strings.Split(rel, ".")
	if len(parts) != 3 {
		return false, false
	}
	var got [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return false, false
		}
		got[i] = n
	}
	for i := range got {
		if got[i] != auroraMySQLMinSupported[i] {
			return got[i] < auroraMySQLMinSupported[i], true
		}
	}
	return false, true
}

var awsRDSGlobalClusterUnsupportedVersion = Check{
	ID:          "aws-rds-global-cluster-unsupported-version",
	Title:       "Aurora MySQL global database runs an unsupported engine version",
	Description: "The global database runs an Aurora MySQL release below 3.08.0 that is not a long-term-support release (3.04.0-3.04.3), so it no longer receives security patches under standard support (and accrues Extended Support charges). FSBP RDS.51.",
	Remediation: "Console: RDS > Databases > the global database > Modify > DB engine version >= 8.0.mysql_aurora.3.08.0 (or a 3.04 LTS release). CLI: `aws rds modify-global-cluster --global-cluster-identifier ID --engine-version 8.0.mysql_aurora.3.08.0 --allow-major-version-upgrade` (test the upgrade on a clone first).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_global_cluster",
	Violates: func(a asset.Asset) bool {
		switch a.Metadata["engine"] {
		case "aurora-mysql", "aurora":
		default:
			return false
		}
		unsupported, ok := auroraMySQLVersionUnsupported(a.Metadata["engine_version"])
		return ok && unsupported
	},
	TableProbes: auroraMySQLUnsupportedProbes,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"engine_version": a.Metadata["engine_version"]}
	},
}
