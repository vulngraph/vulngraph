package checks

import (
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// RDS instance and snapshot posture from fields rds:DescribeDBInstances and
// the snapshot listings already return (AWS FSBP RDS.4/6/9/10/13/17/23/25/
// 36/40/42, CIS AWS 3.2.2). Most of these are hardening and operational
// hygiene that teams routinely waive, so they sit at Low/Info: an RDS
// instance's real exposure is graded by aws-rds-publicly-accessible and
// aws-rds-public-subnet-igw.

var awsRDSSnapshotUnencrypted = Check{
	ID:          "aws-rds-snapshot-unencrypted",
	Title:       "RDS snapshot is not encrypted",
	Description: "This manual RDS DB or cluster snapshot (RDS, Aurora, Neptune or DocumentDB) is not encrypted at rest. A snapshot is a complete copy of the database: one shared to another account, or restored by a principal with snapshot access, yields every table in clear, and an unencrypted snapshot can be shared publicly, which an encrypted one cannot.",
	Remediation: "Copy the snapshot with encryption (`aws rds copy-db-snapshot --kms-key-id KEY ...` or `copy-db-cluster-snapshot`), delete the unencrypted copy, and encrypt the source database so new snapshots inherit it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_snapshot",
	Violates:    func(a asset.Asset) bool { return a.Metadata["encrypted"] == "false" },
}

var awsRDSNoEnhancedMonitoring = Check{
	ID:          "aws-rds-no-enhanced-monitoring",
	Title:       "RDS instance has enhanced monitoring disabled",
	Description: "Enhanced monitoring is off (MonitoringInterval=0), so OS-level metrics for the database host — process list, memory, file system — are not collected. Operational visibility only; it does not change who can reach the data.",
	Remediation: "Enable enhanced monitoring: `aws rds modify-db-instance --db-instance-identifier ID --monitoring-interval 60 --monitoring-role-arn ROLE_ARN`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["monitoring_interval"] == "0" },
}

// rdsRequiredLogExports are the CloudWatch log types AWS FSBP requires an
// instance to export, by engine family (RDS.9; RDS.36 PostgreSQL, RDS.40 SQL
// Server, RDS.42 MariaDB). Aurora exports are a cluster setting and are not
// listed: cluster members are skipped.
func rdsRequiredLogExports(engine string) []string {
	switch {
	case engine == "postgres":
		return []string{"postgresql", "upgrade"}
	case engine == "mysql", engine == "mariadb":
		return []string{"audit", "error", "general", "slowquery"}
	case strings.HasPrefix(engine, "oracle"):
		return []string{"alert", "audit", "listener", "trace"}
	case strings.HasPrefix(engine, "sqlserver"):
		return []string{"agent", "error"}
	}
	return nil
}

// rdsMissingLogExports returns the required log types the instance does not
// export, or nil when the export list was not read.
func rdsMissingLogExports(a asset.Asset) []string {
	raw, ok := a.Metadata["log_exports"]
	if !ok {
		return nil
	}
	have := strings.Split(raw, ",")
	var missing []string
	for _, t := range rdsRequiredLogExports(a.Metadata["engine"]) {
		if !slices.Contains(have, t) {
			missing = append(missing, t)
		}
	}
	return missing
}

var awsRDSNoLogExports = Check{
	ID:          "aws-rds-no-log-exports",
	Title:       "RDS instance does not export its database logs to CloudWatch",
	Description: "The instance does not publish the log types AWS FSBP requires for its engine (PostgreSQL: postgresql, upgrade; MySQL/MariaDB: audit, error, general, slowquery; Oracle: alert, audit, listener, trace; SQL Server: agent, error) to CloudWatch Logs. Logs kept only on the instance rotate away and are lost with it, so authentication failures and suspicious queries leave no durable record.",
	Remediation: "Enable the exports: `aws rds modify-db-instance --db-instance-identifier ID --cloudwatch-logs-export-configuration '{\"EnableLogTypes\":[...]}'` (MySQL/MariaDB audit logs also need the audit plugin in the option group).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		return !rdsClusterMember(a) && len(rdsMissingLogExports(a)) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"missing_log_types": strings.Join(rdsMissingLogExports(a), ",")}
	},
}

// rdsIAMAuthEngines are the engines that support IAM database authentication.
var rdsIAMAuthEngines = []string{"mysql", "mariadb", "postgres"}

var awsRDSNoIAMAuth = Check{
	ID:          "aws-rds-no-iam-auth",
	Title:       "RDS instance does not use IAM database authentication",
	Description: "IAM database authentication is disabled, so every connection authenticates with a long-lived database password rather than a short-lived IAM token tied to an auditable principal.",
	Remediation: "Enable IAM authentication: `aws rds modify-db-instance --db-instance-identifier ID --enable-iam-database-authentication`, then grant `rds_iam` to the database users that should use it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["iam_auth_enabled"] == "false" && !rdsClusterMember(a) &&
			slices.Contains(rdsIAMAuthEngines, a.Metadata["engine"])
	},
	// The engine list is a package var the key derivation cannot read.
	TableProbes: rdsIAMAuthEngines,
}

var awsRDSAutoMinorUpgradeDisabled = Check{
	ID:          "aws-rds-auto-minor-upgrade-disabled",
	Title:       "RDS instance does not apply minor engine upgrades automatically",
	Description: "Automatic minor version upgrade is off, so engine security patches released as minor versions are applied only when someone upgrades by hand. Many teams patch manually on purpose; without that process the engine drifts behind its security fixes.",
	Remediation: "Enable it: `aws rds modify-db-instance --db-instance-identifier ID --auto-minor-version-upgrade`, or confirm a manual patching process covers this instance.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["auto_minor_version_upgrade"] == "false" },
}

var awsRDSNoCopyTagsToSnapshot = Check{
	ID:          "aws-rds-no-copy-tags-to-snapshot",
	Title:       "RDS instance does not copy tags to snapshots",
	Description: "CopyTagsToSnapshot is off, so snapshots lose the instance's ownership and classification tags — and with them any tag-based access control or retention policy.",
	Remediation: "`aws rds modify-db-instance --db-instance-identifier ID --copy-tags-to-snapshot`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["copy_tags_to_snapshot"] == "false" && !rdsClusterMember(a)
	},
}

// rdsEngineDefaultPort is the listener port each engine family ships with.
func rdsEngineDefaultPort(engine string) string {
	switch {
	case engine == "mysql", engine == "mariadb", engine == "aurora", engine == "aurora-mysql":
		return "3306"
	case engine == "postgres", engine == "aurora-postgresql":
		return "5432"
	case strings.HasPrefix(engine, "oracle"):
		return "1521"
	case strings.HasPrefix(engine, "sqlserver"):
		return "1433"
	}
	return ""
}

var awsRDSEngineDefaultPort = Check{
	ID:          "aws-rds-engine-default-port",
	Title:       "Private RDS instance listens on its engine's default port",
	Description: "The instance uses the well-known default port for its engine. On a private instance this only removes a speed bump for an attacker already inside the network, which is why it is informational; a publicly accessible instance on a default port is graded by aws-rds-publicly-accessible instead.",
	Remediation: "Use a non-default port when the instance is next rebuilt or modified (`--port`), and keep security groups scoped to known clients.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		def := rdsEngineDefaultPort(a.Metadata["engine"])
		// Cluster members are excluded as FSBP RDS.23 does: the port is the
		// cluster endpoint's, set once for every member.
		return a.Metadata["publicly_accessible"] == "false" && def != "" && a.Metadata["port"] == def && !rdsClusterMember(a)
	},
}

// rdsDefaultMasterUsernames are the engine-default administrator names that
// credential-stuffing tools try first.
var rdsDefaultMasterUsernames = []string{"admin", "postgres", "root", "sa"}

var awsRDSDefaultMasterUsername = Check{
	ID:          "aws-rds-default-master-username",
	Title:       "RDS instance uses a default administrator username",
	Description: "The master user is named after an engine default (admin, postgres, root or sa). Knowing the administrator's name halves a password-guessing attack; a custom name removes that head start.",
	Remediation: "The master username cannot be changed in place: create a new administrative user with a custom name, move automation to it, and restrict or rotate the default account; use a custom name for new instances.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		return slices.Contains(rdsDefaultMasterUsernames, strings.ToLower(a.Metadata["master_username"])) && !rdsClusterMember(a)
	},
	TableProbes: rdsDefaultMasterUsernames,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"master_username": a.Metadata["master_username"]}
	},
}

func awsDatabaseChecks() []Check {
	return []Check{
		awsRDSSnapshotUnencrypted,
		awsRDSNoEnhancedMonitoring,
		awsRDSNoLogExports,
		awsRDSNoIAMAuth,
		awsRDSAutoMinorUpgradeDisabled,
		awsRDSNoCopyTagsToSnapshot,
		awsRDSEngineDefaultPort,
		awsRDSDefaultMasterUsername,
	}
}
