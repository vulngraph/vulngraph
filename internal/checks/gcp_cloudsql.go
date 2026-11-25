package checks

// gcp_cloudsql.go — CIS GCP Foundation section 6: Cloud SQL database flags and
// authorized networks, read from the instances.list response the collector
// already fetches (internal/collect/gcp/cloudsql.go).
//
// Known-ness: the collector stamps db_flag_<name> for every CIS-graded flag of
// the instance's engine once Settings was read — "" for a flag left at its
// default — and omits them all otherwise. Each check below therefore decides
// on a PRESENT key only, and states the engine default it assumes for "".

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// cloudSQLFlag returns the instance's value for one CIS-graded database flag
// (lower-cased, "" = engine default) and whether the flag is graded here at
// all: the instance runs engine and its flag list was read.
func cloudSQLFlag(a asset.Asset, engine, key string) (string, bool) {
	if !strings.HasPrefix(strings.ToUpper(a.Metadata["version"]), engine) {
		return "", false
	}
	v, ok := a.Metadata[key]
	return v, ok
}

// flagEvidence names the flag and its observed value for a responder.
func flagEvidence(flag, key string) func(asset.Asset) map[string]string {
	return func(a asset.Asset) map[string]string {
		v := a.Metadata[key]
		if v == "" {
			v = "(not set)"
		}
		return map[string]string{"database_flag": flag, "value": v, "version": a.Metadata["version"]}
	}
}

// ── MySQL (CIS 6.1) ──────────────────────────────────────────────────────────

var gcpCloudSQLMySQLSkipShowDatabase = Check{
	ID:          "gcp-cloudsql-mysql-skip-show-database",
	Title:       "Cloud SQL MySQL instance lets any user list every database",
	Description: "The skip_show_database flag is not on (MySQL defaults it off), so any database user can run SHOW DATABASES and enumerate every schema on the instance, including ones it cannot read.",
	Remediation: "Set the flag: `gcloud sql instances patch INSTANCE --database-flags=skip_show_database=on` (include every flag already set — the command replaces the list).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "MYSQL", "db_flag_skip_show_database")
		return ok && v != "on"
	},
	EvidenceFor: flagEvidence("skip_show_database", "db_flag_skip_show_database"),
}

var gcpCloudSQLMySQLLocalInfile = Check{
	ID:          "gcp-cloudsql-mysql-local-infile",
	Title:       "Cloud SQL MySQL instance allows LOAD DATA LOCAL INFILE",
	Description: "The local_infile flag is on, so a client can make the server read files from the client host through LOAD DATA LOCAL. A malicious or compromised server, or SQL injection in an application, can use it to read arbitrary files the client can access. An unset flag is read as the engine default: on for MySQL 5.x, off from 8.0.",
	Remediation: "Turn the flag off: `gcloud sql instances patch INSTANCE --database-flags=local_infile=off` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "MYSQL", "db_flag_local_infile")
		return ok && (v == "on" || (v == "" && strings.HasPrefix(strings.ToUpper(a.Metadata["version"]), "MYSQL_5")))
	},
	EvidenceFor: flagEvidence("local_infile", "db_flag_local_infile"),
}

// ── PostgreSQL (CIS 6.2) ─────────────────────────────────────────────────────

var gcpCloudSQLPostgresLogErrorVerbosity = Check{
	ID:          "gcp-cloudsql-postgres-log-error-verbosity",
	Title:       "Cloud SQL PostgreSQL instance logs errors verbosely",
	Description: "log_error_verbosity is set to verbose, which writes source file, function and line details into every logged message. The extra detail adds log volume and can expose internals; CIS recommends default or terse.",
	Remediation: "Set the flag to default: `gcloud sql instances patch INSTANCE --database-flags=log_error_verbosity=default` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_log_error_verbosity")
		return ok && v == "verbose"
	},
	EvidenceFor: flagEvidence("log_error_verbosity", "db_flag_log_error_verbosity"),
}

var gcpCloudSQLPostgresLogConnections = Check{
	ID:          "gcp-cloudsql-postgres-log-connections",
	Title:       "Cloud SQL PostgreSQL instance does not log connections",
	Description: "log_connections is not on (the default is off), so successful connection attempts are not logged and an unexpected client or credential-stuffing source leaves no trace in the database log.",
	Remediation: "Set the flag: `gcloud sql instances patch INSTANCE --database-flags=log_connections=on` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_log_connections")
		return ok && v != "on"
	},
	EvidenceFor: flagEvidence("log_connections", "db_flag_log_connections"),
}

var gcpCloudSQLPostgresLogDisconnections = Check{
	ID:          "gcp-cloudsql-postgres-log-disconnections",
	Title:       "Cloud SQL PostgreSQL instance does not log disconnections",
	Description: "log_disconnections is not on (the default is off), so session ends and durations are not logged, which leaves gaps when reconstructing what a session did.",
	Remediation: "Set the flag: `gcloud sql instances patch INSTANCE --database-flags=log_disconnections=on` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_log_disconnections")
		return ok && v != "on"
	},
	EvidenceFor: flagEvidence("log_disconnections", "db_flag_log_disconnections"),
}

var gcpCloudSQLPostgresLogStatement = Check{
	ID:          "gcp-cloudsql-postgres-log-statement",
	Title:       "Cloud SQL PostgreSQL instance does not log DDL statements",
	Description: "log_statement is unset or none (the default is none), so schema changes — dropped tables, altered roles, new functions — are not recorded in the database log. CIS recommends at least ddl.",
	Remediation: "Set the flag: `gcloud sql instances patch INSTANCE --database-flags=log_statement=ddl` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_log_statement")
		return ok && (v == "" || v == "none")
	},
	EvidenceFor: flagEvidence("log_statement", "db_flag_log_statement"),
}

var gcpCloudSQLPostgresLogMinMessages = Check{
	ID:          "gcp-cloudsql-postgres-log-min-messages",
	Title:       "Cloud SQL PostgreSQL instance logs below warning level",
	Description: "log_min_messages is set below warning (a debug, info or notice level), which floods the log with routine messages and buries the warnings and errors an investigation needs. An unset flag is the default, warning.",
	Remediation: "Set the flag to warning or stricter: `gcloud sql instances patch INSTANCE --database-flags=log_min_messages=warning` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_log_min_messages")
		return ok && pgLevelBelowWarning(v)
	},
	EvidenceFor: flagEvidence("log_min_messages", "db_flag_log_min_messages"),
}

var gcpCloudSQLPostgresLogMinErrorStatement = Check{
	ID:          "gcp-cloudsql-postgres-log-min-error-statement",
	Title:       "Cloud SQL PostgreSQL instance logs statements below error level",
	Description: "log_min_error_statement is set below error (a debug, info, notice or warning level), so the SQL text of statements that merely warn is written to the log, adding volume and potentially sensitive literals. An unset flag is the default, error.",
	Remediation: "Set the flag to error or stricter: `gcloud sql instances patch INSTANCE --database-flags=log_min_error_statement=error` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_log_min_error_statement")
		return ok && (v == "warning" || pgLevelBelowWarning(v))
	},
	EvidenceFor: flagEvidence("log_min_error_statement", "db_flag_log_min_error_statement"),
}

// pgLevelBelowWarning reports whether a PostgreSQL log level is less severe
// than warning.
func pgLevelBelowWarning(level string) bool {
	switch level {
	case "debug5", "debug4", "debug3", "debug2", "debug1", "debug", "info", "notice":
		return true
	}
	return false
}

var gcpCloudSQLPostgresLogMinDuration = Check{
	ID:          "gcp-cloudsql-postgres-log-min-duration",
	Title:       "Cloud SQL PostgreSQL instance logs statement text by duration",
	Description: "log_min_duration_statement is set to a value other than -1, so the full text of every statement slower than the threshold — including literals such as passwords or personal data in queries — is written to the log. An unset flag is the default, -1 (disabled).",
	Remediation: "Disable it: `gcloud sql instances patch INSTANCE --database-flags=log_min_duration_statement=-1` (include every flag already set), and use Query Insights for slow-query analysis instead.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_log_min_duration_statement")
		return ok && v != "" && v != "-1"
	},
	EvidenceFor: flagEvidence("log_min_duration_statement", "db_flag_log_min_duration_statement"),
}

var gcpCloudSQLPostgresPgAuditDisabled = Check{
	ID:          "gcp-cloudsql-postgres-pgaudit-disabled",
	Title:       "Cloud SQL PostgreSQL instance does not have pgAudit enabled",
	Description: "cloudsql.enable_pgaudit is not on (the default is off), so session and object audit logging through the pgAudit extension is unavailable and data access inside the database is not auditable.",
	Remediation: "Set `gcloud sql instances patch INSTANCE --database-flags=cloudsql.enable_pgaudit=on` (include every flag already set), then `CREATE EXTENSION pgaudit;` and configure pgaudit.log.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_cloudsql_enable_pgaudit")
		return ok && v != "on"
	},
	EvidenceFor: flagEvidence("cloudsql.enable_pgaudit", "db_flag_cloudsql_enable_pgaudit"),
}

// ── SQL Server (CIS 6.3) ─────────────────────────────────────────────────────

var gcpCloudSQLSQLServerExternalScripts = Check{
	ID:          "gcp-cloudsql-sqlserver-external-scripts",
	Title:       "Cloud SQL SQL Server instance allows external scripts",
	Description: "The external scripts enabled flag is on, so sp_execute_external_script can run R or Python code outside the SQL Server security boundary — code execution on the database host for anyone allowed to call it. An unset flag is the default, off.",
	Remediation: "Turn the flag off: `gcloud sql instances patch INSTANCE --database-flags=\"external scripts enabled=off\"` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "SQLSERVER", "db_flag_external_scripts_enabled")
		return ok && v == "on"
	},
	EvidenceFor: flagEvidence("external scripts enabled", "db_flag_external_scripts_enabled"),
}

var gcpCloudSQLSQLServerCrossDBChaining = Check{
	ID:          "gcp-cloudsql-sqlserver-cross-db-chaining",
	Title:       "Cloud SQL SQL Server instance enables cross-database ownership chaining",
	Description: "The cross db ownership chaining flag is on, so ownership chains span databases: a user who owns objects in one database can reach objects in another without being granted access there. An unset flag is the default, off.",
	Remediation: "Turn the flag off: `gcloud sql instances patch INSTANCE --database-flags=\"cross db ownership chaining=off\"` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "SQLSERVER", "db_flag_cross_db_ownership_chaining")
		return ok && v == "on"
	},
	EvidenceFor: flagEvidence("cross db ownership chaining", "db_flag_cross_db_ownership_chaining"),
}

var gcpCloudSQLSQLServerUserConnections = Check{
	ID:          "gcp-cloudsql-sqlserver-user-connections",
	Title:       "Cloud SQL SQL Server instance caps user connections",
	Description: "The user connections flag is set to a non-zero limit, so once that many sessions are open new connections are refused — an availability risk an attacker or a connection leak can trigger. The default, 0, lets SQL Server manage the limit.",
	Remediation: "Reset the flag to 0 (or remove it) with `gcloud sql instances patch INSTANCE --database-flags=...` listing the remaining flags.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "SQLSERVER", "db_flag_user_connections")
		return ok && v != "" && v != "0"
	},
	EvidenceFor: flagEvidence("user connections", "db_flag_user_connections"),
}

var gcpCloudSQLSQLServerUserOptions = Check{
	ID:          "gcp-cloudsql-sqlserver-user-options",
	Title:       "Cloud SQL SQL Server instance overrides default user options",
	Description: "The user options flag is set, overriding session defaults (ANSI settings, transaction behaviour) for every user. CIS recommends leaving it unset so sessions behave predictably.",
	Remediation: "Remove the flag with `gcloud sql instances patch INSTANCE --database-flags=...` listing only the remaining flags.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "SQLSERVER", "db_flag_user_options")
		return ok && v != ""
	},
	EvidenceFor: flagEvidence("user options", "db_flag_user_options"),
}

var gcpCloudSQLSQLServerRemoteAccess = Check{
	ID:          "gcp-cloudsql-sqlserver-remote-access",
	Title:       "Cloud SQL SQL Server instance allows remote access",
	Description: "The remote access flag is not off (SQL Server defaults it on), so stored procedures can be run from and against remote servers — a path for lateral movement and denial of service between linked servers.",
	Remediation: "Turn the flag off: `gcloud sql instances patch INSTANCE --database-flags=\"remote access=off\"` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "SQLSERVER", "db_flag_remote_access")
		return ok && v != "off"
	},
	EvidenceFor: flagEvidence("remote access", "db_flag_remote_access"),
}

var gcpCloudSQLSQLServerTrace3625 = Check{
	ID:          "gcp-cloudsql-sqlserver-trace-3625",
	Title:       "Cloud SQL SQL Server instance does not mask error details",
	Description: "Trace flag 3625 is not on (the default is off), so error messages returned to users who are not sysadmin can include parameters and object details that help an attacker probe the schema.",
	Remediation: "Set the flag: `gcloud sql instances patch INSTANCE --database-flags=3625=on` (include every flag already set).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "SQLSERVER", "db_flag_3625")
		return ok && v != "on"
	},
	EvidenceFor: flagEvidence("3625", "db_flag_3625"),
}

var gcpCloudSQLSQLServerContainedDBAuth = Check{
	ID:          "gcp-cloudsql-sqlserver-contained-db-auth",
	Title:       "Cloud SQL SQL Server instance allows contained database authentication",
	Description: "The contained database authentication flag is on, so contained databases can hold their own users, which authenticate without a server login and bypass server-level login policy and auditing. An unset flag is the default, off.",
	Remediation: "Turn the flag off: `gcloud sql instances patch INSTANCE --database-flags=\"contained database authentication=off\"` (include every flag already set), after migrating contained users to server logins.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "SQLSERVER", "db_flag_contained_database_authentication")
		return ok && v == "on"
	},
	EvidenceFor: flagEvidence("contained database authentication", "db_flag_contained_database_authentication"),
}

// ── Engine-wide (CIS 6.5, 6.6) ───────────────────────────────────────────────

var gcpCloudSQLIAMAuthDisabled = Check{
	ID:          "gcp-cloudsql-iam-auth-disabled",
	Title:       "Cloud SQL instance does not allow IAM database authentication",
	Description: "The IAM database authentication flag (cloudsql.iam_authentication on PostgreSQL, cloudsql_iam_authentication on MySQL) is not on, so every database user authenticates with a static password rather than a short-lived IAM credential that is revoked with the identity. The default is off.",
	Remediation: "Set the flag (`gcloud sql instances patch INSTANCE --database-flags=cloudsql.iam_authentication=on` for PostgreSQL, `cloudsql_iam_authentication=on` for MySQL, including every flag already set) and move users to IAM database users.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := cloudSQLFlag(a, "POSTGRES", "db_flag_cloudsql_iam_authentication")
		if !ok {
			v, ok = cloudSQLFlag(a, "MYSQL", "db_flag_cloudsql_iam_authentication")
		}
		return ok && v != "on"
	},
	EvidenceFor: flagEvidence("cloudsql.iam_authentication", "db_flag_cloudsql_iam_authentication"),
}

// gcpCloudSQLOpenAuthorizedNetwork is the refinement of gcp-cloudsql-public-ip
// that matters: a public IP is reachability only once an authorized network
// admits the client, and 0.0.0.0/0 admits everyone.
var gcpCloudSQLOpenAuthorizedNetwork = Check{
	ID:          "gcp-cloudsql-open-authorized-network",
	Title:       "Cloud SQL instance accepts connections from any IP address",
	Description: "The instance has a public IP and its authorized networks include 0.0.0.0/0 (or ::/0), so any host on the internet can open a connection to the database port. Only the database credentials stand between the internet and the data, and the endpoint is exposed to brute force and to any unpatched protocol flaw. This replaces gcp-cloudsql-public-ip for the instance.",
	Remediation: "Remove the 0.0.0.0/0 entry from the instance's authorized networks (`gcloud sql instances patch INSTANCE --authorized-networks=CIDR,...`), connect through the Cloud SQL Auth Proxy or connectors, or disable the public IP in favour of private IP / Private Service Connect.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates:    cloudSQLOpenAuthorizedNetwork,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"authorized_networks": a.Metadata["authorized_networks"], "public_ip": a.PublicIP}
	},
}

// cloudSQLOpenAuthorizedNetwork is shared with gcp-cloudsql-public-ip so that
// check can step aside for this one.
func cloudSQLOpenAuthorizedNetwork(a asset.Asset) bool {
	return a.Metadata["public"] == "true" && a.Metadata["authorized_networks_world"] == "true"
}

// cloudSQLNoSSL is gcp-cloudsql-no-ssl's predicate. ipConfiguration.sslMode
// supersedes the legacy requireSsl flag: an instance enforcing TLS through
// ENCRYPTED_ONLY reports requireSsl=false, so reading requireSsl alone would
// be a false positive. requireSsl decides only when no mode is set.
func cloudSQLNoSSL(a asset.Asset) bool {
	switch a.Metadata["ssl_mode"] {
	case "ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED":
		return false
	case "ALLOW_UNENCRYPTED_AND_ENCRYPTED":
		return true
	}
	return a.Metadata["require_ssl"] == "false"
}
