package gcp

import (
	"strings"
)

// cisDatabaseFlags are the Cloud SQL database flags the CIS GCP Foundation
// benchmark grades, per engine (section 6). Only these are stamped: the flag
// list can carry arbitrary tuning values no check reads.
var cisDatabaseFlags = map[string][]string{
	"MYSQL": {"skip_show_database", "local_infile", "cloudsql_iam_authentication"},
	"POSTGRES": {
		"log_error_verbosity", "log_connections", "log_disconnections", "log_statement",
		"log_min_messages", "log_min_error_statement", "log_min_duration_statement",
		"cloudsql.enable_pgaudit", "cloudsql.iam_authentication",
	},
	"SQLSERVER": {
		"external scripts enabled", "cross db ownership chaining", "user connections",
		"user options", "remote access", "3625", "contained database authentication",
	},
}

// cloudSQLEngine maps a databaseVersion ("POSTGRES_15", "MYSQL_8_0",
// "SQLSERVER_2019_STANDARD") to its cisDatabaseFlags key, "" when unrecognised.
func cloudSQLEngine(version string) string {
	v := strings.ToUpper(version)
	for engine := range cisDatabaseFlags {
		if strings.HasPrefix(v, engine) {
			return engine
		}
	}
	return ""
}

// dbFlagMetadata stamps every CIS-graded flag of the instance's engine as
// db_flag_<name>. A flag the instance does not set is written as "": the flag
// list was read and the flag is at its engine default, which is distinct from
// the key being missing (Settings never came back). Each check knows its
// flag's default, so the collector does not guess it.
func dbFlagMetadata(version string, flags map[string]string) map[string]string {
	out := map[string]string{}
	for _, name := range cisDatabaseFlags[cloudSQLEngine(version)] {
		out[dbFlagKey(name)] = flags[name]
	}
	return out
}

// dbFlagKey normalises a flag name to a metadata key: "remote access" and
// "cloudsql.enable_pgaudit" become db_flag_remote_access and
// db_flag_cloudsql_enable_pgaudit, so MySQL's cloudsql_iam_authentication and
// Postgres's cloudsql.iam_authentication share one key.
func dbFlagKey(name string) string {
	var b strings.Builder
	b.WriteString("db_flag_")
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// worldAuthorizedNetwork reports whether an authorized-networks list admits
// every IPv4 or IPv6 address.
func worldAuthorizedNetwork(cidrs []string) bool {
	return containsCIDR(cidrs, internetCIDR) || containsCIDR(cidrs, internetCIDRv6)
}
