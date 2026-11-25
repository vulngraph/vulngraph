package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAwsRDSClusterChecksNeverFireOnAbsentData(t *testing.T) {
	aurMySQL := func(kv ...string) map[string]string {
		m := map[string]string{"engine": "aurora-mysql"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "aws-rds-cluster-not-encrypted", check: awsRDSClusterNotEncrypted,
			violating: map[string]string{"storage_encrypted": "false"},
			compliant: map[string]string{"storage_encrypted": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-cluster-no-deletion-protection", check: awsRDSClusterNoDeletionProtection,
			violating: map[string]string{"deletion_protection": "false"},
			compliant: map[string]string{"deletion_protection": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-cluster-no-iam-auth", check: awsRDSClusterNoIAMAuth,
			violating: map[string]string{"engine": "aurora-postgresql", "iam_auth_enabled": "false"},
			compliant: map[string]string{"engine": "aurora-postgresql", "iam_auth_enabled": "true"},
			unknown:   map[string]string{"engine": "aurora-postgresql"},
		},
		{
			name: "aws-rds-cluster-no-backtracking", check: awsRDSClusterNoBacktracking,
			violating: aurMySQL("backtrack_window", "0"),
			compliant: aurMySQL("backtrack_window", "86400"),
			unknown:   aurMySQL(),
		},
		{
			name: "aws-rds-cluster-single-az", check: awsRDSClusterSingleAZ,
			violating: map[string]string{"multi_az": "false"},
			compliant: map[string]string{"multi_az": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-cluster-no-copy-tags-to-snapshot", check: awsRDSClusterNoCopyTagsToSnapshot,
			violating: map[string]string{"copy_tags_to_snapshot": "false"},
			compliant: map[string]string{"copy_tags_to_snapshot": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-cluster-default-master-username", check: awsRDSClusterDefaultMasterUsername,
			violating: map[string]string{"master_username": "Admin"},
			compliant: map[string]string{"master_username": "orders_owner"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-cluster-short-backup-retention", check: awsRDSClusterShortBackupRetention,
			violating: map[string]string{"backup_retention": "1"},
			compliant: map[string]string{"backup_retention": "7"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-cluster-auto-minor-upgrade-disabled", check: awsRDSClusterAutoMinorUpgradeDisabled,
			violating: map[string]string{"auto_minor_version_upgrade": "false"},
			compliant: map[string]string{"auto_minor_version_upgrade": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-aurora-mysql-no-audit-log-export", check: awsAuroraMySQLNoAuditLogExport,
			violating: aurMySQL("log_exports", "error,slowquery", "server_audit_logging", "1", "server_audit_events", "CONNECT", "parameter_group_in_sync", "true"),
			compliant: aurMySQL("log_exports", "audit,error", "server_audit_logging", "1", "server_audit_events", "CONNECT", "parameter_group_in_sync", "true"),
			unknown:   aurMySQL("server_audit_logging", "1", "server_audit_events", "CONNECT"),
		},
		{
			name: "aws-rds-aurora-postgresql-no-log-export", check: awsAuroraPostgreSQLNoLogExport,
			violating: map[string]string{"engine": "aurora-postgresql", "log_exports": ""},
			compliant: map[string]string{"engine": "aurora-postgresql", "log_exports": "postgresql"},
			unknown:   map[string]string{"engine": "aurora-postgresql"},
		},
		{
			name: "aws-rds-aurora-mysql-audit-logging-disabled", check: awsAuroraMySQLAuditLoggingDisabled,
			violating: aurMySQL("server_audit_logging", "0", "server_audit_events", "", "parameter_group_in_sync", "true"),
			compliant: aurMySQL("server_audit_logging", "1", "server_audit_events", "CONNECT,QUERY_DDL", "parameter_group_in_sync", "true"),
			unknown:   aurMySQL("parameter_group_in_sync", "true"),
		},
		{
			name: "aws-rds-proxy-tls-not-required", check: awsRDSProxyTLSNotRequired,
			violating: map[string]string{"require_tls": "false"},
			compliant: map[string]string{"require_tls": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-global-cluster-unsupported-version", check: awsRDSGlobalClusterUnsupportedVersion,
			violating: map[string]string{"engine": "aurora-mysql", "engine_version": "5.7.mysql_aurora.2.11.2"},
			compliant: map[string]string{"engine": "aurora-mysql", "engine_version": "8.0.mysql_aurora.3.08.0"},
			unknown:   map[string]string{"engine": "aurora-mysql"},
		},
		{
			name: "aws-docdb-cluster-not-encrypted", check: awsDocDBClusterNotEncrypted,
			violating: map[string]string{"storage_encrypted": "false"},
			compliant: map[string]string{"storage_encrypted": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-docdb-cluster-short-backup-retention", check: awsDocDBClusterShortBackupRetention,
			violating: map[string]string{"backup_retention": "1"},
			compliant: map[string]string{"backup_retention": "35"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-docdb-cluster-no-audit-log-export", check: awsDocDBClusterNoAuditLogExport,
			violating: map[string]string{"log_exports": "profiler"},
			compliant: map[string]string{"log_exports": "audit,profiler"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-docdb-cluster-no-deletion-protection", check: awsDocDBClusterNoDeletionProtection,
			violating: map[string]string{"deletion_protection": "false"},
			compliant: map[string]string{"deletion_protection": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-docdb-cluster-tls-not-required", check: awsDocDBClusterTLSNotRequired,
			violating: map[string]string{"tls": "enabled", "parameter_group_in_sync": "true"},
			compliant: map[string]string{"tls": "tls1.2+", "parameter_group_in_sync": "true"},
			unknown:   map[string]string{"parameter_group_in_sync": "true"},
		},
		{
			name: "aws-neptune-cluster-not-encrypted", check: awsNeptuneClusterNotEncrypted,
			violating: map[string]string{"storage_encrypted": "false"},
			compliant: map[string]string{"storage_encrypted": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-neptune-cluster-no-audit-log-export", check: awsNeptuneClusterNoAuditLogExport,
			violating: map[string]string{"log_exports": ""},
			compliant: map[string]string{"log_exports": "audit"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-neptune-cluster-no-deletion-protection", check: awsNeptuneClusterNoDeletionProtection,
			violating: map[string]string{"deletion_protection": "false"},
			compliant: map[string]string{"deletion_protection": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-neptune-cluster-short-backup-retention", check: awsNeptuneClusterShortBackupRetention,
			violating: map[string]string{"backup_retention": "6"},
			compliant: map[string]string{"backup_retention": "7"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-neptune-cluster-no-iam-auth", check: awsNeptuneClusterNoIAMAuth,
			violating: map[string]string{"iam_auth_enabled": "false"},
			compliant: map[string]string{"iam_auth_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-neptune-cluster-no-copy-tags-to-snapshot", check: awsNeptuneClusterNoCopyTagsToSnapshot,
			violating: map[string]string{"copy_tags_to_snapshot": "false"},
			compliant: map[string]string{"copy_tags_to_snapshot": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-cluster-events-not-subscribed", check: awsRDSClusterEventsNotSubscribed,
			violating: map[string]string{"has_event_subscriptions": "true", "has_clusters": "true", "cluster_events_covered": "false"},
			compliant: map[string]string{"has_event_subscriptions": "true", "has_clusters": "true", "cluster_events_covered": "true"},
			unknown:   map[string]string{"has_event_subscriptions": "true", "has_clusters": "true"},
		},
		{
			name: "aws-rds-instance-events-not-subscribed", check: awsRDSInstanceEventsNotSubscribed,
			violating: map[string]string{"has_event_subscriptions": "true", "has_instances": "true", "instance_events_covered": "false"},
			compliant: map[string]string{"has_event_subscriptions": "true", "has_instances": "true", "instance_events_covered": "true"},
			unknown:   map[string]string{"has_event_subscriptions": "true", "has_instances": "true"},
		},
		{
			name: "aws-rds-parameter-group-events-not-subscribed", check: awsRDSParameterGroupEventsNotSubscribed,
			violating: map[string]string{"has_event_subscriptions": "true", "has_clusters": "true", "parameter_group_events_covered": "false"},
			compliant: map[string]string{"has_event_subscriptions": "true", "has_clusters": "true", "parameter_group_events_covered": "true"},
			unknown:   map[string]string{"has_event_subscriptions": "true", "has_clusters": "true"},
		},
		{
			name: "aws-rds-security-group-events-not-subscribed", check: awsRDSSecurityGroupEventsNotSubscribed,
			violating: map[string]string{"has_event_subscriptions": "true", "has_instances": "true", "security_group_events_covered": "false"},
			compliant: map[string]string{"has_event_subscriptions": "true", "has_instances": "true", "security_group_events_covered": "true"},
			unknown:   map[string]string{"has_event_subscriptions": "true", "has_instances": "true"},
		},
		{
			name: "aws-rds-sqlserver-tls-not-enforced", check: awsRDSSQLServerTLSNotEnforced,
			violating: map[string]string{"engine": "sqlserver-se", "force_ssl": "0"},
			compliant: map[string]string{"engine": "sqlserver-se", "force_ssl": "1"},
			unknown:   map[string]string{"engine": "sqlserver-se"},
		},
		{
			name: "aws-rds-mariadb-tls-not-enforced", check: awsRDSMariaDBTLSNotEnforced,
			violating: map[string]string{"engine": "mariadb", "require_secure_transport": "OFF", "parameter_group_in_sync": "true"},
			compliant: map[string]string{"engine": "mariadb", "require_secure_transport": "ON", "parameter_group_in_sync": "true"},
			unknown:   map[string]string{"engine": "mariadb", "parameter_group_in_sync": "true"},
		},
	})
}

func clusterAsset(typ string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "arn:aws:rds:eu-west-1:1:cluster:x", Type: typ, Provider: asset.ProviderAWS, Metadata: md}
}

// A default Aurora MySQL cluster has neither Advanced Auditing nor an audit
// export: one finding (auditing off), not two.
func TestAuroraMySQLAuditFindingsFireOnce(t *testing.T) {
	off := map[string]string{"engine": "aurora-mysql", "log_exports": "", "server_audit_logging": "0", "server_audit_events": "", "parameter_group_in_sync": "true"}
	require.True(t, awsAuroraMySQLAuditLoggingDisabled.Violates(clusterAsset("rds_cluster", off)))
	require.False(t, awsAuroraMySQLNoAuditLogExport.Violates(clusterAsset("rds_cluster", off)))
	require.Equal(t, "false", awsAuroraMySQLAuditLoggingDisabled.EvidenceFor(clusterAsset("rds_cluster", off))["audit_log_exported"])

	pending := map[string]string{"engine": "aurora-mysql", "log_exports": "audit", "server_audit_logging": "1", "server_audit_events": "CONNECT", "parameter_group_in_sync": "false"}
	require.True(t, awsAuroraMySQLAuditLoggingDisabled.Violates(clusterAsset("rds_cluster", pending)), "a group not applied to every member is not in effect")

	unreadGroup := map[string]string{"engine": "aurora-mysql", "log_exports": ""}
	require.False(t, awsAuroraMySQLAuditLoggingDisabled.Violates(clusterAsset("rds_cluster", unreadGroup)))
	require.True(t, awsAuroraMySQLNoAuditLogExport.Violates(clusterAsset("rds_cluster", unreadGroup)),
		"an unread parameter group does not hide the observed export gap")
}

func TestAuroraClusterChecksSkipServerlessV1AndGlobalBacktrack(t *testing.T) {
	sv1 := map[string]string{"engine": "aurora-mysql", "engine_mode": "serverless", "log_exports": "", "backtrack_window": "0", "iam_auth_enabled": "false"}
	for _, c := range []Check{awsAuroraMySQLNoAuditLogExport, awsRDSClusterNoBacktracking, awsRDSClusterNoIAMAuth} {
		require.False(t, c.Violates(clusterAsset("rds_cluster", sv1)), c.ID)
	}
	global := map[string]string{"engine": "aurora-mysql", "backtrack_window": "0", "global_cluster_id": "orders-global"}
	require.False(t, awsRDSClusterNoBacktracking.Violates(clusterAsset("rds_cluster", global)))
	pg := map[string]string{"engine": "aurora-postgresql", "backtrack_window": "0"}
	require.False(t, awsRDSClusterNoBacktracking.Violates(clusterAsset("rds_cluster", pg)), "backtracking is Aurora MySQL only")
	// IAM auth applies to Multi-AZ DB clusters too, and not to an unknown engine.
	require.True(t, awsRDSClusterNoIAMAuth.Violates(clusterAsset("rds_cluster", map[string]string{"engine": "mysql", "iam_auth_enabled": "false"})))
}

func TestRDSClusterSingleAZSkipsServerlessV1AndMemberless(t *testing.T) {
	cluster := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "rds_cluster", Provider: asset.ProviderAWS, Metadata: md}
	}
	require.True(t, awsRDSClusterSingleAZ.Violates(cluster(map[string]string{"multi_az": "false", "engine_mode": "provisioned", "member_count": "1"})))
	require.False(t, awsRDSClusterSingleAZ.Violates(cluster(map[string]string{"multi_az": "false", "engine_mode": "serverless", "member_count": "0"})),
		"Aurora Serverless v1 has no instances to place")
	require.False(t, awsRDSClusterSingleAZ.Violates(cluster(map[string]string{"multi_az": "false", "engine_mode": "provisioned", "member_count": "0", "global_cluster_id": "g"})),
		"a headless global-database secondary has no instance in any zone")
}

func TestAuroraMySQLVersionUnsupported(t *testing.T) {
	tests := []struct {
		v                    string
		unsupported, decided bool
	}{
		{"8.0.mysql_aurora.3.08.0", false, true},
		{"8.0.mysql_aurora.3.10.1", false, true},
		{"8.0.mysql_aurora.3.07.1", true, true},
		{"8.0.mysql_aurora.3.04.2", false, true}, // LTS
		{"8.0.mysql_aurora.3.04.4", true, true},  // not an LTS release, below 3.08
		{"5.7.mysql_aurora.2.12.3", true, true},
		{"5.6.10a", true, true},
		{"5.6.mysql_aurora.1.23.4", true, true},
		{"", false, false},
		{"8.0.mysql_aurora.3.x", false, false},
	}
	for _, tt := range tests {
		got, ok := auroraMySQLVersionUnsupported(tt.v)
		require.Equal(t, tt.decided, ok, tt.v)
		require.Equal(t, tt.unsupported, got, tt.v)
	}
	pg := asset.Asset{Type: "rds_global_cluster", Metadata: map[string]string{"engine": "aurora-postgresql", "engine_version": "13.4"}}
	require.False(t, awsRDSGlobalClusterUnsupportedVersion.Violates(pg), "RDS.51 grades Aurora MySQL only")
	require.False(t, registered(t, "aws-rds-global-cluster-unsupported-version").Evaluable(
		asset.Asset{Type: "rds_global_cluster", Provider: asset.ProviderAWS, Metadata: map[string]string{"engine": "aurora-mysql"}}),
		"an unread version must not close an open finding")
}

// Cluster members take their encryption from the cluster: reported once, there.
func TestRDSNotEncryptedHandsMembersToTheirCluster(t *testing.T) {
	standalone := rdsAsset(map[string]string{"engine": "postgres", "db_cluster_id": "", "storage_encrypted": "false"})
	member := rdsAsset(map[string]string{"engine": "aurora-postgresql", "db_cluster_id": "orders", "storage_encrypted": "false"})
	docdb := rdsAsset(map[string]string{"engine": "docdb", "db_cluster_id": "docs", "storage_encrypted": "false"})
	require.True(t, awsRDSNotEncrypted.Violates(standalone))
	require.False(t, awsRDSNotEncrypted.Violates(member))
	require.False(t, awsRDSNotEncrypted.Violates(docdb))
	require.True(t, awsRDSClusterNotEncrypted.Violates(clusterAsset("rds_cluster", map[string]string{"storage_encrypted": "false"})))
}

func TestRDSEventChecksGateOnSubscriptionsAndDatabases(t *testing.T) {
	settings := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "aws_rds_settings", Provider: asset.ProviderAWS, Metadata: md}
	}
	noSubs := map[string]string{"has_event_subscriptions": "false", "has_instances": "true", "has_clusters": "true",
		"cluster_events_covered": "false", "instance_events_covered": "false", "parameter_group_events_covered": "false", "security_group_events_covered": "false"}
	noDBs := map[string]string{"has_event_subscriptions": "true", "has_instances": "false", "has_clusters": "false",
		"cluster_events_covered": "false", "instance_events_covered": "false", "parameter_group_events_covered": "false", "security_group_events_covered": "false"}
	for _, c := range awsRDSSettingsChecks()[:4] {
		require.False(t, c.Violates(settings(noSubs)), c.ID+": FSBP passes a region with no subscriptions")
		require.False(t, c.Violates(settings(noDBs)), c.ID+": no database emits the events")
	}
	clustersOnly := map[string]string{"has_event_subscriptions": "true", "has_instances": "false", "has_clusters": "true",
		"instance_events_covered": "false", "parameter_group_events_covered": "false"}
	require.False(t, awsRDSInstanceEventsNotSubscribed.Violates(settings(clustersOnly)))
	require.True(t, awsRDSParameterGroupEventsNotSubscribed.Violates(settings(clustersOnly)))
}

func TestRDSMariaDBTLSNeedsTheGroupApplied(t *testing.T) {
	pending := rdsAsset(map[string]string{"engine": "mariadb", "require_secure_transport": "1", "parameter_group_in_sync": "false"})
	require.True(t, awsRDSMariaDBTLSNotEnforced.Violates(pending), "FSBP RDS.44 fails a group that is not in sync")
	mysql := rdsAsset(map[string]string{"engine": "mysql", "require_secure_transport": "0"})
	require.False(t, awsRDSMariaDBTLSNotEnforced.Violates(mysql))
	require.False(t, awsRDSSQLServerTLSNotEnforced.Violates(rdsAsset(map[string]string{"engine": "postgres", "force_ssl": "0"})))
}

// RDS.38 / RDS.39 grade standalone instances only, each on its own engine.
func TestRDSPostgresMySQLTLS_EngineAndClusterScope(t *testing.T) {
	pg := map[string]string{"engine": "postgres", "db_cluster_id": "", "force_ssl": "0"}
	require.True(t, awsRDSPostgresTLSNotEnforced.Violates(rdsAsset(pg)))
	pg["db_cluster_id"] = "multi-az-cluster"
	require.False(t, awsRDSPostgresTLSNotEnforced.Violates(rdsAsset(pg)), "a cluster member is the cluster's concern")
	require.False(t, awsRDSPostgresTLSNotEnforced.Violates(rdsAsset(map[string]string{"engine": "sqlserver-se", "db_cluster_id": "", "force_ssl": "0"})))
	require.False(t, awsRDSPostgresTLSNotEnforced.Violates(rdsAsset(map[string]string{"engine": "postgres", "force_ssl": "0"})),
		"an unread cluster membership is unknown")

	require.True(t, awsRDSMySQLTLSNotEnforced.Violates(rdsAsset(map[string]string{"engine": "mysql", "db_cluster_id": "", "require_secure_transport": "0"})))
	require.False(t, awsRDSMySQLTLSNotEnforced.Violates(rdsAsset(map[string]string{"engine": "mysql", "db_cluster_id": "", "require_secure_transport": "1"})))
	require.False(t, awsRDSMySQLTLSNotEnforced.Violates(rdsAsset(map[string]string{"engine": "mariadb", "db_cluster_id": "", "require_secure_transport": "0"})),
		"MariaDB is RDS.44's")
}
