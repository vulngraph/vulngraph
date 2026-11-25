package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestAwsRedshiftChecksNeverFireOnAbsentData(t *testing.T) {
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "aws-redshift-publicly-accessible", check: awsRedshiftPubliclyAccessible,
			violating: map[string]string{"publicly_accessible": "true"},
			compliant: map[string]string{"publicly_accessible": "false"},
			unknown:   map[string]string{"port": "5439"},
		},
		{
			name: "aws-redshift-port-world-open", check: awsRedshiftPortWorldOpen,
			violating: map[string]string{"port_world_open": "true"},
			compliant: map[string]string{"port_world_open": "false"},
			unknown:   map[string]string{"publicly_accessible": "true"},
		},
		{
			name: "aws-redshift-no-tls", check: awsRedshiftNoTLS,
			violating: map[string]string{"require_ssl": "false"},
			compliant: map[string]string{"require_ssl": "true"},
			unknown:   map[string]string{"parameter_group": "default.redshift-1.0"},
		},
		{
			name: "aws-redshift-snapshot-retention-short", check: awsRedshiftSnapshotRetentionShort,
			violating: map[string]string{"automated_snapshot_retention": "1"},
			compliant: map[string]string{"automated_snapshot_retention": "7"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-redshift-audit-logging-disabled", check: awsRedshiftAuditLoggingDisabled,
			violating: map[string]string{"audit_logging_enabled": "false"},
			compliant: map[string]string{"audit_logging_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-redshift-version-upgrade-disabled", check: awsRedshiftVersionUpgradeDisabled,
			violating: map[string]string{"allow_version_upgrade": "false"},
			compliant: map[string]string{"allow_version_upgrade": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-redshift-no-enhanced-vpc-routing", check: awsRedshiftNoEnhancedVPCRouting,
			violating: map[string]string{"enhanced_vpc_routing": "false"},
			compliant: map[string]string{"enhanced_vpc_routing": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-redshift-default-admin-username", check: awsRedshiftDefaultAdminUsername,
			violating: map[string]string{"master_username": "awsuser"},
			compliant: map[string]string{"master_username": "warehouse_admin"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-redshift-not-encrypted", check: awsRedshiftNotEncrypted,
			violating: map[string]string{"encrypted": "false"},
			compliant: map[string]string{"encrypted": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-redshift-no-multi-az", check: awsRedshiftNoMultiAZ,
			violating: map[string]string{"multi_az": "false"},
			compliant: map[string]string{"multi_az": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-redshift-serverless-no-enhanced-vpc-routing", check: awsRedshiftServerlessNoEnhancedVPCRouting,
			violating: map[string]string{"enhanced_vpc_routing": "false"},
			compliant: map[string]string{"enhanced_vpc_routing": "true"},
			unknown:   map[string]string{"namespace": "ns"},
		},
		{
			name: "aws-redshift-serverless-no-tls", check: awsRedshiftServerlessNoTLS,
			violating: map[string]string{"require_ssl": "false"},
			compliant: map[string]string{"require_ssl": "true"},
			unknown:   map[string]string{"namespace": "ns"},
		},
		{
			name: "aws-redshift-serverless-publicly-accessible", check: awsRedshiftServerlessPubliclyAccessible,
			violating: map[string]string{"publicly_accessible": "true"},
			compliant: map[string]string{"publicly_accessible": "false"},
			unknown:   map[string]string{"namespace": "ns"},
		},
		{
			name: "aws-redshift-serverless-default-admin-username", check: awsRedshiftServerlessDefaultAdminUsername,
			violating: map[string]string{"admin_username": "admin"},
			compliant: map[string]string{"admin_username": "dw_owner"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-redshift-serverless-no-log-exports", check: awsRedshiftServerlessNoLogExports,
			violating: map[string]string{"log_exports": "userlog"},
			compliant: map[string]string{"log_exports": "connectionlog,useractivitylog,userlog"},
			unknown:   map[string]string{"admin_username": "dw_owner"},
		},
	})
}

func redshiftAsset(typ string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "r-1", Name: "r-1", Type: typ, Provider: asset.ProviderAWS, Metadata: md}
}

// A public cluster whose port is also world-open is one root cause: the
// port check reports it at High and the public-access check steps aside.
func TestRedshiftPublicAndWorldOpenIsOneFinding(t *testing.T) {
	r := NewRegistry()
	r.Register(awsRedshiftPubliclyAccessible, awsRedshiftPortWorldOpen)
	both := redshiftAsset("redshift_cluster", map[string]string{"publicly_accessible": "true", "port_world_open": "true", "port": "5439"})
	fs := r.Run([]asset.Asset{both}, time.Now())
	require.Len(t, fs, 1)
	require.Equal(t, "aws-redshift-port-world-open", fs[0].CheckID)
	require.Equal(t, finding.SeverityHigh, fs[0].Severity)

	// Private cluster, world-open rule: reachable only from inside, Low.
	private := redshiftAsset("redshift_cluster", map[string]string{"publicly_accessible": "false", "port_world_open": "true"})
	fs = r.Run([]asset.Asset{private}, time.Now())
	require.Len(t, fs, 1)
	require.Equal(t, finding.SeverityLow, fs[0].Severity)
	require.Contains(t, fs[0].Title, "Private")

	// Public, port closed to the world: the public-access check, Medium on 5439.
	public := redshiftAsset("redshift_cluster", map[string]string{"publicly_accessible": "true", "port_world_open": "false", "port": "5439"})
	fs = r.Run([]asset.Asset{public}, time.Now())
	require.Len(t, fs, 1)
	require.Equal(t, "aws-redshift-publicly-accessible", fs[0].CheckID)
	require.Equal(t, finding.SeverityMedium, fs[0].Severity)
	public.Metadata["port"] = "15439"
	require.Equal(t, finding.SeverityLow, awsRedshiftPubliclyAccessible.SeverityFor(public))
}

func TestRedshiftSnapshotRetentionTiers(t *testing.T) {
	c := func(days string) asset.Asset {
		return redshiftAsset("redshift_cluster", map[string]string{"automated_snapshot_retention": days})
	}
	require.True(t, awsRedshiftSnapshotRetentionShort.Violates(c("0")))
	require.Equal(t, "Redshift cluster has automated snapshots disabled", awsRedshiftSnapshotRetentionShort.TitleFor(c("0")))
	require.True(t, awsRedshiftSnapshotRetentionShort.Violates(c("6")))
	require.False(t, awsRedshiftSnapshotRetentionShort.Violates(c("7")))
	require.False(t, awsRedshiftSnapshotRetentionShort.Violates(c("35")))
}

func TestRedshiftServerlessLogExportsNeedBoth(t *testing.T) {
	ns := func(exports string) asset.Asset {
		return redshiftAsset("redshift_serverless_namespace", map[string]string{"log_exports": exports})
	}
	require.True(t, awsRedshiftServerlessNoLogExports.Violates(ns("")), "an observed empty export list fires")
	require.True(t, awsRedshiftServerlessNoLogExports.Violates(ns("connectionlog")))
	require.True(t, awsRedshiftServerlessNoLogExports.Violates(ns("useractivitylog,userlog")))
	require.False(t, awsRedshiftServerlessNoLogExports.Violates(ns("connectionlog,userlog")))
	require.Equal(t, "connectionlog", awsRedshiftServerlessNoLogExports.EvidenceFor(ns("userlog"))["missing_log_types"])
}

func TestRedshiftDefaultAdminNames(t *testing.T) {
	require.True(t, awsRedshiftDefaultAdminUsername.Violates(redshiftAsset("redshift_cluster", map[string]string{"master_username": "AWSUser"})))
	require.False(t, awsRedshiftDefaultAdminUsername.Violates(redshiftAsset("redshift_cluster", map[string]string{"master_username": "admin"})),
		"Redshift.8 fails awsuser only")
	require.False(t, awsRedshiftServerlessDefaultAdminUsername.Violates(redshiftAsset("redshift_serverless_namespace", map[string]string{"admin_username": "awsuser"})),
		"RedshiftServerless.5 fails admin only")
}
