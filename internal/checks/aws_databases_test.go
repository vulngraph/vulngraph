package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// registered returns the check as Default() stamps it: Evaluable needs the
// derived required keys and probes, which the bare package var lacks.
func registered(t *testing.T, id string) Check {
	t.Helper()
	c, ok := Default().ByID(id)
	require.True(t, ok, id)
	return c
}

func rdsAsset(md map[string]string) asset.Asset {
	return asset.Asset{ID: "arn:aws:rds:eu-west-1:1:db:x", Type: "rds_instance", Provider: asset.ProviderAWS, Metadata: md}
}

// Aurora and other cluster members report MultiAZ=false and
// DeletionProtection=false at the instance level by design; FSBP RDS.5/RDS.8
// exclude them. An unread membership keeps the checks silent.
func TestRDSInstanceChecksSkipClusterMembers(t *testing.T) {
	standalone := map[string]string{"engine": "postgres", "db_cluster_id": "", "multi_az": "false", "deletion_protection": "false"}
	aurora := map[string]string{"engine": "aurora-postgresql", "db_cluster_id": "orders", "multi_az": "false", "deletion_protection": "false"}
	multiAZCluster := map[string]string{"engine": "postgres", "db_cluster_id": "maz", "multi_az": "false", "deletion_protection": "false"}
	unread := map[string]string{"engine": "postgres", "multi_az": "false", "deletion_protection": "false"}
	for _, c := range []Check{awsRDSNoMultiAZ, awsRDSNoDeletionProtection} {
		require.True(t, c.Violates(rdsAsset(standalone)), c.ID)
		require.False(t, c.Violates(rdsAsset(aurora)), c.ID)
		require.False(t, c.Violates(rdsAsset(multiAZCluster)), c.ID)
		require.False(t, c.Violates(rdsAsset(unread)), c.ID+": unread membership")
		require.False(t, registered(t, c.ID).Evaluable(rdsAsset(unread)), c.ID+": unread membership must not close a finding")
	}
}

func TestRDSNoBackupRetentionTiers(t *testing.T) {
	tests := []struct {
		name      string
		md        map[string]string
		fires     bool
		severity  finding.Severity
		titleHint string
	}{
		{"none", map[string]string{"backup_retention": "0", "db_cluster_id": "", "read_replica_source": ""}, true, finding.SeverityHigh, "disabled"},
		{"short", map[string]string{"backup_retention": "3", "db_cluster_id": "", "read_replica_source": ""}, true, finding.SeverityLow, "less than 7 days"},
		{"seven", map[string]string{"backup_retention": "7", "db_cluster_id": "", "read_replica_source": ""}, false, "", ""},
		{"read replica", map[string]string{"backup_retention": "0", "db_cluster_id": "", "read_replica_source": "primary"}, false, "", ""},
		{"cluster member", map[string]string{"backup_retention": "1", "db_cluster_id": "orders", "read_replica_source": ""}, false, "", ""},
		{"garbage", map[string]string{"backup_retention": "x", "db_cluster_id": ""}, false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := rdsAsset(tt.md)
			require.Equal(t, tt.fires, awsRDSNoBackup.Violates(a))
			if tt.fires {
				require.Equal(t, tt.severity, awsRDSNoBackup.SeverityFor(a))
				require.Contains(t, awsRDSNoBackup.TitleFor(a), tt.titleHint)
			}
		})
	}
}

func TestRDSNoLogExportsPerEngine(t *testing.T) {
	tests := []struct {
		engine, exports string
		fires           bool
		missing         string
	}{
		{"postgres", "postgresql,upgrade", false, ""},
		{"postgres", "", true, "postgresql,upgrade"},
		{"postgres", "postgresql", true, "upgrade"}, // FSBP RDS.9 wants both
		{"mysql", "error,slowquery", true, "audit,general"},
		{"mariadb", "audit,error,general,slowquery", false, ""},
		{"sqlserver-se", "error", true, "agent"},
		{"oracle-ee", "alert,audit,listener,trace", false, ""},
		{"neptune", "", false, ""}, // no FSBP requirement
	}
	for _, tt := range tests {
		a := rdsAsset(map[string]string{"engine": tt.engine, "log_exports": tt.exports, "db_cluster_id": ""})
		require.Equal(t, tt.fires, awsRDSNoLogExports.Violates(a), tt.engine)
		if tt.fires {
			require.Equal(t, tt.missing, awsRDSNoLogExports.EvidenceFor(a)["missing_log_types"])
		}
	}
	aurora := rdsAsset(map[string]string{"engine": "aurora-mysql", "log_exports": "", "db_cluster_id": "c"})
	require.False(t, awsRDSNoLogExports.Violates(aurora), "Aurora exports are a cluster setting")
	// A Multi-AZ DB cluster member on a listed engine is skipped too.
	member := rdsAsset(map[string]string{"engine": "postgres", "log_exports": "", "db_cluster_id": "maz"})
	require.False(t, awsRDSNoLogExports.Violates(member), "cluster members export at the cluster")
}

func TestRDSIAMAuthOnlySupportedEngines(t *testing.T) {
	require.True(t, awsRDSNoIAMAuth.Violates(rdsAsset(map[string]string{"engine": "mysql", "iam_auth_enabled": "false", "db_cluster_id": ""})))
	require.False(t, awsRDSNoIAMAuth.Violates(rdsAsset(map[string]string{"engine": "sqlserver-ex", "iam_auth_enabled": "false", "db_cluster_id": ""})))
	require.False(t, registered(t, awsRDSNoIAMAuth.ID).Evaluable(rdsAsset(map[string]string{"iam_auth_enabled": "false", "db_cluster_id": ""})),
		"an unread engine could be a supported one")
}

func TestRDSEngineDefaultPortStepsAsideForPublic(t *testing.T) {
	private := map[string]string{"engine": "postgres", "port": "5432", "publicly_accessible": "false", "db_cluster_id": ""}
	require.True(t, awsRDSEngineDefaultPort.Violates(rdsAsset(private)))
	public := map[string]string{"engine": "postgres", "port": "5432", "publicly_accessible": "true"}
	require.False(t, awsRDSEngineDefaultPort.Violates(rdsAsset(public)), "aws-rds-publicly-accessible grades the port")
	custom := map[string]string{"engine": "oracle-ee", "port": "1522", "publicly_accessible": "false", "db_cluster_id": ""}
	require.False(t, awsRDSEngineDefaultPort.Violates(rdsAsset(custom)))
	auroraMember := map[string]string{"engine": "aurora-postgresql", "port": "5432", "publicly_accessible": "false", "db_cluster_id": "orders"}
	require.False(t, awsRDSEngineDefaultPort.Violates(rdsAsset(auroraMember)), "FSBP RDS.23 excludes cluster members")
}

func TestRDSDefaultMasterUsername(t *testing.T) {
	require.True(t, awsRDSDefaultMasterUsername.Violates(rdsAsset(map[string]string{"master_username": "Admin", "db_cluster_id": ""})))
	require.False(t, awsRDSDefaultMasterUsername.Violates(rdsAsset(map[string]string{"master_username": "orders_owner", "db_cluster_id": ""})))
	require.False(t, registered(t, awsRDSDefaultMasterUsername.ID).Evaluable(rdsAsset(map[string]string{"db_cluster_id": ""})),
		"an unread username could be a default one")
}
