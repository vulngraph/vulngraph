package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/require"
)

// The posture fields DescribeDBInstances already returns are kept, and cluster
// membership is written even when empty so "not a member" is an observation.
func TestCollectRDSInstances_PostureFields(t *testing.T) {
	f := &fakeRDS{dbs: []rdstypes.DBInstance{
		{
			DBInstanceIdentifier: awssdk.String("aurora-1"),
			DBInstanceArn:        awssdk.String("arn:aws:rds:eu-west-1:111:db:aurora-1"),
			Engine:               awssdk.String("aurora-postgresql"),
			DBClusterIdentifier:  awssdk.String("orders"),
		},
		{
			DBInstanceIdentifier:                  awssdk.String("pg"),
			DBInstanceArn:                         awssdk.String("arn:aws:rds:eu-west-1:111:db:pg"),
			Engine:                                awssdk.String("postgres"),
			MonitoringInterval:                    awssdk.Int32(60),
			EnabledCloudwatchLogsExports:          []string{"postgresql", "upgrade"},
			IAMDatabaseAuthenticationEnabled:      awssdk.Bool(true),
			AutoMinorVersionUpgrade:               awssdk.Bool(true),
			CopyTagsToSnapshot:                    awssdk.Bool(false),
			MasterUsername:                        awssdk.String("postgres"),
			ReadReplicaSourceDBInstanceIdentifier: awssdk.String("pg-primary"),
		},
	}}
	got, err := collectRDSInstances(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)

	aurora := got[0].Metadata
	require.Equal(t, "orders", aurora["db_cluster_id"])
	require.Equal(t, "", aurora["read_replica_source"])
	require.Equal(t, "0", aurora["monitoring_interval"])
	require.Equal(t, "", aurora["log_exports"])
	require.NotContains(t, aurora, "master_username")

	pg := got[1].Metadata
	require.Contains(t, pg, "db_cluster_id")
	require.Equal(t, "", pg["db_cluster_id"])
	require.Equal(t, "pg-primary", pg["read_replica_source"])
	require.Equal(t, "60", pg["monitoring_interval"])
	require.Equal(t, "postgresql,upgrade", pg["log_exports"])
	require.Equal(t, "true", pg["iam_auth_enabled"])
	require.Equal(t, "true", pg["auto_minor_version_upgrade"])
	require.Equal(t, "false", pg["copy_tags_to_snapshot"])
	require.Equal(t, "postgres", pg["master_username"])
}
