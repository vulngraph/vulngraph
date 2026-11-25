package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestAwsDMSCacheMSKChecksNeverFireOnAbsentData(t *testing.T) {
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "aws-dms-replication-instance-public", check: awsDMSReplicationInstancePublic,
			violating: map[string]string{"publicly_accessible": "true"},
			compliant: map[string]string{"publicly_accessible": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-dms-auto-minor-upgrade-disabled", check: awsDMSAutoMinorUpgradeDisabled,
			violating: map[string]string{"auto_minor_version_upgrade": "false"},
			compliant: map[string]string{"auto_minor_version_upgrade": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-dms-replication-instance-single-az", check: awsDMSReplicationInstanceSingleAZ,
			violating: map[string]string{"multi_az": "false"},
			compliant: map[string]string{"multi_az": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-dms-task-target-logging-disabled", check: awsDMSTaskTargetLoggingDisabled,
			violating: map[string]string{"target_logging_enabled": "false"},
			compliant: map[string]string{"target_logging_enabled": "true"},
			// Task settings not returned or unparseable.
			unknown: map[string]string{"source_logging_enabled": "false"},
		},
		{
			name: "aws-dms-task-source-logging-disabled", check: awsDMSTaskSourceLoggingDisabled,
			violating: map[string]string{"source_logging_enabled": "false"},
			compliant: map[string]string{"source_logging_enabled": "true"},
			unknown:   map[string]string{"target_logging_enabled": "false"},
		},
		{
			name: "aws-dms-endpoint-no-ssl", check: awsDMSEndpointNoSSL,
			violating: map[string]string{"engine": "postgres", "ssl_mode": "none"},
			compliant: map[string]string{"engine": "postgres", "ssl_mode": "verify-full"},
			unknown:   map[string]string{"engine": "postgres"},
		},
		{
			name: "aws-dms-neptune-endpoint-no-iam-auth", check: awsDMSNeptuneEndpointNoIAMAuth,
			violating: map[string]string{"engine": "neptune", "neptune_iam_auth_enabled": "false"},
			compliant: map[string]string{"engine": "neptune", "neptune_iam_auth_enabled": "true"},
			// NeptuneSettings not returned.
			unknown: map[string]string{"engine": "neptune"},
		},
		{
			name: "aws-dms-mongodb-endpoint-no-auth", check: awsDMSMongoDBEndpointNoAuth,
			violating: map[string]string{"engine": "mongodb", "mongodb_auth_type": "no"},
			compliant: map[string]string{"engine": "mongodb", "mongodb_auth_type": "password"},
			unknown:   map[string]string{"engine": "mongodb"},
		},
		{
			name: "aws-dms-redis-endpoint-no-tls", check: awsDMSRedisEndpointNoTLS,
			violating: map[string]string{"engine": "redis", "redis_ssl_security_protocol": "plaintext"},
			compliant: map[string]string{"engine": "redis", "redis_ssl_security_protocol": "ssl-encryption"},
			unknown:   map[string]string{"engine": "redis"},
		},
		{
			name: "aws-elasticache-cluster-no-backup", check: awsElastiCacheClusterNoBackup,
			violating: map[string]string{"engine": "redis", "replication_group_id": "", "snapshot_retention_limit": "0"},
			compliant: map[string]string{"engine": "redis", "replication_group_id": "", "snapshot_retention_limit": "1"},
			unknown:   map[string]string{"engine": "redis", "replication_group_id": ""},
		},
		{
			name: "aws-elasticache-replication-group-no-backup", check: awsElastiCacheGroupNoBackup,
			violating: map[string]string{"snapshot_retention_limit": "0"},
			compliant: map[string]string{"snapshot_retention_limit": "7"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-elasticache-cluster-auto-minor-upgrade-disabled", check: awsElastiCacheClusterAutoMinorUpgradeDisabled,
			violating: map[string]string{"engine": "valkey", "replication_group_id": "", "auto_minor_version_upgrade": "false"},
			compliant: map[string]string{"engine": "valkey", "replication_group_id": "", "auto_minor_version_upgrade": "true"},
			unknown:   map[string]string{"engine": "valkey", "replication_group_id": ""},
		},
		{
			name: "aws-elasticache-replication-group-auto-minor-upgrade-disabled", check: awsElastiCacheGroupAutoMinorUpgradeDisabled,
			violating: map[string]string{"auto_minor_version_upgrade": "false"},
			compliant: map[string]string{"auto_minor_version_upgrade": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-elasticache-replication-group-no-auto-failover", check: awsElastiCacheGroupNoAutoFailover,
			violating: map[string]string{"automatic_failover": "disabled"},
			compliant: map[string]string{"automatic_failover": "enabled"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-elasticache-replication-group-not-encrypted-at-rest", check: awsElastiCacheGroupNotEncryptedAtRest,
			violating: map[string]string{"at_rest_encryption_enabled": "false"},
			compliant: map[string]string{"at_rest_encryption_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-elasticache-replication-group-not-encrypted-in-transit", check: awsElastiCacheGroupNotEncryptedInTransit,
			violating: map[string]string{"transit_encryption_enabled": "false"},
			compliant: map[string]string{"transit_encryption_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-elasticache-replication-group-redis-no-auth", check: awsElastiCacheGroupRedisNoAuth,
			violating: map[string]string{"engine": "redis", "engine_version": "5.0.6", "auth_token_enabled": "false"},
			compliant: map[string]string{"engine": "redis", "engine_version": "5.0.6", "auth_token_enabled": "true"},
			// No node was listed for the group, so its version is unread.
			unknown: map[string]string{"engine": "redis", "auth_token_enabled": "false"},
		},
		{
			name: "aws-elasticache-cluster-default-subnet-group", check: awsElastiCacheClusterDefaultSubnetGroup,
			violating: map[string]string{"cache_subnet_group": "default", "replication_group_id": ""},
			compliant: map[string]string{"cache_subnet_group": "cache-private", "replication_group_id": ""},
			unknown:   map[string]string{"cache_subnet_group": "default"},
		},
		{
			name: "aws-elasticache-replication-group-default-subnet-group", check: awsElastiCacheGroupDefaultSubnetGroup,
			violating: map[string]string{"cache_subnet_group": "default"},
			compliant: map[string]string{"cache_subnet_group": "cache-private"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-msk-in-cluster-plaintext", check: awsMSKInClusterPlaintext,
			violating: map[string]string{"in_cluster_encryption": "false"},
			compliant: map[string]string{"in_cluster_encryption": "true"},
			unknown:   map[string]string{"cluster_type": "PROVISIONED"},
		},
		{
			name: "aws-msk-public-access", check: awsMSKPublicAccess,
			violating: map[string]string{"public_access_type": "SERVICE_PROVIDED_EIPS"},
			compliant: map[string]string{"public_access_type": "DISABLED"},
			unknown:   map[string]string{"cluster_type": "SERVERLESS"},
		},
		{
			name: "aws-msk-unauthenticated-access", check: awsMSKUnauthenticatedAccess,
			violating: map[string]string{"unauthenticated_access": "true"},
			compliant: map[string]string{"unauthenticated_access": "false"},
			unknown:   map[string]string{"cluster_type": "SERVERLESS"},
		},
		{
			name: "aws-msk-connector-plaintext", check: awsMSKConnectorPlaintext,
			violating: map[string]string{"encryption_in_transit_type": "PLAINTEXT"},
			compliant: map[string]string{"encryption_in_transit_type": "TLS"},
			unknown:   map[string]string{"log_delivery_enabled": "true"},
		},
		{
			name: "aws-msk-connector-no-logging", check: awsMSKConnectorNoLogging,
			violating: map[string]string{"log_delivery_enabled": "false"},
			compliant: map[string]string{"log_delivery_enabled": "true"},
			unknown:   map[string]string{},
		},
	})
}

func TestDMSEndpointSSLGradesOnlySslModeEngines(t *testing.T) {
	ep := func(engine string) asset.Asset {
		return asset.Asset{Type: "dms_endpoint", Provider: asset.ProviderAWS, Metadata: map[string]string{"engine": engine, "ssl_mode": "none"}}
	}
	for _, engine := range []string{"mysql", "oracle", "sqlserver", "mongodb", "docdb", "aurora-postgresql"} {
		require.True(t, awsDMSEndpointNoSSL.Violates(ep(engine)), engine)
	}
	// SslMode is "none" by construction on these: they speak HTTPS, or carry
	// transport security in their own settings (Redis: DMS.12; Kafka).
	for _, engine := range []string{"s3", "dynamodb", "kinesis", "kafka", "opensearch", "neptune", "redshift", "redis"} {
		require.False(t, awsDMSEndpointNoSSL.Violates(ep(engine)), engine)
	}
}

// One replication group's setting is one finding: its nodes step aside, and
// an unread membership counts as a member.
func TestElastiCacheGroupNodesStepAsideForTheGroup(t *testing.T) {
	node := func(rg string, set bool) asset.Asset {
		md := map[string]string{
			"engine": "redis", "snapshot_retention_limit": "0",
			"auto_minor_version_upgrade": "false", "cache_subnet_group": "default",
		}
		if set {
			md["replication_group_id"] = rg
		}
		return asset.Asset{Type: "elasticache_cluster", Provider: asset.ProviderAWS, Metadata: md}
	}
	for _, c := range []Check{awsElastiCacheClusterNoBackup, awsElastiCacheClusterAutoMinorUpgradeDisabled, awsElastiCacheClusterDefaultSubnetGroup} {
		require.True(t, c.Violates(node("", true)), c.ID+": standalone node")
		require.False(t, c.Violates(node("rg-1", true)), c.ID+": group member")
		require.False(t, c.Violates(node("", false)), c.ID+": unread membership")
	}
	// Memcached has no backups and is outside ElastiCache.1/.2, but its subnet
	// group is still graded (ElastiCache.7 covers every engine).
	mc := node("", true)
	mc.Metadata["engine"] = "memcached"
	require.False(t, awsElastiCacheClusterNoBackup.Violates(mc))
	require.False(t, awsElastiCacheClusterAutoMinorUpgradeDisabled.Violates(mc))
	require.True(t, awsElastiCacheClusterDefaultSubnetGroup.Violates(mc))
}

func TestElastiCacheRedisAuthOnlyBefore6(t *testing.T) {
	grp := func(engine, version string) asset.Asset {
		return asset.Asset{Type: "elasticache_replication_group", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"engine": engine, "engine_version": version, "auth_token_enabled": "false"}}
	}
	require.True(t, awsElastiCacheGroupRedisNoAuth.Violates(grp("redis", "5.0.6")))
	require.True(t, awsElastiCacheGroupRedisNoAuth.Violates(grp("redis", "4.0.10")))
	require.False(t, awsElastiCacheGroupRedisNoAuth.Violates(grp("redis", "6.2")), "6.0+ uses RBAC")
	require.False(t, awsElastiCacheGroupRedisNoAuth.Violates(grp("redis", "7.1")))
	require.False(t, awsElastiCacheGroupRedisNoAuth.Violates(grp("valkey", "7.2")))
	require.False(t, awsElastiCacheGroupRedisNoAuth.Violates(grp("redis", "")))
}

func TestMSKPublicAccessTiers(t *testing.T) {
	c := asset.Asset{Type: "msk_cluster", Provider: asset.ProviderAWS, Metadata: map[string]string{
		"public_access_type": "SERVICE_PROVIDED_EIPS", "unauthenticated_access": "false", "public_access": asset.PublicAccessPossible,
	}}
	f, ok := awsMSKPublicAccess.eval(c, c.LastSeen)
	require.True(t, ok)
	require.Equal(t, finding.SeverityMedium, f.Severity)
	require.Equal(t, "MSK cluster brokers are publicly accessible", f.Title)

	c.Metadata["unauthenticated_access"] = "true"
	c.Metadata["public_access"] = asset.PublicAccessConfirmed
	f, ok = awsMSKPublicAccess.eval(c, c.LastSeen)
	require.True(t, ok)
	require.Equal(t, finding.SeverityCritical, f.Severity)
	require.Equal(t, "MSK cluster brokers are public and accept unauthenticated clients", f.Title)
}
