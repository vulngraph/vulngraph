package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAwsDataPostureChecksNeverFireOnAbsentData(t *testing.T) {
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "aws-backup-vault-not-encrypted", check: awsBackupVaultNotEncrypted,
			violating: map[string]string{"encryption_key_arn": ""},
			compliant: map[string]string{"encryption_key_arn": "arn:aws:kms:us-east-1:1:key/k"},
			unknown:   map[string]string{"locked": "false"},
		},
		{
			name: "aws-backup-no-vault", check: awsBackupNoVault,
			violating: map[string]string{"backup_vaults": "0"},
			compliant: map[string]string{"backup_vaults": "2"},
			unknown:   map[string]string{"backup_plans": "0"},
		},
		{
			name: "aws-cloudtrail-bucket-no-mfa-delete", check: awsCloudTrailBucketNoMFADelete,
			violating: map[string]string{"is_logging": "true", "s3_bucket_mfa_delete": "Disabled"},
			compliant: map[string]string{"is_logging": "true", "s3_bucket_mfa_delete": "Enabled"},
			// Bucket outside the sweep's inventory: the join key is absent.
			unknown: map[string]string{"is_logging": "true", "s3_bucket": "org-log-archive"},
		},
		{
			name: "aws-docdb-cluster-single-az", check: awsDocDBClusterSingleAZ,
			violating: map[string]string{"multi_az": "false"},
			compliant: map[string]string{"multi_az": "true"},
			unknown:   map[string]string{"member_count": "1"},
		},
		{
			name: "aws-neptune-cluster-single-az", check: awsNeptuneClusterSingleAZ,
			violating: map[string]string{"multi_az": "false"},
			compliant: map[string]string{"multi_az": "true"},
			unknown:   map[string]string{"member_count": "1"},
		},
		{
			name: "aws-kms-cmk-not-enabled", check: awsKMSCMKNotEnabled,
			violating: map[string]string{"key_state": "Disabled"},
			compliant: map[string]string{"key_state": "Enabled"},
			unknown:   map[string]string{"key_spec": "SYMMETRIC_DEFAULT"},
		},
		{
			name: "aws-kms-cmk-multi-region", check: awsKMSCMKMultiRegion,
			violating: map[string]string{"key_state": "Enabled", "multi_region_key_type": "PRIMARY"},
			compliant: map[string]string{"key_state": "Enabled", "multi_region_key_type": ""},
			// Multi-region scope unread.
			unknown: map[string]string{"key_state": "Enabled"},
		},
		{
			name: "aws-opensearch-slow-logs-disabled", check: awsOpenSearchSlowLogsDisabled,
			violating: map[string]string{"search_slow_logs_enabled": "true", "index_slow_logs_enabled": "false"},
			compliant: map[string]string{"search_slow_logs_enabled": "true", "index_slow_logs_enabled": "true"},
			unknown:   map[string]string{"error_logs_enabled": "false"},
		},
		{
			name: "aws-rds-cluster-default-port", check: awsRDSClusterDefaultPort,
			violating: map[string]string{"engine": "aurora-postgresql", "port": "5432"},
			compliant: map[string]string{"engine": "aurora-postgresql", "port": "5433"},
			unknown:   map[string]string{"engine": "aurora-postgresql"},
		},
		{
			name: "aws-rds-instance-retired-engine-version", check: awsRDSInstanceRetiredEngineVersion,
			violating: map[string]string{"engine": "mysql", "engine_version_available": "false"},
			compliant: map[string]string{"engine": "mysql", "engine_version_available": "true"},
			unknown:   map[string]string{"engine": "mysql", "engine_version": "5.7.44"},
		},
		{
			name: "aws-s3-no-default-encryption", check: awsS3NoDefaultEncryption,
			violating: map[string]string{"encryption": ""},
			compliant: map[string]string{"encryption": "AES256"},
			unknown:   map[string]string{"logging": "disabled"},
		},
		{
			name: "aws-s3-not-kms-encrypted", check: awsS3NotKMSEncrypted,
			violating: map[string]string{"encryption": "AES256"},
			compliant: map[string]string{"encryption": "aws:kms"},
			unknown:   map[string]string{"logging": "disabled"},
		},
	})
}

func TestAwsKMSCMKNotEnabledStates(t *testing.T) {
	for state, fires := range map[string]bool{
		"Enabled": false, "Disabled": true, "PendingDeletion": false,
		"PendingReplicaDeletion": false, "Unavailable": true, "PendingImport": true, "Creating": false, "Updating": false, "": false,
	} {
		a := asset.Asset{Metadata: map[string]string{"key_state": state}}
		require.Equalf(t, fires, awsKMSCMKNotEnabled.Violates(a), "key_state %q", state)
	}
}

func TestAwsKMSCMKMultiRegionIgnoresUnusableKeys(t *testing.T) {
	a := asset.Asset{Metadata: map[string]string{"key_state": "Disabled", "multi_region_key_type": "REPLICA"}}
	require.False(t, awsKMSCMKMultiRegion.Violates(a))
	a.Metadata["key_state"] = "Enabled"
	require.True(t, awsKMSCMKMultiRegion.Violates(a))
}

func TestAwsCloudTrailBucketNoMFADeleteNeedsActiveTrail(t *testing.T) {
	a := asset.Asset{Metadata: map[string]string{"is_logging": "false", "s3_bucket_mfa_delete": "Disabled"}}
	require.False(t, awsCloudTrailBucketNoMFADelete.Violates(a), "a stopped trail is not graded")
	delete(a.Metadata, "is_logging")
	require.False(t, awsCloudTrailBucketNoMFADelete.Violates(a), "unread logging state is unknown")
}

func TestAwsCloudWatchCrossAccountRole(t *testing.T) {
	role := func(name string) asset.Asset {
		return asset.Asset{Name: name, Type: "iam_role", Provider: asset.ProviderAWS}
	}
	require.True(t, awsCloudWatchCrossAccountRole.Violates(role("CloudWatch-CrossAccountSharingRole")))
	require.False(t, awsCloudWatchCrossAccountRole.Violates(role("CloudWatch-Other")))
	require.False(t, awsCloudWatchCrossAccountRole.Violates(role("")))
}

func TestAwsRDSClusterDefaultPortEngines(t *testing.T) {
	tests := []struct {
		engine, port string
		fires        bool
	}{
		{"aurora-mysql", "3306", true},
		{"mysql", "3306", true},
		{"mariadb", "3306", true},
		{"postgres", "5432", true},
		{"aurora-postgresql", "5432", true},
		{"aurora-mysql", "5432", false},
		{"aurora-postgresql", "3306", false},
		{"aurora-mysql", "3307", false},
		{"aurora-mysql", "", false},
		{"aurora-mysql", "not-a-port", false},
		{"", "3306", false},
	}
	for _, tt := range tests {
		a := asset.Asset{Metadata: map[string]string{"engine": tt.engine, "port": tt.port}}
		require.Equalf(t, tt.fires, awsRDSClusterDefaultPort.Violates(a), "%s:%s", tt.engine, tt.port)
	}
}

func TestAwsS3KMSEncryptionVariants(t *testing.T) {
	for algorithm, fires := range map[string]bool{
		"": true, "AES256": true, "aws:kms": false, "aws:kms:dsse": false,
	} {
		a := asset.Asset{Metadata: map[string]string{"encryption": algorithm}}
		require.Equalf(t, fires, awsS3NotKMSEncrypted.Violates(a), "algorithm %q", algorithm)
	}
}

func TestRDSRetiredEngineVersion_OnlyCommunityEngines(t *testing.T) {
	for engine, want := range map[string]bool{"mysql": true, "mariadb": true, "postgres": true, "oracle-ee": false, "sqlserver-se": false, "custom-oracle-ee": false} {
		a := asset.Asset{Type: "rds_instance", Provider: asset.ProviderAWS, Metadata: map[string]string{"engine": engine, "engine_version_available": "false"}}
		if got := awsRDSInstanceRetiredEngineVersion.Violates(a); got != want {
			t.Errorf("%s: Violates = %v, want %v", engine, got, want)
		}
	}
}

func TestBackupVaultNotEncrypted_SkipsAirGappedVaults(t *testing.T) {
	a := asset.Asset{Type: "backup_vault", Provider: asset.ProviderAWS, Metadata: map[string]string{"encryption_key_arn": "", "vault_type": "LOGICALLY_AIR_GAPPED_BACKUP_VAULT"}}
	if awsBackupVaultNotEncrypted.Violates(a) {
		t.Fatal("an air-gapped vault with no listed key must not fire")
	}
	a.Metadata["vault_type"] = "BACKUP_VAULT"
	if !awsBackupVaultNotEncrypted.Violates(a) {
		t.Fatal("a standard vault with no key must fire")
	}
}
