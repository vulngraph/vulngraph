package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAwsStorageServiceChecksNeverFireOnAbsentData(t *testing.T) {
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "aws-efs-not-encrypted", check: awsEFSNotEncrypted,
			violating: map[string]string{"encrypted": "false"},
			compliant: map[string]string{"encrypted": "true"},
			unknown:   map[string]string{"kms_key_id": ""},
		},
		{
			name: "aws-efs-policy-public", check: awsEFSPolicyPublic,
			violating: map[string]string{"public_access": asset.PublicAccessConfirmed},
			compliant: map[string]string{"public_access": asset.PublicAccessNone},
			unknown:   map[string]string{},
		},
		{
			name: "aws-efs-not-in-backup-plan", check: awsEFSNotInBackupPlan,
			violating: map[string]string{"in_backup_plan": "false"},
			compliant: map[string]string{"in_backup_plan": "true"},
			unknown:   map[string]string{"automatic_backups": "DISABLED"},
		},
		{
			name: "aws-efs-automatic-backups-disabled", check: awsEFSAutomaticBackupsDisabled,
			violating: map[string]string{"automatic_backups": "DISABLED", "in_backup_plan": "true"},
			compliant: map[string]string{"automatic_backups": "ENABLED", "in_backup_plan": "true"},
			unknown:   map[string]string{"in_backup_plan": "true"},
		},
		{
			name: "aws-efs-access-point-root-directory", check: awsEFSAccessPointRootDirectory,
			violating: map[string]string{"root_directory": "/"},
			compliant: map[string]string{"root_directory": "/app"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-efs-access-point-no-user-identity", check: awsEFSAccessPointNoUserIdentity,
			violating: map[string]string{"posix_user_enforced": "false"},
			compliant: map[string]string{"posix_user_enforced": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-fsx-openzfs-no-copy-tags", check: awsFSxOpenZFSNoCopyTags,
			violating: map[string]string{"file_system_type": "OPENZFS", "copy_tags_to_backups": "true", "copy_tags_to_volumes": "false"},
			compliant: map[string]string{"file_system_type": "OPENZFS", "copy_tags_to_backups": "true", "copy_tags_to_volumes": "true"},
			unknown:   map[string]string{"file_system_type": "OPENZFS"},
		},
		{
			name: "aws-fsx-lustre-no-copy-tags", check: awsFSxLustreNoCopyTags,
			violating: map[string]string{"file_system_type": "LUSTRE", "deployment_type": "PERSISTENT_2", "copy_tags_to_backups": "false"},
			compliant: map[string]string{"file_system_type": "LUSTRE", "deployment_type": "PERSISTENT_2", "copy_tags_to_backups": "true"},
			unknown:   map[string]string{"file_system_type": "LUSTRE"},
		},
		{
			name: "aws-fsx-openzfs-single-az", check: awsFSxOpenZFSSingleAZ,
			violating: map[string]string{"file_system_type": "OPENZFS", "deployment_type": "SINGLE_AZ_HA_2"},
			compliant: map[string]string{"file_system_type": "OPENZFS", "deployment_type": "MULTI_AZ_1"},
			unknown:   map[string]string{"file_system_type": "OPENZFS"},
		},
		{
			name: "aws-fsx-ontap-single-az", check: awsFSxONTAPSingleAZ,
			violating: map[string]string{"file_system_type": "ONTAP", "deployment_type": "SINGLE_AZ_2"},
			compliant: map[string]string{"file_system_type": "ONTAP", "deployment_type": "MULTI_AZ_2"},
			unknown:   map[string]string{"file_system_type": "ONTAP"},
		},
		{
			name: "aws-fsx-windows-single-az", check: awsFSxWindowsSingleAZ,
			violating: map[string]string{"file_system_type": "WINDOWS", "deployment_type": "SINGLE_AZ_2"},
			compliant: map[string]string{"file_system_type": "WINDOWS", "deployment_type": "MULTI_AZ_1"},
			unknown:   map[string]string{"file_system_type": "WINDOWS"},
		},
		{
			name: "aws-backup-vault-policy-public", check: awsBackupVaultPolicyPublic,
			violating: map[string]string{"public_access": asset.PublicAccessConfirmed},
			compliant: map[string]string{"public_access": asset.PublicAccessNone},
			unknown:   map[string]string{},
		},
		{
			name: "aws-backup-recovery-points-unencrypted", check: awsBackupRecoveryPointsUnencrypted,
			violating: map[string]string{"unencrypted_recovery_points": "3"},
			compliant: map[string]string{"unencrypted_recovery_points": "0"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-backup-vault-not-locked", check: awsBackupVaultNotLocked,
			violating: map[string]string{"locked": "false", "vault_type": "BACKUP_VAULT"},
			compliant: map[string]string{"locked": "true", "vault_type": "BACKUP_VAULT"},
			unknown:   map[string]string{"vault_type": "BACKUP_VAULT"},
		},
		{
			name: "aws-backup-no-plan", check: awsBackupNoPlan,
			violating: map[string]string{"backup_plans": "0", "recovery_points": "12"},
			compliant: map[string]string{"backup_plans": "1", "recovery_points": "12"},
			unknown:   map[string]string{"recovery_points": "12"},
		},
		{
			name: "aws-dynamodb-table-policy-public", check: awsDynamoDBTablePolicyPublic,
			violating: map[string]string{"public_access": asset.PublicAccessConfirmed},
			compliant: map[string]string{"public_access": asset.PublicAccessNone},
			unknown:   map[string]string{},
		},
		{
			name: "aws-dynamodb-no-autoscaling", check: awsDynamoDBNoAutoScaling,
			violating: map[string]string{"billing_mode": "PROVISIONED", "read_autoscaling": "true", "write_autoscaling": "false"},
			compliant: map[string]string{"billing_mode": "PROVISIONED", "read_autoscaling": "true", "write_autoscaling": "true"},
			unknown:   map[string]string{"billing_mode": "PROVISIONED"},
		},
		{
			name: "aws-dynamodb-no-pitr", check: awsDynamoDBNoPITR,
			violating: map[string]string{"point_in_time_recovery": "DISABLED"},
			compliant: map[string]string{"point_in_time_recovery": "ENABLED"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-dynamodb-no-deletion-protection", check: awsDynamoDBNoDeletionProtection,
			violating: map[string]string{"deletion_protection": "false"},
			compliant: map[string]string{"deletion_protection": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-dax-not-encrypted-at-rest", check: awsDAXNotEncryptedAtRest,
			violating: map[string]string{"sse_status": "DISABLED"},
			compliant: map[string]string{"sse_status": "ENABLED"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-dax-not-encrypted-in-transit", check: awsDAXNotEncryptedInTransit,
			violating: map[string]string{"endpoint_encryption_type": "NONE"},
			compliant: map[string]string{"endpoint_encryption_type": "TLS"},
			unknown:   map[string]string{},
		},
	})
}

// The two EFS backup checks split one root cause: a file system no plan
// covers is the not-in-plan finding only; automatic backups off while another
// plan covers it is the informational one. Together they fire exactly when
// automatic backups are off (FSBP EFS.7).
func TestEFSBackupChecksFireOncePerRootCause(t *testing.T) {
	fs := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "efs_file_system", Provider: asset.ProviderAWS, Metadata: md}
	}
	tests := []struct {
		name               string
		md                 map[string]string
		notInPlan, autoOff bool
	}{
		{"no plan at all", map[string]string{"automatic_backups": "DISABLED", "in_backup_plan": "false"}, true, false},
		{"covered by another plan", map[string]string{"automatic_backups": "DISABLED", "in_backup_plan": "true"}, false, true},
		{"plans unreadable", map[string]string{"automatic_backups": "DISABLING"}, false, true},
		{"automatic backups on", map[string]string{"automatic_backups": "ENABLED", "in_backup_plan": "true"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.notInPlan, awsEFSNotInBackupPlan.Violates(fs(tt.md)))
			require.Equal(t, tt.autoOff, awsEFSAutomaticBackupsDisabled.Violates(fs(tt.md)))
		})
	}
}

func TestFSxChecksGradeOnlyTheirFileSystemType(t *testing.T) {
	fs := func(typ, deploy string) asset.Asset {
		return asset.Asset{Type: "fsx_file_system", Provider: asset.ProviderAWS, Metadata: map[string]string{
			"file_system_type": typ, "deployment_type": deploy, "copy_tags_to_backups": "false", "copy_tags_to_volumes": "false",
		}}
	}
	singleAZ := []Check{awsFSxOpenZFSSingleAZ, awsFSxONTAPSingleAZ, awsFSxWindowsSingleAZ}
	for _, a := range []asset.Asset{fs("LUSTRE", "PERSISTENT_1"), fs("ONTAP", "MULTI_AZ_1"), fs("OPENZFS", "MULTI_AZ_1"), fs("WINDOWS", "MULTI_AZ_1")} {
		for _, c := range singleAZ {
			require.Falsef(t, c.Violates(a), "%s on %s %s", c.ID, a.Metadata["file_system_type"], a.Metadata["deployment_type"])
		}
	}
	require.True(t, awsFSxONTAPSingleAZ.Violates(fs("ONTAP", "SINGLE_AZ_1")))
	require.False(t, awsFSxOpenZFSSingleAZ.Violates(fs("ONTAP", "SINGLE_AZ_1")))
	require.False(t, awsFSxLustreNoCopyTags.Violates(fs("LUSTRE", "SCRATCH_2")), "scratch file systems cannot be backed up")
	require.False(t, awsFSxOpenZFSNoCopyTags.Violates(fs("WINDOWS", "SINGLE_AZ_1")))
}

func TestStorageServiceChecksDecideOnlyWhatTheySaw(t *testing.T) {
	r := NewRegistry()
	r.Register(awsStorageServiceChecks()...)
	for _, id := range []string{"aws-efs-policy-public", "aws-backup-vault-policy-public", "aws-dynamodb-table-policy-public"} {
		c, ok := r.ByID(id)
		require.True(t, ok)
		a := asset.Asset{Type: c.AssetType, Provider: asset.ProviderAWS, Metadata: map[string]string{}}
		require.Falsef(t, c.Evaluable(a), "%s: an unread policy must not close an open finding", id)
	}
	c, _ := r.ByID("aws-backup-no-plan")
	require.False(t, c.Evaluable(asset.Asset{Type: c.AssetType, Provider: asset.ProviderAWS, Metadata: map[string]string{"recovery_points": "4"}}))
	c, _ = r.ByID("aws-dynamodb-no-autoscaling")
	require.True(t, c.Evaluable(asset.Asset{Type: c.AssetType, Provider: asset.ProviderAWS, Metadata: map[string]string{"billing_mode": "PAY_PER_REQUEST"}}),
		"an on-demand table needs no scaling targets")
}
