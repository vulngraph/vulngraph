package checks

// aws_efs_fsx.go — Amazon EFS and Amazon FSx posture (AWS FSBP EFS.1/2/3/4/
// 7/8, FSx.1-5; CIS AWS 3.3.1). Encryption and file-system policy exposure
// carry real severity; backups, Multi-AZ and tag copying are Low/Info
// resilience hygiene.

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// awsStorageServiceChecks registers every EFS, FSx, AWS Backup, DynamoDB and
// DAX check.
func awsStorageServiceChecks() []Check {
	return []Check{
		awsEFSNotEncrypted,
		awsEFSPolicyPublic,
		awsEFSNotInBackupPlan,
		awsEFSAutomaticBackupsDisabled,
		awsEFSAccessPointRootDirectory,
		awsEFSAccessPointNoUserIdentity,
		awsFSxOpenZFSNoCopyTags,
		awsFSxLustreNoCopyTags,
		awsFSxOpenZFSSingleAZ,
		awsFSxONTAPSingleAZ,
		awsFSxWindowsSingleAZ,
		awsBackupVaultPolicyPublic,
		awsBackupRecoveryPointsUnencrypted,
		awsBackupVaultNotLocked,
		awsBackupNoPlan,
		awsDynamoDBTablePolicyPublic,
		awsDynamoDBNoAutoScaling,
		awsDynamoDBNoPITR,
		awsDynamoDBNoDeletionProtection,
		awsDAXNotEncryptedAtRest,
		awsDAXNotEncryptedInTransit,
	}
}

var awsEFSNotEncrypted = Check{
	ID:          "aws-efs-not-encrypted",
	Title:       "EFS file system is not encrypted at rest",
	Description: "The file system was created without encryption at rest (Encrypted=false), so its data and metadata are stored in clear on the underlying storage. Encryption can only be chosen at creation. CIS AWS 3.3.1, FSBP EFS.1 and EFS.8 (both test the Encrypted flag).",
	Remediation: "Create an encrypted file system (console: EFS > Create file system > Customize > Enable encryption of data at rest; CLI: `aws efs create-file-system --encrypted --kms-key-id KEY`), copy the data across with AWS DataSync, switch clients to the new mount targets and delete the old file system.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "efs_file_system",
	Violates:    func(a asset.Asset) bool { return a.Metadata["encrypted"] == "false" },
}

var awsEFSPolicyPublic = Check{
	ID:          "aws-efs-policy-public",
	Title:       "EFS file system policy allows any principal to mount it",
	Description: "The file-system policy grants elasticfilesystem:ClientMount, ClientWrite or ClientRootAccess to everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller. Any IAM principal in any account that can reach a mount target — through a peered VPC, a shared subnet, Transit Gateway or VPN — can mount the file system and read or overwrite every file, root access included.",
	Remediation: "Replace Principal \"*\" (or the Allow with NotPrincipal) with the roles that need it (console: EFS > file system > File system policy > Edit; CLI: `aws efs put-file-system-policy --file-system-id FS --policy file://policy.json`), or add an aws:PrincipalOrgID / aws:SourceVpc condition to the statement. Keep mount-target security groups limited to the clients' subnets.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "efs_file_system",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_access"] == asset.PublicAccessConfirmed },
	// The tier constant lives outside this package, so the key derivation
	// cannot harvest it as a probe; without it an unread policy would read as
	// evaluated-clean and close an open finding.
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsEFSNotInBackupPlan = Check{
	ID:          "aws-efs-not-in-backup-plan",
	Title:       "EFS file system is not in any AWS Backup plan",
	Description: "Automatic backups are off and no AWS Backup plan's resource assignment selects this file system (resource ARNs and wildcards, NotResources, tag conditions and the region's EFS opt-in were all evaluated). A deleted directory, a bad deploy or ransomware on a client is unrecoverable. FSBP EFS.2.",
	Remediation: "Turn on automatic backups (console: EFS > file system > Edit > Automatic backups; CLI: `aws efs put-backup-policy --file-system-id FS --backup-policy Status=ENABLED`) or add the file system to a plan (`aws backup create-backup-selection --backup-plan-id PLAN --backup-selection file://selection.json`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "efs_file_system",
	Violates:    func(a asset.Asset) bool { return a.Metadata["in_backup_plan"] == "false" },
}

// efsAutomaticBackupsOff reads the backup-policy status the collector wrote.
func efsAutomaticBackupsOff(a asset.Asset) bool {
	switch a.Metadata["automatic_backups"] {
	case "DISABLED", "DISABLING":
		return true
	}
	return false
}

var awsEFSAutomaticBackupsDisabled = Check{
	ID:          "aws-efs-automatic-backups-disabled",
	Title:       "EFS automatic backups are disabled",
	Description: "The file system's automatic daily backups (the AWS Backup default plan for EFS) are off. FSBP EFS.7. Informational when another backup plan already selects the file system; a file system no plan covers is reported by aws-efs-not-in-backup-plan instead.",
	Remediation: "Console: EFS > file system > Edit > Automatic backups > Enabled. CLI: `aws efs put-backup-policy --file-system-id FS --backup-policy Status=ENABLED`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "efs_file_system",
	Violates: func(a asset.Asset) bool {
		// Steps aside when no plan covers it: one root cause, one finding.
		return efsAutomaticBackupsOff(a) && a.Metadata["in_backup_plan"] != "false"
	},
}

var awsEFSAccessPointRootDirectory = Check{
	ID:          "aws-efs-access-point-root-directory",
	Title:       "EFS access point exposes the file system root",
	Description: "The access point's root directory is \"/\", so every client that mounts through it sees the whole file system rather than the application's own subdirectory. FSBP EFS.3.",
	Remediation: "Access points are immutable: create one with a dedicated root (console: EFS > Access points > Create, Root directory path /app; CLI: `aws efs create-access-point --file-system-id FS --root-directory Path=/app,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=750}`), move clients to it and delete the old one.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "efs_access_point",
	Violates:    func(a asset.Asset) bool { return a.Metadata["root_directory"] == "/" },
}

var awsEFSAccessPointNoUserIdentity = Check{
	ID:          "aws-efs-access-point-no-user-identity",
	Title:       "EFS access point does not enforce a POSIX user",
	Description: "The access point defines no POSIX user, so NFS clients act as whatever uid/gid they claim — including root — instead of one identity the access point imposes. FSBP EFS.4.",
	Remediation: "Access points are immutable: create one with a POSIX user (console: EFS > Access points > Create > POSIX user; CLI: `aws efs create-access-point --file-system-id FS --posix-user Uid=1000,Gid=1000`), move clients to it and delete the old one.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "efs_access_point",
	Violates:    func(a asset.Asset) bool { return a.Metadata["posix_user_enforced"] == "false" },
}

// fsxType reports whether an FSx file system is of the given type.
func fsxType(a asset.Asset, t string) bool { return a.Metadata["file_system_type"] == t }

var awsFSxOpenZFSNoCopyTags = Check{
	ID:          "aws-fsx-openzfs-no-copy-tags",
	Title:       "FSx for OpenZFS does not copy tags to backups and volumes",
	Description: "The OpenZFS file system does not copy its tags to backups and to new volumes, so those lose the ownership and classification tags that tag-based access control and retention rely on. FSBP FSx.1.",
	Remediation: "Console: FSx > file system > Update > Copy tags to backups / Copy tags to volumes. CLI: `aws fsx update-file-system --file-system-id FS --open-zfs-configuration CopyTagsToBackups=true,CopyTagsToVolumes=true`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "fsx_file_system",
	Violates: func(a asset.Asset) bool {
		return fsxType(a, "OPENZFS") &&
			(a.Metadata["copy_tags_to_backups"] == "false" || a.Metadata["copy_tags_to_volumes"] == "false")
	},
}

var awsFSxLustreNoCopyTags = Check{
	ID:          "aws-fsx-lustre-no-copy-tags",
	Title:       "FSx for Lustre does not copy tags to backups",
	Description: "The persistent Lustre file system does not copy its tags to backups, so backups lose the ownership and classification tags that tag-based access control and retention rely on. Scratch deployments are not graded: they cannot be backed up. FSBP FSx.2.",
	Remediation: "CLI: `aws fsx update-file-system --file-system-id FS --lustre-configuration CopyTagsToBackups=true` (console: FSx > file system > Update).",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "fsx_file_system",
	Violates: func(a asset.Asset) bool {
		return fsxType(a, "LUSTRE") && a.Metadata["copy_tags_to_backups"] == "false" &&
			strings.HasPrefix(a.Metadata["deployment_type"], "PERSISTENT")
	},
}

var awsFSxOpenZFSSingleAZ = Check{
	ID:          "aws-fsx-openzfs-single-az",
	Title:       "FSx for OpenZFS is not deployed Multi-AZ",
	Description: "The OpenZFS file system uses a Single-AZ deployment type, so an Availability Zone outage takes it offline. FSBP FSx.3 (MULTI_AZ_1 required).",
	Remediation: "The deployment type is fixed at creation: create a MULTI_AZ_1 file system (console: FSx > Create file system > OpenZFS > Multi-AZ; CLI: `aws fsx create-file-system --file-system-type OPENZFS --open-zfs-configuration DeploymentType=MULTI_AZ_1,...`) and restore from a backup.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "fsx_file_system",
	Violates: func(a asset.Asset) bool {
		d := a.Metadata["deployment_type"]
		return fsxType(a, "OPENZFS") && d != "" && d != "MULTI_AZ_1"
	},
}

var awsFSxONTAPSingleAZ = Check{
	ID:          "aws-fsx-ontap-single-az",
	Title:       "FSx for NetApp ONTAP is not deployed Multi-AZ",
	Description: "The ONTAP file system uses a Single-AZ deployment type, so an Availability Zone outage takes it offline. FSBP FSx.4 (MULTI_AZ_1 or MULTI_AZ_2).",
	Remediation: "The deployment type is fixed at creation: create a MULTI_AZ_2 file system (CLI: `aws fsx create-file-system --file-system-type ONTAP --ontap-configuration DeploymentType=MULTI_AZ_2,...`) and replicate the volumes across with SnapMirror.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "fsx_file_system",
	Violates: func(a asset.Asset) bool {
		d := a.Metadata["deployment_type"]
		return fsxType(a, "ONTAP") && d != "" && !strings.HasPrefix(d, "MULTI_AZ_")
	},
}

var awsFSxWindowsSingleAZ = Check{
	ID:          "aws-fsx-windows-single-az",
	Title:       "FSx for Windows File Server is not deployed Multi-AZ",
	Description: "The Windows file system uses a Single-AZ deployment type, so an Availability Zone outage takes the shares offline. FSBP FSx.5 (MULTI_AZ_1 required).",
	Remediation: "The deployment type is fixed at creation: create a MULTI_AZ_1 file system (CLI: `aws fsx create-file-system --file-system-type WINDOWS --windows-configuration DeploymentType=MULTI_AZ_1,...`) and restore from a backup.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "fsx_file_system",
	Violates: func(a asset.Asset) bool {
		d := a.Metadata["deployment_type"]
		return fsxType(a, "WINDOWS") && d != "" && d != "MULTI_AZ_1"
	},
}
