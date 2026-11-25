package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// efsSensitiveActions are the file-system policy actions that let a principal
// mount the file system and read, write or act as root on it.
var efsSensitiveActions = []string{
	"elasticfilesystem:clientmount", "elasticfilesystem:clientwrite", "elasticfilesystem:clientrootaccess",
}

type efsAPI interface {
	DescribeFileSystems(context.Context, *efs.DescribeFileSystemsInput, ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
	DescribeAccessPoints(context.Context, *efs.DescribeAccessPointsInput, ...func(*efs.Options)) (*efs.DescribeAccessPointsOutput, error)
	// DescribeBackupPolicy and DescribeFileSystemPolicy answer "none set"
	// with PolicyNotFound, an observation rather than a failed read.
	DescribeBackupPolicy(context.Context, *efs.DescribeBackupPolicyInput, ...func(*efs.Options)) (*efs.DescribeBackupPolicyOutput, error)
	DescribeFileSystemPolicy(context.Context, *efs.DescribeFileSystemPolicyInput, ...func(*efs.Options)) (*efs.DescribeFileSystemPolicyOutput, error)
}

func collectEFS(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectEFS: %w", err)
	}
	return collectEFSFileSystems(ctx, efs.NewFromConfig(awsCfg), backup.NewFromConfig(awsCfg), region, accountID, now)
}

// collectEFSFileSystems emits the region's EFS file systems and access points.
// Backup-plan coverage (FSBP EFS.2) is read from AWS Backup only when the
// region has a file system, and only stamped when it can be decided.
func collectEFSFileSystems(ctx context.Context, client efsAPI, plans backupPlanAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	fss, err := listEFSFileSystems(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("collectEFSFileSystems: %w", err)
	}
	points, err := listEFSAccessPoints(ctx, client, region, accountID, now)
	if err != nil {
		return nil, fmt.Errorf("collectEFSFileSystems: %w", err)
	}
	metas := make([]map[string]string, len(fss))
	var backupFailed, policyFailed atomic.Int32
	eachBounded(ctx, len(fss), eachBoundedTimeout, "efs", func(ctx context.Context, i int) {
		metas[i] = efsMetadata(fss[i])
		id := fss[i].FileSystemId
		var notFound *efstypes.PolicyNotFound
		switch bp, err := client.DescribeBackupPolicy(ctx, &efs.DescribeBackupPolicyInput{FileSystemId: id}); {
		case err == nil && bp.BackupPolicy != nil:
			metas[i]["automatic_backups"] = string(bp.BackupPolicy.Status)
		case errors.As(err, &notFound):
			metas[i]["automatic_backups"] = string(efstypes.StatusDisabled)
		default:
			backupFailed.Add(1)
		}
		switch pol, err := client.DescribeFileSystemPolicy(ctx, &efs.DescribeFileSystemPolicyInput{FileSystemId: id}); {
		case err == nil:
			pub, policies := resourcePolicyMetadata(awssdk.ToString(pol.Policy), awssdk.ToString(id)+"-resource", efsSensitiveActions)
			metas[i]["public_access"] = pub
			if policies != "" {
				metas[i]["policies"] = policies
			}
		case errors.As(err, &notFound):
			// No policy: access is whatever the mount targets' network reach
			// allows — not an internet grant.
			metas[i]["public_access"] = asset.PublicAccessNone
		default:
			policyFailed.Add(1)
		}
	})
	if n := backupFailed.Load(); n > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int32("file_systems", n).
			Msg("efs: backup policy unreadable (check elasticfilesystem:DescribeBackupPolicy); automatic backups unknown for those file systems")
	}
	if n := policyFailed.Load(); n > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int32("file_systems", n).
			Msg("efs: file system policy unreadable (check elasticfilesystem:DescribeFileSystemPolicy); public grant unknown for those file systems")
	}
	if len(fss) > 0 {
		stampEFSBackupPlanCoverage(ctx, plans, fss, metas, region)
	}

	assets := make([]asset.Asset, 0, len(fss)+len(points))
	for i, fs := range fss {
		id := awssdk.ToString(fs.FileSystemId)
		assets = append(assets, asset.Asset{
			ID:           awssdk.ToString(fs.FileSystemArn),
			Name:         efsName(fs, id),
			Type:         "efs_file_system",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Tags:         efsTagMap(fs.Tags),
			Metadata:     metas[i],
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return append(assets, points...), nil
}

func listEFSFileSystems(ctx context.Context, client efsAPI) ([]efstypes.FileSystemDescription, error) {
	var (
		out    []efstypes.FileSystemDescription
		marker *string
	)
	for {
		page, err := client.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listEFSFileSystems: %w", err)
		}
		out = append(out, page.FileSystems...)
		if page.NextMarker == nil {
			return out, nil
		}
		marker = page.NextMarker
	}
}

func efsMetadata(fs efstypes.FileSystemDescription) map[string]string {
	meta := map[string]string{
		"file_system_id": awssdk.ToString(fs.FileSystemId),
		"lifecycle":      string(fs.LifeCycleState),
	}
	// Encrypted is part of every DescribeFileSystems entry; a nil pointer is
	// a response that did not say, which is unknown rather than unencrypted.
	if fs.Encrypted != nil {
		meta["encrypted"] = strconv.FormatBool(*fs.Encrypted)
	}
	if k := awssdk.ToString(fs.KmsKeyId); k != "" {
		meta["kms_key_id"] = k
	}
	return meta
}

// stampEFSBackupPlanCoverage writes in_backup_plan: true when automatic
// backups are on (that IS an AWS Backup plan) or a plan's resource assignment
// selects the file system; false only when automatic backups were read off
// and every assignment was read and decidably excludes it.
func stampEFSBackupPlanCoverage(ctx context.Context, plans backupPlanAPI, fss []efstypes.FileSystemDescription, metas []map[string]string, region string) {
	cov, err := readBackupPlanCoverage(ctx, plans)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("region", region).
			Msg("efs: backup plans unreadable (check backup:ListBackupPlans, ListBackupSelections, GetBackupSelection, DescribeRegionSettings); plan coverage known only from automatic backups")
	}
	for i, fs := range fss {
		switch auto, ok := metas[i]["automatic_backups"]; {
		case ok && efsAutomaticBackupsOn(auto):
			metas[i]["in_backup_plan"] = "true"
		case cov == nil:
		default:
			covered, known := cov.covers(awssdk.ToString(fs.FileSystemArn), efsTagMap(fs.Tags), "EFS", "file-system/")
			switch {
			case covered:
				metas[i]["in_backup_plan"] = "true"
			case known && ok:
				metas[i]["in_backup_plan"] = "false"
			}
		}
	}
}

// efsAutomaticBackupsOn reads a backup-policy status; ENABLING is on its way.
func efsAutomaticBackupsOn(status string) bool {
	return status == string(efstypes.StatusEnabled) || status == string(efstypes.StatusEnabling)
}

func listEFSAccessPoints(ctx context.Context, client efsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out  []asset.Asset
		next *string
	)
	for {
		page, err := client.DescribeAccessPoints(ctx, &efs.DescribeAccessPointsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listEFSAccessPoints: %w", err)
		}
		for _, ap := range page.AccessPoints {
			// RootDirectory is omitted when the access point uses the file
			// system's root, the API default "/".
			root := "/"
			if ap.RootDirectory != nil && awssdk.ToString(ap.RootDirectory.Path) != "" {
				root = awssdk.ToString(ap.RootDirectory.Path)
			}
			id := awssdk.ToString(ap.AccessPointId)
			name := awssdk.ToString(ap.Name)
			if name == "" {
				name = id
			}
			out = append(out, asset.Asset{
				ID:        awssdk.ToString(ap.AccessPointArn),
				Name:      name,
				Type:      "efs_access_point",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Tags:      efsTagMap(ap.Tags),
				Metadata: map[string]string{
					"file_system_id":      awssdk.ToString(ap.FileSystemId),
					"root_directory":      root,
					"posix_user_enforced": strconv.FormatBool(ap.PosixUser != nil),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

func efsTagMap(tags []efstypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return m
}

func efsName(fs efstypes.FileSystemDescription, fallback string) string {
	if n := awssdk.ToString(fs.Name); n != "" {
		return n
	}
	return fallback
}
