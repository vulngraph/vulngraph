package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fsxAPI interface {
	DescribeFileSystems(context.Context, *fsx.DescribeFileSystemsInput, ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error)
}

func collectFSx(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectFSx: %w", err)
	}
	return collectFSxFileSystems(ctx, fsx.NewFromConfig(awsCfg), region, accountID, now)
}

// collectFSxFileSystems emits every FSx file system with the per-type
// deployment and tag-copy settings FSBP FSx.1-5 grade. Everything comes from
// the one listing; the ONTAP admin password it carries is never read.
func collectFSxFileSystems(ctx context.Context, client fsxAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		next   *string
	)
	for {
		page, err := client.DescribeFileSystems(ctx, &fsx.DescribeFileSystemsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectFSxFileSystems: %w", err)
		}
		for _, fs := range page.FileSystems {
			id := awssdk.ToString(fs.FileSystemId)
			assets = append(assets, asset.Asset{
				ID:           awssdk.ToString(fs.ResourceARN),
				Name:         fsxName(fs.Tags, id),
				Type:         "fsx_file_system",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Tags:         fsxTagMap(fs.Tags),
				Metadata:     fsxMetadata(fs),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			return assets, nil
		}
		next = page.NextToken
	}
}

// fsxMetadata reads the type-specific configuration. A configuration block
// absent from the response leaves its keys absent; inside a present block
// an omitted CopyTags* is the API default, false.
func fsxMetadata(fs fsxtypes.FileSystem) map[string]string {
	meta := map[string]string{
		"file_system_id":   awssdk.ToString(fs.FileSystemId),
		"file_system_type": string(fs.FileSystemType),
		"lifecycle":        string(fs.Lifecycle),
	}
	switch {
	case fs.FileSystemType == fsxtypes.FileSystemTypeOpenzfs && fs.OpenZFSConfiguration != nil:
		c := fs.OpenZFSConfiguration
		meta["deployment_type"] = string(c.DeploymentType)
		meta["copy_tags_to_backups"] = strconv.FormatBool(awssdk.ToBool(c.CopyTagsToBackups))
		meta["copy_tags_to_volumes"] = strconv.FormatBool(awssdk.ToBool(c.CopyTagsToVolumes))
	case fs.FileSystemType == fsxtypes.FileSystemTypeLustre && fs.LustreConfiguration != nil:
		c := fs.LustreConfiguration
		meta["deployment_type"] = string(c.DeploymentType)
		meta["copy_tags_to_backups"] = strconv.FormatBool(awssdk.ToBool(c.CopyTagsToBackups))
	case fs.FileSystemType == fsxtypes.FileSystemTypeOntap && fs.OntapConfiguration != nil:
		meta["deployment_type"] = string(fs.OntapConfiguration.DeploymentType)
	case fs.FileSystemType == fsxtypes.FileSystemTypeWindows && fs.WindowsConfiguration != nil:
		c := fs.WindowsConfiguration
		meta["deployment_type"] = string(c.DeploymentType)
		meta["copy_tags_to_backups"] = strconv.FormatBool(awssdk.ToBool(c.CopyTagsToBackups))
	}
	return meta
}

func fsxTagMap(tags []fsxtypes.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		m[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return m
}

func fsxName(tags []fsxtypes.Tag, fallback string) string {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == "Name" && awssdk.ToString(t.Value) != "" {
			return awssdk.ToString(t.Value)
		}
	}
	return fallback
}
