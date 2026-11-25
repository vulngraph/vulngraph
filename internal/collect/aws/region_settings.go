package aws

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// regionSettingsType is the per-region counterpart of aws_account_settings:
// EC2 account settings that AWS scopes to a region (EBS encryption by default,
// snapshot and VPC Block Public Access) and the SSM service settings for
// document public sharing and Automation logging, one asset per account-region
// so each is one finding, not one per volume, snapshot, VPC or document.
const regionSettingsType = "aws_region_settings"

type regionSettingsAPI interface {
	GetEbsEncryptionByDefault(context.Context, *ec2.GetEbsEncryptionByDefaultInput, ...func(*ec2.Options)) (*ec2.GetEbsEncryptionByDefaultOutput, error)
	GetSnapshotBlockPublicAccessState(context.Context, *ec2.GetSnapshotBlockPublicAccessStateInput, ...func(*ec2.Options)) (*ec2.GetSnapshotBlockPublicAccessStateOutput, error)
	DescribeVpcBlockPublicAccessOptions(context.Context, *ec2.DescribeVpcBlockPublicAccessOptionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcBlockPublicAccessOptionsOutput, error)
}

func collectRegionSettings(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectRegionSettings: %w", err)
	}
	return readRegionSettings(ctx, ec2.NewFromConfig(awsCfg), region, accountID, now,
		newDetectionClients(awsCfg).read, ssmServiceSettingsReader(ssm.NewFromConfig(awsCfg)))
}

// readRegionSettings reads the three EC2 settings and every extra reader
// (the detection services, region_detection.go; the SSM service settings,
// ssm_documents.go); a failed read leaves its
// keys absent. The asset is emitted when any read succeeded — a key-less
// asset would carry nothing — and the call errors only when all failed, so a
// region closed to the connector is still recognised as denied.
func readRegionSettings(ctx context.Context, client regionSettingsAPI, region, accountID string, now time.Time,
	extra ...func(context.Context) (map[string]string, []error),
) ([]asset.Asset, error) {
	meta := map[string]string{}
	var errs []error
	for _, read := range extra {
		kv, e := read(ctx)
		maps.Copy(meta, kv)
		errs = append(errs, e...)
	}
	if out, err := client.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{}); err == nil && out != nil && out.EbsEncryptionByDefault != nil {
		meta["ebs_encryption_by_default"] = strconv.FormatBool(awssdk.ToBool(out.EbsEncryptionByDefault))
	} else {
		errs = append(errs, fmt.Errorf("GetEbsEncryptionByDefault: %w", orEmpty(err)))
	}
	if out, err := client.GetSnapshotBlockPublicAccessState(ctx, &ec2.GetSnapshotBlockPublicAccessStateInput{}); err == nil && out != nil && out.State != "" {
		meta["snapshot_block_public_access"] = string(out.State)
	} else {
		errs = append(errs, fmt.Errorf("GetSnapshotBlockPublicAccessState: %w", orEmpty(err)))
	}
	if out, err := client.DescribeVpcBlockPublicAccessOptions(ctx, &ec2.DescribeVpcBlockPublicAccessOptionsInput{}); err == nil && out != nil &&
		out.VpcBlockPublicAccessOptions != nil && out.VpcBlockPublicAccessOptions.InternetGatewayBlockMode != "" {
		meta["vpc_block_public_access"] = string(out.VpcBlockPublicAccessOptions.InternetGatewayBlockMode)
	} else {
		errs = append(errs, fmt.Errorf("DescribeVpcBlockPublicAccessOptions: %w", orEmpty(err)))
	}
	if len(meta) == 0 {
		return nil, fmt.Errorf("readRegionSettings: %w", errors.Join(errs...))
	}
	if len(errs) > 0 {
		log.FromContext(ctx).Warn().Err(errors.Join(errs...)).Str("region", region).
			Msg("aws region settings read failed; its checks cannot evaluate this region this sweep (permissions: docs/iam/aws-account-settings-permissions.md, docs/iam/aws-logging-detection-permissions.md)")
	}
	return []asset.Asset{{
		ID:           "aws:" + accountID + ":" + region + ":region-settings",
		Name:         "Region settings (" + region + ")",
		Type:         regionSettingsType,
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}}, nil
}

// errEmptyResponse stands in for a nil error on a response that carried no
// answer, so the all-failed error still says why.
var errEmptyResponse = errors.New("empty response")

func orEmpty(err error) error {
	if err == nil {
		return errEmptyResponse
	}
	return err
}
