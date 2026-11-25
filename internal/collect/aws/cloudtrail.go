package aws

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectCloudTrail lists all CloudTrail trails in an account and maps them to
// assets. A trail that is not logging, not multi-region, or lacks log-file
// validation is a compliance gap and audit-control failure.
func collectCloudTrail(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectCloudTrail: %w", err)
	}
	return collectCloudTrailTrails(ctx, cloudtrail.NewFromConfig(awsCfg), region, accountID, now)
}

type cloudtrailAPI interface {
	DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
	GetEventSelectors(context.Context, *cloudtrail.GetEventSelectorsInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error)
}

func collectCloudTrailTrails(ctx context.Context, client cloudtrailAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	// IncludeShadowTrails=true also returns the multi-region and organization
	// trails homed in OTHER regions (their "shadows" here). With false, only
	// trails whose home is the connector's base region come back, so an account
	// whose multi-region trail lives elsewhere would look like it had no trail.
	out, err := client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{
		IncludeShadowTrails: awssdk.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("collectCloudTrailTrails: %w", err)
	}

	var assets []asset.Asset
	seen := map[string]bool{}
	for _, trail := range out.TrailList {
		arn := awssdk.ToString(trail.TrailARN)
		name := awssdk.ToString(trail.Name)
		// A trail can be listed once per region it shadows into; it is one
		// trail, keyed by ARN.
		if arn == "" || seen[arn] {
			continue
		}
		seen[arn] = true

		meta := map[string]string{
			"multi_region":        fmt.Sprintf("%t", awssdk.ToBool(trail.IsMultiRegionTrail)),
			"log_file_validation": fmt.Sprintf("%t", awssdk.ToBool(trail.LogFileValidationEnabled)),
			"is_organization":     fmt.Sprintf("%t", awssdk.ToBool(trail.IsOrganizationTrail)),
			"s3_bucket":           awssdk.ToString(trail.S3BucketName),
			"home_region":         awssdk.ToString(trail.HomeRegion),
			// Both come from the DescribeTrails answer itself, so empty is an
			// observation (not configured), never an unread setting.
			"cloudwatch_log_group": awssdk.ToString(trail.CloudWatchLogsLogGroupArn),
			"kms_key_id":           awssdk.ToString(trail.KmsKeyId),
		}

		// Logging status is authoritative only in the trail's home region, so
		// the call is retargeted there. On error is_logging stays absent
		// (unknown), never "false".
		status, err := client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: trail.TrailARN},
			homeRegionOpt(awssdk.ToString(trail.HomeRegion)))
		if err == nil && status != nil {
			meta["is_logging"] = fmt.Sprintf("%t", awssdk.ToBool(status.IsLogging))
			if status.LatestDeliveryTime != nil {
				meta["latest_delivery"] = status.LatestDeliveryTime.UTC().Format(time.RFC3339)
			}
			if status.LatestDeliveryError != nil {
				meta["delivery_error"] = awssdk.ToString(status.LatestDeliveryError)
			}
		}

		// What the trail records (cloudtrail_selectors.go), also read in the home
		// region. On error both keys stay absent: an unread selector set is not
		// a trail that records nothing.
		if sel, err := client.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: trail.TrailARN},
			homeRegionOpt(awssdk.ToString(trail.HomeRegion))); err == nil && sel != nil {
			maps.Copy(meta, eventSelectorMeta(sel))
		}

		// Shorten the trail name for display — keep the last segment of ARN or
		// the name itself.
		displayName := name
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			displayName = name[idx+1:]
		}

		assets = append(assets, asset.Asset{
			ID:           arn,
			Name:         displayName,
			Type:         "aws_cloudtrail",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

// homeRegionOpt retargets one CloudTrail call at the trail's home region (no-op
// when the home region is unknown).
func homeRegionOpt(home string) func(*cloudtrail.Options) {
	return func(o *cloudtrail.Options) {
		if home != "" {
			o.Region = home
		}
	}
}
