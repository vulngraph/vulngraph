package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// S3 access points (FSBP S3.19), Multi-Region Access Points (S3.24) and
// directory buckets (S3.25). Access points and directory buckets are
// regional; Multi-Region Access Points are an account-global listing served
// only from us-west-2 and are read with the rest of S3 (collectS3).

type s3AccessPointAPI interface {
	ListAccessPoints(context.Context, *s3control.ListAccessPointsInput, ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error)
	GetAccessPoint(context.Context, *s3control.GetAccessPointInput, ...func(*s3control.Options)) (*s3control.GetAccessPointOutput, error)
	GetAccessPointPolicyStatus(context.Context, *s3control.GetAccessPointPolicyStatusInput, ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyStatusOutput, error)
}

func collectS3AccessPoints(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	if accountID == "" {
		return nil, nil // s3control addresses every call by account
	}
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectS3AccessPoints: %w", err)
	}
	return listS3AccessPoints(ctx, s3control.NewFromConfig(awsCfg), region, accountID, now)
}

func listS3AccessPoints(ctx context.Context, client s3AccessPointAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		aps  []s3controltypes.AccessPoint
		next *string
	)
	for {
		out, err := client.ListAccessPoints(ctx, &s3control.ListAccessPointsInput{AccountId: awssdk.String(accountID), NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listS3AccessPoints: %w", err)
		}
		aps = append(aps, out.AccessPointList...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		next = out.NextToken
	}

	metas := make([]map[string]string, len(aps))
	eachBounded(ctx, len(aps), eachBoundedTimeout, "s3:GetAccessPoint", func(ctx context.Context, i int) {
		metas[i] = s3AccessPointFacts(ctx, client, accountID, awssdk.ToString(aps[i].Name))
	})

	assets := make([]asset.Asset, 0, len(aps))
	unread := 0
	for i, ap := range aps {
		meta := metas[i]
		if meta == nil {
			unread++
			meta = map[string]string{}
		}
		meta["bucket"] = awssdk.ToString(ap.Bucket)
		meta["network_origin"] = string(ap.NetworkOrigin)
		assets = append(assets, asset.Asset{
			ID:           awssdk.ToString(ap.AccessPointArn),
			Name:         awssdk.ToString(ap.Name),
			Type:         "s3_access_point",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	if unread > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("access_points", len(aps)).Int("unread", unread).
			Msg("s3: GetAccessPoint failed for some access points (check s3:GetAccessPoint); their Block Public Access is unknown this sweep")
	}
	return assets, nil
}

// s3AccessPointFacts reads one access point's own Block Public Access and,
// best-effort, whether its policy is public. nil when GetAccessPoint failed.
func s3AccessPointFacts(ctx context.Context, client s3AccessPointAPI, accountID, name string) map[string]string {
	out, err := client.GetAccessPoint(ctx, &s3control.GetAccessPointInput{AccountId: awssdk.String(accountID), Name: awssdk.String(name)})
	if err != nil || out == nil {
		return nil
	}
	meta := map[string]string{"bpa_all_enabled": strconv.FormatBool(s3ControlBlockAll(out.PublicAccessBlockConfiguration))}
	ps, err := client.GetAccessPointPolicyStatus(ctx, &s3control.GetAccessPointPolicyStatusInput{AccountId: awssdk.String(accountID), Name: awssdk.String(name)})
	switch {
	case err == nil && ps != nil && ps.PolicyStatus != nil:
		meta["policy_public"] = strconv.FormatBool(ps.PolicyStatus.IsPublic)
	case err != nil && awsErrCode(err) == "NoSuchAccessPointPolicy":
		meta["policy_public"] = "false"
	}
	return meta
}

// s3ControlBlockAll reports all four Block Public Access flags on. A missing
// configuration blocks nothing.
func s3ControlBlockAll(c *s3controltypes.PublicAccessBlockConfiguration) bool {
	return c != nil && awssdk.ToBool(c.BlockPublicAcls) && awssdk.ToBool(c.IgnorePublicAcls) &&
		awssdk.ToBool(c.BlockPublicPolicy) && awssdk.ToBool(c.RestrictPublicBuckets)
}

// ── Multi-Region Access Points ───────────────────────────────────────────────

type s3MRAPAPI interface {
	ListMultiRegionAccessPoints(context.Context, *s3control.ListMultiRegionAccessPointsInput, ...func(*s3control.Options)) (*s3control.ListMultiRegionAccessPointsOutput, error)
}

// mrapControlRegion is the only region that serves the Multi-Region Access
// Point control API; the feature exists in the commercial partition only.
const mrapControlRegion = "us-west-2"

// listMultiRegionAccessPoints emits the account's Multi-Region Access Points
// with their Block Public Access, which is fixed at creation. A connector
// outside the commercial partition has none to list.
func listMultiRegionAccessPoints(ctx context.Context, client s3MRAPAPI, partition, accountID string, now time.Time) ([]asset.Asset, error) {
	if partition != "aws" || accountID == "" {
		return nil, nil
	}
	retarget := func(o *s3control.Options) { o.Region = mrapControlRegion }
	var (
		assets []asset.Asset
		next   *string
	)
	for {
		out, err := client.ListMultiRegionAccessPoints(ctx, &s3control.ListMultiRegionAccessPointsInput{AccountId: awssdk.String(accountID), NextToken: next}, retarget)
		if err != nil {
			return nil, fmt.Errorf("listMultiRegionAccessPoints: %w", err)
		}
		for _, ap := range out.AccessPoints {
			alias := awssdk.ToString(ap.Alias)
			regions := make([]string, 0, len(ap.Regions))
			for _, r := range ap.Regions {
				regions = append(regions, awssdk.ToString(r.Region))
			}
			assets = append(assets, asset.Asset{
				ID:        fmt.Sprintf("arn:aws:s3::%s:accesspoint/%s", accountID, alias),
				Name:      awssdk.ToString(ap.Name),
				Type:      "s3_multi_region_access_point",
				Provider:  asset.ProviderAWS,
				AccountID: accountID,
				Metadata: map[string]string{
					"bpa_all_enabled": strconv.FormatBool(s3ControlBlockAll(ap.PublicAccessBlock)),
					"status":          string(ap.Status),
					"regions":         strings.Join(regions, ","),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return assets, nil
		}
		next = out.NextToken
	}
}

// ── Directory buckets ────────────────────────────────────────────────────────

type s3DirectoryBucketAPI interface {
	ListDirectoryBuckets(context.Context, *s3.ListDirectoryBucketsInput, ...func(*s3.Options)) (*s3.ListDirectoryBucketsOutput, error)
	GetBucketLifecycleConfiguration(context.Context, *s3.GetBucketLifecycleConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
}

func collectS3DirectoryBuckets(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectS3DirectoryBuckets: %w", err)
	}
	return listS3DirectoryBuckets(ctx, s3.NewFromConfig(awsCfg), region, accountID, now)
}

// listS3DirectoryBuckets emits the region's S3 Express One Zone directory
// buckets and their enabled lifecycle rule count. The lifecycle read needs
// s3express:GetLifecycleConfiguration, which the managed read-only policies
// do not grant; without it the count is absent (unknown), never zero.
func listS3DirectoryBuckets(ctx context.Context, client s3DirectoryBucketAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		buckets []s3types.Bucket
		token   *string
	)
	for {
		out, err := client.ListDirectoryBuckets(ctx, &s3.ListDirectoryBucketsInput{ContinuationToken: token})
		if err != nil {
			return nil, fmt.Errorf("listS3DirectoryBuckets: %w", err)
		}
		buckets = append(buckets, out.Buckets...)
		if out.ContinuationToken == nil || *out.ContinuationToken == "" {
			break
		}
		token = out.ContinuationToken
	}

	rules := make([]string, len(buckets))
	eachBounded(ctx, len(buckets), eachBoundedTimeout, "s3express:GetLifecycleConfiguration", func(ctx context.Context, i int) {
		if n, ok := lifecycleRuleCount(client.GetBucketLifecycleConfiguration(ctx,
			&s3.GetBucketLifecycleConfigurationInput{Bucket: buckets[i].Name})); ok {
			rules[i] = n
		}
	})

	assets := make([]asset.Asset, 0, len(buckets))
	unread := 0
	for i, b := range buckets {
		name := awssdk.ToString(b.Name)
		meta := map[string]string{}
		if rules[i] != "" {
			meta["lifecycle_rules_enabled"] = rules[i]
		} else {
			unread++
		}
		id := awssdk.ToString(b.BucketArn)
		if id == "" {
			id = fmt.Sprintf("arn:%s:s3express:%s:%s:bucket/%s", partitionFor(region), region, accountID, name)
		}
		assets = append(assets, asset.Asset{
			ID:           id,
			Name:         name,
			Type:         "s3_directory_bucket",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	if unread > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("directory_buckets", len(buckets)).Int("unread", unread).
			Msg("s3: directory bucket lifecycle unreadable (check s3express:GetLifecycleConfiguration); lifecycle coverage unknown this sweep")
	}
	return assets, nil
}
