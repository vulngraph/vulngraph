package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// CloudFront distributions (AWS FSBP CloudFront.1-17). The service is global
// and signed in the partition's home region. ListDistributions' summary
// carries origins, behaviours, the viewer certificate and the web ACL; only
// the default root object and legacy logging need GetDistributionConfig, and
// standard logging v2 lives in CloudWatch Logs deliveries.

const cloudfrontDistributionType = "cloudfront_distribution"

// cloudfrontConcurrency bounds the per-distribution GetDistributionConfig and
// per-bucket HeadBucket fan-out.
const cloudfrontConcurrency = 4

type cloudfrontAPI interface {
	ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
	GetDistributionConfig(context.Context, *cloudfront.GetDistributionConfigInput, ...func(*cloudfront.Options)) (*cloudfront.GetDistributionConfigOutput, error)
}

// cloudfrontLogsAPI reads standard logging (v2): a delivery source names the
// distribution ARN, a delivery attaches the source to a destination.
type cloudfrontLogsAPI interface {
	DescribeDeliverySources(context.Context, *cloudwatchlogs.DescribeDeliverySourcesInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeDeliverySourcesOutput, error)
	DescribeDeliveries(context.Context, *cloudwatchlogs.DescribeDeliveriesInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeDeliveriesOutput, error)
}

// bucketProber answers whether an S3 bucket name exists anywhere in AWS, and
// which buckets this account owns.
type bucketProber interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
}

func collectCloudFront(ctx context.Context, cfg map[string]string, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectCloudFront: %w", err)
	}
	if !cloudFrontPartition(awsCfg.Region) {
		return nil, nil
	}
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	// Path-style keeps HeadBucket on dotted bucket names off a wildcard TLS
	// certificate that cannot match them.
	probe := s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.UsePathStyle = true })
	return readCloudFront(ctx, cloudfront.NewFromConfig(awsCfg), cloudwatchlogs.NewFromConfig(awsCfg), probe, accountID, now)
}

func readCloudFront(ctx context.Context, client cloudfrontAPI, logs cloudfrontLogsAPI, probe bucketProber, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		dists  []cftypes.DistributionSummary
		marker *string
	)
	for {
		out, err := client.ListDistributions(ctx, &cloudfront.ListDistributionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("readCloudFront: ListDistributions: %w", err)
		}
		if out.DistributionList == nil {
			break
		}
		dists = append(dists, out.DistributionList.Items...)
		if !awssdk.ToBool(out.DistributionList.IsTruncated) || out.DistributionList.NextMarker == nil {
			break
		}
		marker = out.DistributionList.NextMarker
	}
	if len(dists) == 0 {
		return nil, nil
	}

	v2Logged, v2Err := cloudfrontV2Logging(ctx, logs)
	if v2Err != nil {
		log.FromContext(ctx).Warn().Err(v2Err).
			Msg("cloudfront standard-logging (v2) deliveries unreadable; logging is unknown for distributions without legacy logging")
	}

	assets := make([]asset.Asset, len(dists))
	buckets := map[string]bucketPresence{}
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, cloudfrontConcurrency)
	)
	for i, d := range dists {
		assets[i] = distributionAsset(d, accountID, now)
		for _, b := range s3OriginBuckets(d) {
			buckets[b] = bucketUnknown
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, id string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("distribution", id).Msg("cloudfront config read panicked")
				}
			}()
			out, err := client.GetDistributionConfig(ctx, &cloudfront.GetDistributionConfigInput{Id: awssdk.String(id)})
			mu.Lock()
			defer mu.Unlock()
			stampDistributionConfig(assets[i].Metadata, assets[i].ID, out, err, v2Logged, v2Err == nil)
			if err != nil {
				log.FromContext(ctx).Warn().Err(err).Str("distribution", id).
					Msg("cloudfront GetDistributionConfig failed; default root object and logging unknown")
			}
		}(i, awssdk.ToString(d.Id))
	}
	// The probes write into buckets, so iterate a snapshot of its keys: ranging
	// over the map itself while they write is a concurrent map read and write.
	names := make([]string, 0, len(buckets))
	for name := range buckets {
		names = append(names, name)
	}
	for _, name := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("bucket", name).Msg("cloudfront origin bucket probe panicked")
				}
			}()
			p := probeBucket(ctx, probe, name)
			mu.Lock()
			buckets[name] = p
			mu.Unlock()
		}(name)
	}
	wg.Wait()
	resolveBucketOwnership(ctx, probe, buckets)
	for i, d := range dists {
		stampMissingBuckets(assets[i].Metadata, d, buckets)
	}
	return assets, nil
}

// resolveBucketOwnership settles the buckets HeadBucket proved exist without
// letting this account read them (403) or that live in another region (301):
// one this account owns is present; one it does not own is someone else's
// bucket behind your distribution — a possible takeover. Ownership comes from
// s3:ListBuckets; if that fails they stay unknown rather than either answer.
func resolveBucketOwnership(ctx context.Context, probe bucketProber, buckets map[string]bucketPresence) {
	needed := false
	for _, p := range buckets {
		needed = needed || p == bucketExistsUnowned
	}
	if !needed {
		return
	}
	owned, err := ownedBuckets(ctx, probe)
	for name, p := range buckets {
		if p != bucketExistsUnowned {
			continue
		}
		switch {
		case err != nil:
			buckets[name] = bucketUnknown
		case owned[name]:
			buckets[name] = bucketPresent
		default:
			buckets[name] = bucketForeign
		}
	}
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("s3 bucket listing failed; ownership of CloudFront origin buckets is unknown this sweep")
	}
}

// ownedBuckets lists every bucket this account owns. Any page error fails it.
func ownedBuckets(ctx context.Context, probe bucketProber) (map[string]bool, error) {
	owned := map[string]bool{}
	var token *string
	for {
		out, err := probe.ListBuckets(ctx, &s3.ListBucketsInput{ContinuationToken: token})
		if err != nil {
			return nil, fmt.Errorf("ownedBuckets: %w", err)
		}
		for _, b := range out.Buckets {
			owned[awssdk.ToString(b.Name)] = true
		}
		if awssdk.ToString(out.ContinuationToken) == "" {
			return owned, nil
		}
		token = out.ContinuationToken
	}
}

// distributionAsset builds the asset from the summary's own fields.
func distributionAsset(d cftypes.DistributionSummary, accountID string, now time.Time) asset.Asset {
	domain := awssdk.ToString(d.DomainName)
	name := domain
	if d.Aliases != nil && len(d.Aliases.Items) > 0 {
		name = d.Aliases.Items[0]
	}
	meta := map[string]string{
		"distribution_id": awssdk.ToString(d.Id),
		"enabled":         strconv.FormatBool(awssdk.ToBool(d.Enabled)),
		// Every distribution answers on its public *.cloudfront.net name.
		"public":                         "true",
		"public_access":                  asset.PublicAccessPossible,
		"web_acl_id":                     awssdk.ToString(d.WebACLId),
		"has_s3_origin":                  strconv.FormatBool(hasS3Origin(d)),
		"viewer_http_behaviors":          strings.Join(viewerHTTPBehaviors(d), ","),
		"trusted_signer_behaviors":       strings.Join(trustedSignerBehaviors(d), ","),
		"custom_origins_unencrypted":     strings.Join(unencryptedCustomOrigins(d), ","),
		"custom_origins_sslv3":           strings.Join(sslv3CustomOrigins(d), ","),
		"lambda_url_origins_without_oac": strings.Join(lambdaURLOriginsWithoutOAC(d), ","),
	}
	if d.OriginGroups != nil {
		meta["origin_group_count"] = strconv.Itoa(int(awssdk.ToInt32(d.OriginGroups.Quantity)))
	}
	if vc := d.ViewerCertificate; vc != nil {
		meta["default_certificate"] = strconv.FormatBool(awssdk.ToBool(vc.CloudFrontDefaultCertificate))
		if vc.SSLSupportMethod != "" {
			meta["ssl_support_method"] = string(vc.SSLSupportMethod)
		}
		if vc.MinimumProtocolVersion != "" {
			meta["minimum_protocol_version"] = string(vc.MinimumProtocolVersion)
		}
	}
	return asset.Asset{
		ID:           awssdk.ToString(d.ARN),
		Name:         name,
		Type:         cloudfrontDistributionType,
		Provider:     asset.ProviderAWS,
		Region:       "global",
		AccountID:    accountID,
		Domain:       domain,
		Endpoint:     "https://" + domain,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// stampDistributionConfig records the config-only fields. A failed read
// leaves default_root_object absent, and logging absent unless v2 proves it on.
func stampDistributionConfig(meta map[string]string, arn string, out *cloudfront.GetDistributionConfigOutput, err error, v2Logged map[string]bool, v2Read bool) {
	arnLogged := v2Logged[arn]
	if err != nil || out == nil || out.DistributionConfig == nil {
		if arnLogged {
			meta["logging_enabled"] = "true"
		}
		return
	}
	dc := out.DistributionConfig
	meta["default_root_object"] = awssdk.ToString(dc.DefaultRootObject)
	legacy := dc.Logging != nil && awssdk.ToBool(dc.Logging.Enabled)
	switch {
	case legacy || arnLogged:
		meta["logging_enabled"] = "true"
	case v2Read:
		meta["logging_enabled"] = "false"
	}
}

// cloudfrontV2Logging returns the distribution ARNs with a standard-logging
// (v2) access-log delivery. Any page failure is an error: a short list would
// read as "not logged".
func cloudfrontV2Logging(ctx context.Context, client cloudfrontLogsAPI) (map[string]bool, error) {
	sources := map[string][]string{} // source name → resource ARNs
	var token *string
	for {
		out, err := client.DescribeDeliverySources(ctx, &cloudwatchlogs.DescribeDeliverySourcesInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("cloudfrontV2Logging: DescribeDeliverySources: %w", err)
		}
		// Matched by resource ARN below, so sources of other services
		// never collide with a distribution.
		for _, s := range out.DeliverySources {
			sources[awssdk.ToString(s.Name)] = s.ResourceArns
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	logged := map[string]bool{}
	token = nil
	for {
		out, err := client.DescribeDeliveries(ctx, &cloudwatchlogs.DescribeDeliveriesInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("cloudfrontV2Logging: DescribeDeliveries: %w", err)
		}
		for _, d := range out.Deliveries {
			for _, arn := range sources[awssdk.ToString(d.DeliverySourceName)] {
				logged[arn] = true
			}
		}
		if out.NextToken == nil {
			return logged, nil
		}
		token = out.NextToken
	}
}
