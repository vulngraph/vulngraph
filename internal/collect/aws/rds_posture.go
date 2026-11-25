package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// rdsPostureAPI is the slice of the RDS client the cluster, proxy, global
// cluster, parameter-group and event-subscription reads use. Every call is an
// rds:Describe* action, granted by SecurityAudit and ViewOnlyAccess.
type rdsPostureAPI interface {
	DescribeDBClusters(context.Context, *rds.DescribeDBClustersInput, ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBParameters(context.Context, *rds.DescribeDBParametersInput, ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error)
	DescribeDBClusterParameters(context.Context, *rds.DescribeDBClusterParametersInput, ...func(*rds.Options)) (*rds.DescribeDBClusterParametersOutput, error)
	DescribeDBProxies(context.Context, *rds.DescribeDBProxiesInput, ...func(*rds.Options)) (*rds.DescribeDBProxiesOutput, error)
	DescribeGlobalClusters(context.Context, *rds.DescribeGlobalClustersInput, ...func(*rds.Options)) (*rds.DescribeGlobalClustersOutput, error)
	DescribeEventSubscriptions(context.Context, *rds.DescribeEventSubscriptionsInput, ...func(*rds.Options)) (*rds.DescribeEventSubscriptionsOutput, error)
	DescribeDBEngineVersions(context.Context, *rds.DescribeDBEngineVersionsInput, ...func(*rds.Options)) (*rds.DescribeDBEngineVersionsOutput, error)
}

// collectRDSPosture emits the region's DB clusters, proxies, global clusters
// and RDS settings asset, and stamps parameter-group facts onto the instances
// already collected. The cluster listing is required — instance checks hand
// cluster members to their cluster, so an unread cluster set is an error —
// while the rest are best-effort: a failure leaves its assets out and flags
// the sweep partial.
func collectRDSPosture(ctx context.Context, client rdsPostureAPI, region, accountID string, now time.Time, instances []asset.Asset) ([]asset.Asset, bool, error) {
	clusters, err := collectRDSClusters(ctx, client, region, accountID, now)
	if err != nil {
		return nil, false, err
	}
	stampRDSParameterFacts(ctx, client, region, instances, clusters)
	stampRDSEngineVersionFacts(ctx, client, region, instances)

	out := clusters
	partial := false
	logger := log.FromContext(ctx)
	if proxies, err := collectRDSProxies(ctx, client, region, accountID, now); err == nil {
		out = append(out, proxies...)
	} else {
		partial = true
		logger.Warn().Err(err).Str("region", region).Msg("rds proxy listing failed (check rds:DescribeDBProxies); proxies omitted this sweep")
	}
	if globals, err := collectRDSGlobalClusters(ctx, client, region, accountID, now); err == nil {
		out = append(out, globals...)
	} else {
		partial = true
		logger.Warn().Err(err).Str("region", region).Msg("rds global cluster listing failed (check rds:DescribeGlobalClusters); global clusters omitted this sweep")
	}
	if settings, err := rdsRegionSettings(ctx, client, region, accountID, now, instances, clusters); err == nil {
		out = append(out, settings)
	} else {
		partial = true
		logger.Warn().Err(err).Str("region", region).Msg("rds event subscription listing failed (check rds:DescribeEventSubscriptions); event-notification coverage unknown this sweep")
	}
	return out, partial, nil
}

// collectRDSProxies lists the region's RDS proxies (FSBP RDS.43).
func collectRDSProxies(ctx context.Context, client rdsPostureAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out    []asset.Asset
		marker *string
	)
	for {
		page, err := client.DescribeDBProxies(ctx, &rds.DescribeDBProxiesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("collectRDSProxies: %w", err)
		}
		for _, p := range page.DBProxies {
			meta := map[string]string{
				"engine_family": awssdk.ToString(p.EngineFamily),
				"status":        string(p.Status),
			}
			if p.RequireTLS != nil {
				meta["require_tls"] = strconv.FormatBool(*p.RequireTLS)
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(p.DBProxyArn),
				Name:         awssdk.ToString(p.DBProxyName),
				Type:         "rds_proxy",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Endpoint:     awssdk.ToString(p.Endpoint),
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}

// collectRDSGlobalClusters lists Aurora global databases (FSBP RDS.51).
// DescribeGlobalClusters answers with the same global clusters in every
// region, so each is emitted only by the region holding its writer cluster —
// one asset per global cluster without cross-region state. A global cluster
// with no writer member holds no data to grade and is skipped.
func collectRDSGlobalClusters(ctx context.Context, client rdsPostureAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out    []asset.Asset
		marker *string
	)
	for {
		page, err := client.DescribeGlobalClusters(ctx, &rds.DescribeGlobalClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("collectRDSGlobalClusters: %w", err)
		}
		for _, g := range page.GlobalClusters {
			writer := ""
			for _, m := range g.GlobalClusterMembers {
				if awssdk.ToBool(m.IsWriter) {
					writer = awssdk.ToString(m.DBClusterArn)
				}
			}
			if writer == "" || arnRegion(writer) != region {
				continue
			}
			meta := map[string]string{
				"engine":         awssdk.ToString(g.Engine),
				"writer_cluster": writer,
			}
			if v := awssdk.ToString(g.EngineVersion); v != "" {
				meta["engine_version"] = v
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(g.GlobalClusterArn),
				Name:         awssdk.ToString(g.GlobalClusterIdentifier),
				Type:         "rds_global_cluster",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}

// arnRegion returns the region field of an ARN (arn:partition:service:region:…).
func arnRegion(arn string) string {
	parts := strings.SplitN(arn, ":", 5)
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}
