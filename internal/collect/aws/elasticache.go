package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ElastiCache replication groups and cache clusters (FSBP ElastiCache.1-7).
//
// A Redis OSS / Valkey replication group is made of cache clusters (its
// nodes), and FSBP grades some controls on the node: graded per node, one
// group's single setting would raise a finding per node. So a node that
// belongs to a group carries replication_group_id and the checks grade the
// group instead; the group borrows the node-only facts it needs (engine
// version, subnet group — every node of a group shares them) from its nodes.

type elastiCacheAPI interface {
	DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
	DescribeCacheClusters(context.Context, *elasticache.DescribeCacheClustersInput, ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error)
}

func collectElastiCache(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectElastiCache: %w", err)
	}
	return collectElastiCacheResources(ctx, elasticache.NewFromConfig(awsCfg), region, accountID, now)
}

func collectElastiCacheResources(ctx context.Context, client elastiCacheAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	clusters, err := listCacheClusters(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("collectElastiCacheResources: %w", err)
	}
	groups, err := listReplicationGroups(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("collectElastiCacheResources: %w", err)
	}
	// The first node seen for each group supplies the group's node facts.
	nodeOf := map[string]ectypes.CacheCluster{}
	for _, c := range clusters {
		if rg := awssdk.ToString(c.ReplicationGroupId); rg != "" {
			if _, ok := nodeOf[rg]; !ok {
				nodeOf[rg] = c
			}
		}
	}
	out := make([]asset.Asset, 0, len(clusters)+len(groups))
	for _, g := range groups {
		out = append(out, replicationGroupAsset(g, nodeOf, region, accountID, now))
	}
	for _, c := range clusters {
		out = append(out, cacheClusterAsset(c, region, accountID, now))
	}
	return out, nil
}

func listCacheClusters(ctx context.Context, client elastiCacheAPI) ([]ectypes.CacheCluster, error) {
	var (
		out    []ectypes.CacheCluster
		marker *string
	)
	for {
		page, err := client.DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("DescribeCacheClusters: %w", err)
		}
		out = append(out, page.CacheClusters...)
		if page.Marker == nil || *page.Marker == "" {
			return out, nil
		}
		marker = page.Marker
	}
}

func listReplicationGroups(ctx context.Context, client elastiCacheAPI) ([]ectypes.ReplicationGroup, error) {
	var (
		out    []ectypes.ReplicationGroup
		marker *string
	)
	for {
		page, err := client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("DescribeReplicationGroups: %w", err)
		}
		out = append(out, page.ReplicationGroups...)
		if page.Marker == nil || *page.Marker == "" {
			return out, nil
		}
		marker = page.Marker
	}
}

// ecPutBool writes a *bool posture field only when the API returned it.
func ecPutBool(meta map[string]string, key string, v *bool) {
	if v != nil {
		meta[key] = strconv.FormatBool(*v)
	}
}

func ecPutInt32(meta map[string]string, key string, v *int32) {
	if v != nil {
		meta[key] = strconv.Itoa(int(*v))
	}
}

func replicationGroupAsset(g ectypes.ReplicationGroup, nodeOf map[string]ectypes.CacheCluster, region, accountID string, now time.Time) asset.Asset {
	id := awssdk.ToString(g.ReplicationGroupId)
	meta := map[string]string{
		"engine": awssdk.ToString(g.Engine),
	}
	if g.AutomaticFailover != "" {
		meta["automatic_failover"] = string(g.AutomaticFailover)
	}
	ecPutBool(meta, "at_rest_encryption_enabled", g.AtRestEncryptionEnabled)
	ecPutBool(meta, "transit_encryption_enabled", g.TransitEncryptionEnabled)
	ecPutBool(meta, "auth_token_enabled", g.AuthTokenEnabled)
	ecPutBool(meta, "auto_minor_version_upgrade", g.AutoMinorVersionUpgrade)
	ecPutInt32(meta, "snapshot_retention_limit", g.SnapshotRetentionLimit)
	if n, ok := nodeOf[id]; ok {
		meta["engine_version"] = awssdk.ToString(n.EngineVersion)
		meta["cache_subnet_group"] = awssdk.ToString(n.CacheSubnetGroupName)
	}
	return asset.Asset{
		ID: awssdk.ToString(g.ARN), Name: id, Type: "elasticache_replication_group",
		Provider: asset.ProviderAWS, Region: region, AccountID: accountID, Metadata: meta,
		DiscoveredAt: now, LastSeen: now,
	}
}

func cacheClusterAsset(c ectypes.CacheCluster, region, accountID string, now time.Time) asset.Asset {
	meta := map[string]string{
		"engine":         awssdk.ToString(c.Engine),
		"engine_version": awssdk.ToString(c.EngineVersion),
		// Written empty for a standalone node: "not in a group" is what lets
		// the node-level checks grade it.
		"replication_group_id": awssdk.ToString(c.ReplicationGroupId),
		"cache_subnet_group":   awssdk.ToString(c.CacheSubnetGroupName),
		// Same CSV shape ec2_instance / rds_instance use for security_groups.
		"security_groups": ecSecurityGroupIDs(c.SecurityGroups),
	}
	ecPutBool(meta, "auto_minor_version_upgrade", c.AutoMinorVersionUpgrade)
	ecPutInt32(meta, "snapshot_retention_limit", c.SnapshotRetentionLimit)
	return asset.Asset{
		ID: awssdk.ToString(c.ARN), Name: awssdk.ToString(c.CacheClusterId), Type: "elasticache_cluster",
		Provider: asset.ProviderAWS, Region: region, AccountID: accountID, Metadata: meta,
		DiscoveredAt: now, LastSeen: now,
	}
}

func ecSecurityGroupIDs(groups []ectypes.SecurityGroupMembership) string {
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		if id := awssdk.ToString(g.SecurityGroupId); id != "" {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}
