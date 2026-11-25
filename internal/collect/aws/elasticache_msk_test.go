package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/kafkaconnect"
	kctypes "github.com/aws/aws-sdk-go-v2/service/kafkaconnect/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeElastiCache struct {
	groups   []ectypes.ReplicationGroup
	clusters [][]ectypes.CacheCluster
	pageErr  error
}

func (f *fakeElastiCache) DescribeReplicationGroups(context.Context, *elasticache.DescribeReplicationGroupsInput, ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	return &elasticache.DescribeReplicationGroupsOutput{ReplicationGroups: f.groups}, nil
}

func (f *fakeElastiCache) DescribeCacheClusters(_ context.Context, in *elasticache.DescribeCacheClustersInput, _ ...func(*elasticache.Options)) (*elasticache.DescribeCacheClustersOutput, error) {
	page := 0
	if in.Marker != nil {
		page = 1
		if f.pageErr != nil {
			return nil, f.pageErr
		}
	}
	out := &elasticache.DescribeCacheClustersOutput{}
	if page < len(f.clusters) {
		out.CacheClusters = f.clusters[page]
	}
	if page+1 < len(f.clusters) {
		out.Marker = awssdk.String("next")
	}
	return out, nil
}

func TestCollectElastiCacheResources(t *testing.T) {
	f := &fakeElastiCache{
		groups: []ectypes.ReplicationGroup{{
			ARN: awssdk.String("arn:rg:1"), ReplicationGroupId: awssdk.String("rg-1"), Engine: awssdk.String("redis"),
			AutomaticFailover: ectypes.AutomaticFailoverStatusDisabled, AtRestEncryptionEnabled: awssdk.Bool(false),
			TransitEncryptionEnabled: awssdk.Bool(true), AuthTokenEnabled: awssdk.Bool(false),
			SnapshotRetentionLimit: awssdk.Int32(0),
		}, {
			// Fields omitted by the API stay unknown.
			ARN: awssdk.String("arn:rg:2"), ReplicationGroupId: awssdk.String("rg-2"),
		}},
		clusters: [][]ectypes.CacheCluster{
			{{ARN: awssdk.String("arn:cc:rg-1-001"), CacheClusterId: awssdk.String("rg-1-001"), ReplicationGroupId: awssdk.String("rg-1"),
				Engine: awssdk.String("redis"), EngineVersion: awssdk.String("5.0.6"), CacheSubnetGroupName: awssdk.String("default")}},
			{{ARN: awssdk.String("arn:cc:solo"), CacheClusterId: awssdk.String("solo"), Engine: awssdk.String("memcached"),
				AutoMinorVersionUpgrade: awssdk.Bool(true), CacheSubnetGroupName: awssdk.String("private"),
				SecurityGroups: []ectypes.SecurityGroupMembership{
					{SecurityGroupId: awssdk.String("sg-cache"), Status: awssdk.String("active")},
					{SecurityGroupId: awssdk.String("sg-app")},
				}}},
		},
	}
	got, err := collectElastiCacheResources(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	m := dmsByID(got)
	require.Len(t, m, 4)

	rg := m["arn:rg:1"]
	require.Equal(t, "elasticache_replication_group", rg.Type)
	require.Equal(t, "disabled", rg.Metadata["automatic_failover"])
	require.Equal(t, "false", rg.Metadata["at_rest_encryption_enabled"])
	require.Equal(t, "true", rg.Metadata["transit_encryption_enabled"])
	require.Equal(t, "0", rg.Metadata["snapshot_retention_limit"])
	require.Equal(t, "5.0.6", rg.Metadata["engine_version"], "borrowed from the group's node")
	require.Equal(t, "default", rg.Metadata["cache_subnet_group"])

	rg2 := m["arn:rg:2"].Metadata
	for _, k := range []string{"automatic_failover", "at_rest_encryption_enabled", "auth_token_enabled", "snapshot_retention_limit", "engine_version"} {
		require.NotContains(t, rg2, k)
	}

	require.Equal(t, "rg-1", m["arn:cc:rg-1-001"].Metadata["replication_group_id"])
	solo := m["arn:cc:solo"].Metadata
	require.Equal(t, "elasticache_cluster", m["arn:cc:solo"].Type)
	require.Equal(t, "", solo["replication_group_id"])
	require.Equal(t, "true", solo["auto_minor_version_upgrade"])
	require.NotContains(t, solo, "snapshot_retention_limit")
	// The VPC security groups join the node to the SG graph (connected_via_sg).
	require.Equal(t, "sg-cache,sg-app", solo["security_groups"])
}

func TestCollectElastiCacheFailedPageFailsTheListing(t *testing.T) {
	f := &fakeElastiCache{
		clusters: [][]ectypes.CacheCluster{{{ARN: awssdk.String("a")}}, {{ARN: awssdk.String("b")}}},
		pageErr:  errors.New("throttled"),
	}
	_, err := collectElastiCacheResources(context.Background(), f, "eu-west-1", "111", time.Now())
	require.Error(t, err)
}

type fakeKafka struct{ pages [][]kafkatypes.Cluster }

func (f *fakeKafka) ListClustersV2(_ context.Context, in *kafka.ListClustersV2Input, _ ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error) {
	page := 0
	if in.NextToken != nil {
		page = 1
	}
	out := &kafka.ListClustersV2Output{ClusterInfoList: f.pages[page]}
	if page+1 < len(f.pages) {
		out.NextToken = awssdk.String("next")
	}
	return out, nil
}

func TestCollectMSKClusters(t *testing.T) {
	prov := func(arn string, p *kafkatypes.Provisioned) kafkatypes.Cluster {
		return kafkatypes.Cluster{ClusterArn: awssdk.String(arn), ClusterType: kafkatypes.ClusterTypeProvisioned, Provisioned: p}
	}
	public := &kafkatypes.ConnectivityInfo{PublicAccess: &kafkatypes.PublicAccess{Type: awssdk.String("SERVICE_PROVIDED_EIPS")}}
	f := &fakeKafka{pages: [][]kafkatypes.Cluster{
		{
			prov("arn:msk:plain", &kafkatypes.Provisioned{
				EncryptionInfo:       &kafkatypes.EncryptionInfo{EncryptionInTransit: &kafkatypes.EncryptionInTransit{InCluster: awssdk.Bool(false), ClientBroker: kafkatypes.ClientBrokerTlsPlaintext}},
				ClientAuthentication: &kafkatypes.ClientAuthentication{Unauthenticated: &kafkatypes.Unauthenticated{Enabled: awssdk.Bool(true)}},
				BrokerNodeGroupInfo:  &kafkatypes.BrokerNodeGroupInfo{ConnectivityInfo: &kafkatypes.ConnectivityInfo{}},
			}),
			prov("arn:msk:public", &kafkatypes.Provisioned{
				EncryptionInfo:       &kafkatypes.EncryptionInfo{EncryptionInTransit: &kafkatypes.EncryptionInTransit{}},
				ClientAuthentication: &kafkatypes.ClientAuthentication{Sasl: &kafkatypes.Sasl{}},
				BrokerNodeGroupInfo:  &kafkatypes.BrokerNodeGroupInfo{ConnectivityInfo: public},
			}),
		},
		{
			prov("arn:msk:noauth", &kafkatypes.Provisioned{}),
			{ClusterArn: awssdk.String("arn:msk:serverless"), ClusterType: kafkatypes.ClusterTypeServerless},
		},
	}}
	got, err := collectMSKClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	m := dmsByID(got)
	require.Len(t, m, 4)

	plain := m["arn:msk:plain"].Metadata
	require.Equal(t, "false", plain["in_cluster_encryption"])
	require.Equal(t, "true", plain["unauthenticated_access"])
	require.Equal(t, "DISABLED", plain["public_access_type"])
	require.NotContains(t, plain, "public_access")

	pub := m["arn:msk:public"].Metadata
	require.Equal(t, "true", pub["in_cluster_encryption"], "InCluster defaults to true when omitted")
	require.Equal(t, "false", pub["unauthenticated_access"])
	require.Equal(t, "SERVICE_PROVIDED_EIPS", pub["public_access_type"])
	require.Equal(t, asset.PublicAccessPossible, pub["public_access"], "authenticated public brokers are reachable, not open")

	noauth := m["arn:msk:noauth"].Metadata
	require.Equal(t, "true", noauth["unauthenticated_access"], "no authentication mechanism configured")
	require.NotContains(t, noauth, "in_cluster_encryption", "an unread encryption block stays unknown")
	require.NotContains(t, noauth, "public_access_type")

	require.Equal(t, map[string]string{"cluster_type": "SERVERLESS"}, m["arn:msk:serverless"].Metadata)
}

type fakeKafkaConnect struct{ connectors []kctypes.ConnectorSummary }

func (f *fakeKafkaConnect) ListConnectors(context.Context, *kafkaconnect.ListConnectorsInput, ...func(*kafkaconnect.Options)) (*kafkaconnect.ListConnectorsOutput, error) {
	return &kafkaconnect.ListConnectorsOutput{Connectors: f.connectors}, nil
}

func TestCollectMSKConnectors(t *testing.T) {
	f := &fakeKafkaConnect{connectors: []kctypes.ConnectorSummary{
		{ConnectorArn: awssdk.String("arn:c:1"),
			KafkaClusterEncryptionInTransit: &kctypes.KafkaClusterEncryptionInTransitDescription{EncryptionType: kctypes.KafkaClusterEncryptionInTransitTypePlaintext}},
		{ConnectorArn: awssdk.String("arn:c:2"),
			KafkaClusterEncryptionInTransit: &kctypes.KafkaClusterEncryptionInTransitDescription{EncryptionType: kctypes.KafkaClusterEncryptionInTransitTypeTls},
			LogDelivery: &kctypes.LogDeliveryDescription{WorkerLogDelivery: &kctypes.WorkerLogDeliveryDescription{
				CloudWatchLogs: &kctypes.CloudWatchLogsLogDeliveryDescription{Enabled: false},
				S3:             &kctypes.S3LogDeliveryDescription{Enabled: true},
			}}},
		{ConnectorArn: awssdk.String("arn:c:3"), LogDelivery: &kctypes.LogDeliveryDescription{WorkerLogDelivery: &kctypes.WorkerLogDeliveryDescription{
			CloudWatchLogs: &kctypes.CloudWatchLogsLogDeliveryDescription{Enabled: false}}}},
	}}
	got, err := collectMSKConnectors(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	m := dmsByID(got)
	require.Equal(t, "PLAINTEXT", m["arn:c:1"].Metadata["encryption_in_transit_type"])
	require.Equal(t, "false", m["arn:c:1"].Metadata["log_delivery_enabled"])
	require.Equal(t, "TLS", m["arn:c:2"].Metadata["encryption_in_transit_type"])
	require.Equal(t, "true", m["arn:c:2"].Metadata["log_delivery_enabled"])
	require.Equal(t, "false", m["arn:c:3"].Metadata["log_delivery_enabled"], "a destination configured but disabled logs nothing")
	require.NotContains(t, m["arn:c:3"].Metadata, "encryption_in_transit_type")
}
