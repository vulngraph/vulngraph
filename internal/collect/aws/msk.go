package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/kafkaconnect"
	kctypes "github.com/aws/aws-sdk-go-v2/service/kafkaconnect/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Amazon MSK clusters (FSBP MSK.1, MSK.4, MSK.6) and MSK Connect connectors
// (MSK.3, MSK.5). Two services, two collectors: a region without MSK Connect,
// or a role missing kafkaconnect:List*, must not cost the cluster posture.

type kafkaAPI interface {
	ListClustersV2(context.Context, *kafka.ListClustersV2Input, ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error)
}

type kafkaConnectAPI interface {
	ListConnectors(context.Context, *kafkaconnect.ListConnectorsInput, ...func(*kafkaconnect.Options)) (*kafkaconnect.ListConnectorsOutput, error)
}

func collectMSK(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectMSK: %w", err)
	}
	return collectMSKClusters(ctx, kafka.NewFromConfig(awsCfg), region, accountID, now)
}

func collectMSKConnect(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectMSKConnect: %w", err)
	}
	return collectMSKConnectors(ctx, kafkaconnect.NewFromConfig(awsCfg), region, accountID, now)
}

func collectMSKClusters(ctx context.Context, client kafkaAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out  []asset.Asset
		next *string
	)
	for {
		page, err := client.ListClustersV2(ctx, &kafka.ListClustersV2Input{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectMSKClusters: %w", err)
		}
		for _, c := range page.ClusterInfoList {
			out = append(out, asset.Asset{
				ID: awssdk.ToString(c.ClusterArn), Name: awssdk.ToString(c.ClusterName), Type: "msk_cluster",
				Provider: asset.ProviderAWS, Region: region, AccountID: accountID,
				Metadata: mskClusterMeta(c), DiscoveredAt: now, LastSeen: now,
			})
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		next = page.NextToken
	}
}

// mskClusterMeta grades a cluster's transport, authentication and network
// exposure. Serverless clusters carry only cluster_type: they always use IAM
// authentication and TLS and cannot be made public, so none of the
// provisioned-cluster settings exists for them to fail.
func mskClusterMeta(c kafkatypes.Cluster) map[string]string {
	meta := map[string]string{"cluster_type": string(c.ClusterType)}
	p := c.Provisioned
	if c.ClusterType != kafkatypes.ClusterTypeProvisioned || p == nil {
		return meta
	}
	if p.EncryptionInfo != nil && p.EncryptionInfo.EncryptionInTransit != nil {
		eit := p.EncryptionInfo.EncryptionInTransit
		// InCluster is documented to default to true when omitted.
		meta["in_cluster_encryption"] = strconv.FormatBool(eit.InCluster == nil || *eit.InCluster)
		if eit.ClientBroker != "" {
			meta["client_broker_encryption"] = string(eit.ClientBroker)
		}
	}
	// A provisioned cluster with no client authentication block was created
	// without any authentication mechanism, which leaves unauthenticated
	// access as the only way in; one with SASL or TLS but no Unauthenticated
	// entry has it off.
	switch ca := p.ClientAuthentication; {
	case ca == nil:
		meta["unauthenticated_access"] = "true"
	case ca.Unauthenticated != nil:
		meta["unauthenticated_access"] = strconv.FormatBool(awssdk.ToBool(ca.Unauthenticated.Enabled))
	default:
		meta["unauthenticated_access"] = "false"
	}
	if b := p.BrokerNodeGroupInfo; b != nil && b.ConnectivityInfo != nil {
		typ := "DISABLED" // the API's value for a cluster reachable only inside its VPC
		if pa := b.ConnectivityInfo.PublicAccess; pa != nil && awssdk.ToString(pa.Type) != "" {
			typ = awssdk.ToString(pa.Type)
		}
		meta["public_access_type"] = typ
		if typ != "DISABLED" {
			// Public brokers with unauthenticated access on accept any client on
			// the internet; with authentication required they are reachable but
			// still credential-gated.
			if meta["unauthenticated_access"] == "true" {
				meta["public_access"] = asset.PublicAccessConfirmed
			} else {
				meta["public_access"] = asset.PublicAccessPossible
			}
		}
	}
	return meta
}

func collectMSKConnectors(ctx context.Context, client kafkaConnectAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out  []asset.Asset
		next *string
	)
	for {
		page, err := client.ListConnectors(ctx, &kafkaconnect.ListConnectorsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectMSKConnectors: %w", err)
		}
		for _, c := range page.Connectors {
			out = append(out, asset.Asset{
				ID: awssdk.ToString(c.ConnectorArn), Name: awssdk.ToString(c.ConnectorName), Type: "msk_connector",
				Provider: asset.ProviderAWS, Region: region, AccountID: accountID,
				Metadata: mskConnectorMeta(c), DiscoveredAt: now, LastSeen: now,
			})
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		next = page.NextToken
	}
}

// mskConnectorMeta reads the encryption and log-delivery settings the
// ListConnectors summary carries (the same fields DescribeConnector returns).
// A summary without a LogDelivery block is a connector created with no log
// destination, which is the "logging disabled" FSBP MSK.5 fails.
func mskConnectorMeta(c kctypes.ConnectorSummary) map[string]string {
	meta := map[string]string{}
	if e := c.KafkaClusterEncryptionInTransit; e != nil && e.EncryptionType != "" {
		meta["encryption_in_transit_type"] = string(e.EncryptionType)
	}
	enabled := false
	if ld := c.LogDelivery; ld != nil && ld.WorkerLogDelivery != nil {
		w := ld.WorkerLogDelivery
		enabled = (w.CloudWatchLogs != nil && w.CloudWatchLogs.Enabled) ||
			(w.Firehose != nil && w.Firehose.Enabled) ||
			(w.S3 != nil && w.S3.Enabled)
	}
	meta["log_delivery_enabled"] = strconv.FormatBool(enabled)
	return meta
}
