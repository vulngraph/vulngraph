package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Data Firehose posture (FSBP DataFirehose.1, server-side encryption at rest).

type firehoseAPI interface {
	ListDeliveryStreams(context.Context, *firehose.ListDeliveryStreamsInput, ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error)
	DescribeDeliveryStream(context.Context, *firehose.DescribeDeliveryStreamInput, ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error)
}

func collectFirehose(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectFirehose: %w", err)
	}
	return collectFirehoseStreams(ctx, firehose.NewFromConfig(awsCfg), region, accountID, now)
}

func collectFirehoseStreams(ctx context.Context, client firehoseAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	// ListDeliveryStreams pages by the last name seen, not a token.
	var (
		names []string
		start *string
	)
	for {
		out, err := client.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{ExclusiveStartDeliveryStreamName: start})
		if err != nil {
			return nil, fmt.Errorf("collectFirehoseStreams: %w", err)
		}
		names = append(names, out.DeliveryStreamNames...)
		if !awssdk.ToBool(out.HasMoreDeliveryStreams) || len(out.DeliveryStreamNames) == 0 {
			break
		}
		start = awssdk.String(out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1])
	}

	descs := make([]*firehosetypes.DeliveryStreamDescription, len(names))
	eachBounded(ctx, len(names), eachBoundedTimeout, "firehose:DescribeDeliveryStream", func(ctx context.Context, i int) {
		out, err := client.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: awssdk.String(names[i])})
		if err == nil && out != nil {
			descs[i] = out.DeliveryStreamDescription
		}
	})

	assets := make([]asset.Asset, 0, len(names))
	unread := 0
	for i, name := range names {
		d := descs[i]
		if d == nil {
			// Listed but not described: emitted so it is not read as deleted,
			// with no posture keys and an ID that is the name until an ARN is read.
			unread++
			assets = append(assets, firehoseAsset(name, firehoseARN(region, accountID, name), map[string]string{}, region, accountID, now))
			continue
		}
		assets = append(assets, firehoseAsset(name, awssdk.ToString(d.DeliveryStreamARN), firehoseStreamFacts(d), region, accountID, now))
	}
	if unread > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("streams", len(names)).Int("unread", unread).
			Msg("firehose: DescribeDeliveryStream failed for some streams (check firehose:DescribeDeliveryStream); their encryption is unknown this sweep")
	}
	return assets, nil
}

// firehoseARN builds a delivery stream's ARN for one that was listed but not
// described, so its asset ID matches the described form on the next sweep.
func firehoseARN(region, accountID, name string) string {
	return fmt.Sprintf("arn:%s:firehose:%s:%s:deliverystream/%s", partitionFor(region), region, accountID, name)
}

func firehoseAsset(name, arn string, meta map[string]string, region, accountID string, now time.Time) asset.Asset {
	return asset.Asset{
		ID:           arn,
		Name:         name,
		Type:         "firehose_delivery_stream",
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// firehoseStreamFacts records the source type and the server-side encryption
// status. A described stream with no encryption configuration has never had
// SSE turned on, which the API reports by omitting the block: that is
// recorded as DISABLED, an observation of the described stream.
func firehoseStreamFacts(d *firehosetypes.DeliveryStreamDescription) map[string]string {
	meta := map[string]string{"source_type": string(d.DeliveryStreamType)}
	if c := d.DeliveryStreamEncryptionConfiguration; c != nil && c.Status != "" {
		meta["sse_status"] = string(c.Status)
	} else {
		meta["sse_status"] = string(firehosetypes.DeliveryStreamEncryptionStatusDisabled)
	}
	return meta
}
