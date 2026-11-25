package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Kinesis Data Streams posture (FSBP Kinesis.1 encryption at rest, Kinesis.3
// retention). ListStreams returns only names and ARNs; encryption and
// retention come from one DescribeStreamSummary per stream.

type kinesisAPI interface {
	ListStreams(context.Context, *kinesis.ListStreamsInput, ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error)
	DescribeStreamSummary(context.Context, *kinesis.DescribeStreamSummaryInput, ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error)
}

func collectKinesis(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectKinesis: %w", err)
	}
	return collectKinesisStreams(ctx, kinesis.NewFromConfig(awsCfg), region, accountID, now)
}

func collectKinesisStreams(ctx context.Context, client kinesisAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		streams []kinesistypes.StreamSummary
		next    *string
	)
	for {
		out, err := client.ListStreams(ctx, &kinesis.ListStreamsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("collectKinesisStreams: %w", err)
		}
		streams = append(streams, out.StreamSummaries...)
		if out.NextToken == nil || !awssdk.ToBool(out.HasMoreStreams) {
			break
		}
		next = out.NextToken
	}

	metas := make([]map[string]string, len(streams))
	eachBounded(ctx, len(streams), eachBoundedTimeout, "kinesis:DescribeStreamSummary", func(ctx context.Context, i int) {
		out, err := client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{StreamARN: streams[i].StreamARN})
		if err != nil || out == nil || out.StreamDescriptionSummary == nil {
			return
		}
		metas[i] = kinesisStreamFacts(out.StreamDescriptionSummary)
	})

	assets := make([]asset.Asset, 0, len(streams))
	unread := 0
	for i, s := range streams {
		meta := metas[i]
		if meta == nil {
			unread++
			meta = map[string]string{}
		}
		meta["stream_status"] = string(s.StreamStatus)
		assets = append(assets, asset.Asset{
			ID:           awssdk.ToString(s.StreamARN),
			Name:         awssdk.ToString(s.StreamName),
			Type:         "kinesis_stream",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	if unread > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("streams", len(streams)).Int("unread", unread).
			Msg("kinesis: DescribeStreamSummary failed for some streams (check kinesis:DescribeStreamSummary); their encryption and retention are unknown this sweep")
	}
	return assets, nil
}

// kinesisStreamFacts are the posture fields of one stream summary. A missing
// EncryptionType or retention is left absent rather than read as "none" / 0.
func kinesisStreamFacts(s *kinesistypes.StreamDescriptionSummary) map[string]string {
	meta := map[string]string{}
	if s.EncryptionType != "" {
		meta["encryption_type"] = string(s.EncryptionType)
	}
	if s.RetentionPeriodHours != nil {
		meta["retention_hours"] = strconv.Itoa(int(*s.RetentionPeriodHours))
	}
	return meta
}
