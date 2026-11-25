package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// lbTargetGroupType is the asset type of an ELBv2 target group (AWS FSBP
// ELB.21/ELB.22 grade each group on its own, attached or not).
const lbTargetGroupType = "lb_target_group"

type elbv2TargetGroupAPI interface {
	DescribeTargetGroups(context.Context, *elasticloadbalancingv2.DescribeTargetGroupsInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error)
}

func collectTargetGroups(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectTargetGroups: %w", err)
	}
	return listTargetGroups(ctx, elasticloadbalancingv2.NewFromConfig(awsCfg), region, accountID, now)
}

// listTargetGroups emits every target group in the region. A page error fails
// the whole listing (no short list).
func listTargetGroups(ctx context.Context, client elbv2TargetGroupAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		marker *string
	)
	for {
		out, err := client.DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listTargetGroups: %w", err)
		}
		for _, tg := range out.TargetGroups {
			arn := awssdk.ToString(tg.TargetGroupArn)
			if arn == "" {
				continue
			}
			meta := map[string]string{
				"target_type":        string(tg.TargetType),
				"protocol":           string(tg.Protocol),
				"load_balancer_arns": strings.Join(tg.LoadBalancerArns, ","),
				"vpc_id":             awssdk.ToString(tg.VpcId),
			}
			// A Lambda target group has no health-check protocol; an empty one is
			// not an observation of plaintext, so the key is left out.
			if tg.HealthCheckProtocol != "" {
				meta["health_check_protocol"] = string(tg.HealthCheckProtocol)
			}
			assets = append(assets, asset.Asset{
				ID:           arn,
				Name:         awssdk.ToString(tg.TargetGroupName),
				Type:         lbTargetGroupType,
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextMarker == nil {
			return assets, nil
		}
		marker = out.NextMarker
	}
}
