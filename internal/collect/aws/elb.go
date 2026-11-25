package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type elbv2API interface {
	DescribeLoadBalancers(context.Context, *elasticloadbalancingv2.DescribeLoadBalancersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error)
	// Per-balancer posture (elb_detail.go).
	DescribeLoadBalancerAttributes(context.Context, *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error)
	DescribeListeners(context.Context, *elasticloadbalancingv2.DescribeListenersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error)
	DescribeRules(context.Context, *elasticloadbalancingv2.DescribeRulesInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeRulesOutput, error)
}

func collectELBv2(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("collectELBv2: %w", err)
	}
	client := elasticloadbalancingv2.NewFromConfig(awsCfg)
	return collectLoadBalancers(ctx, client, region, accountID, now)
}

func collectLoadBalancers(ctx context.Context, client elbv2API, region, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	var (
		assets []asset.Asset
		edges  []asset.Edge
		marker *string
	)
	for {
		out, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{
			Marker: marker,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("collectLoadBalancers: %w", err)
		}
		for _, lb := range out.LoadBalancers {
			arn := awssdk.ToString(lb.LoadBalancerArn)
			name := awssdk.ToString(lb.LoadBalancerName)
			dns := awssdk.ToString(lb.DNSName)

			var sgIDs []string
			for _, sg := range lb.SecurityGroups {
				sgIDs = append(sgIDs, sg)
				edges = append(edges, asset.Edge{
					SrcID: arn, SrcType: "load_balancer",
					DstID: sg, DstType: "security_group",
					EdgeType: "protected_by",
				})
			}

			assets = append(assets, asset.Asset{
				ID:        arn,
				Name:      name,
				Type:      "load_balancer",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Domain:    dns,
				Endpoint:  fmt.Sprintf("https://%s", dns),
				Metadata: map[string]string{
					"scheme":          string(lb.Scheme),
					"type":            string(lb.Type),
					"state":           lbState(lb.State),
					"vpc_id":          awssdk.ToString(lb.VpcId),
					"security_groups": strings.Join(sgIDs, ","),
					// public=true triggers exposed_to_internet edge in InternetReachability.
					// Internet-facing ALBs/NLBs are the primary public entry point for AWS workloads.
					"public": fmt.Sprintf("%t", lb.Scheme == elbv2types.LoadBalancerSchemeEnumInternetFacing),
					// DescribeLoadBalancers lists every enabled zone, so the count is an
					// observation (FSBP ELB.13 wants at least two).
					"availability_zone_count": strconv.Itoa(len(lb.AvailabilityZones)),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	annotateLoadBalancers(ctx, client, assets)
	return assets, edges, nil
}

func lbState(s *elbv2types.LoadBalancerState) string {
	if s == nil {
		return ""
	}
	return string(s.Code)
}
