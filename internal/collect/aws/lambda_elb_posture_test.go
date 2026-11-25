package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/stretchr/testify/require"
)

func TestCollectLambdaFunctions_SubnetIDs(t *testing.T) {
	f := &fakeLambda{fns: []lambdatypes.FunctionConfiguration{
		{FunctionName: awssdk.String("vpc"), FunctionArn: awssdk.String("arn:vpc"), VpcConfig: &lambdatypes.VpcConfigResponse{
			VpcId: awssdk.String("vpc-1"), SubnetIds: []string{"subnet-a", "subnet-b"},
		}},
		{FunctionName: awssdk.String("plain"), FunctionArn: awssdk.String("arn:plain")},
	}}
	got, err := collectLambdaFunctions(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "subnet-a,subnet-b", got[0].Metadata["subnet_ids"])
	require.Equal(t, "", got[1].Metadata["subnet_ids"])
}

// fakeELBv2 lists lbs; the per-balancer reads come from the embedded detail
// fake (elb_detail_test.go), empty unless a test fills it.
type fakeELBv2 struct {
	lbs []elbv2types.LoadBalancer
	fakeELBv2Detail
}

func (f fakeELBv2) DescribeLoadBalancers(context.Context, *elasticloadbalancingv2.DescribeLoadBalancersInput, ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{LoadBalancers: f.lbs}, nil
}

func TestCollectLoadBalancers_AvailabilityZoneCount(t *testing.T) {
	f := fakeELBv2{lbs: []elbv2types.LoadBalancer{{
		LoadBalancerArn:   awssdk.String("arn:lb"),
		State:             &elbv2types.LoadBalancerState{Code: elbv2types.LoadBalancerStateEnumActive},
		AvailabilityZones: []elbv2types.AvailabilityZone{{ZoneName: awssdk.String("eu-west-1a")}},
	}}}
	got, _, err := collectLoadBalancers(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "1", got[0].Metadata["availability_zone_count"])
}
