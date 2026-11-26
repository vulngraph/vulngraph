package aws

import (
	"context"
	"fmt"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
)

func TestConnectorScale(t *testing.T) {
	for _, n := range collectbench.Sizes(t) {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := &fakeEC2{sgPages: []*ec2.DescribeSecurityGroupsOutput{{}}}
			for start := 0; start < n; start += 100 {
				page := &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{}}}
				for i := start; i < min(start+100, n); i++ {
					page.Reservations[0].Instances = append(page.Reservations[0].Instances, ec2types.Instance{InstanceId: awssdk.String(fmt.Sprintf("i-%08d", i)), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}, InstanceType: ec2types.InstanceTypeT3Micro})
				}
				if start+100 < n {
					page.NextToken = awssdk.String("next")
				}
				f.instancePages = append(f.instancePages, page)
			}
			c := withFake(f)
			collectbench.Run(t, "aws", "EC2 paginated inventory; SDK response fixture", "ec2_instance", n, func() { f.instCall = 0; f.sgCall = 0 }, func() (collect.Result, int, error) {
				r, err := c.Collect(context.Background(), map[string]string{"regions": "eu-west-1"})
				require.Equal(t, (n+99)/100, f.instCall)
				return r, f.instCall + f.sgCall, err
			})
		})
	}
}
