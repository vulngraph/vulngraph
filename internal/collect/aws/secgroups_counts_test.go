package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

// Rule counts are written even when a group has no rules, so "the default
// group allows nothing" is an observation rather than a missing key.
func TestCollectSecurityGroups_RuleCountsAlwaysWritten(t *testing.T) {
	client := &fakeEC2{sgPages: []*ec2.DescribeSecurityGroupsOutput{{SecurityGroups: []ec2types.SecurityGroup{
		{GroupId: awssdk.String("sg-empty"), GroupName: awssdk.String("default")},
		{
			GroupId: awssdk.String("sg-open"), GroupName: awssdk.String("default"),
			IpPermissions:       []ec2types.IpPermission{{IpProtocol: awssdk.String("-1")}},
			IpPermissionsEgress: []ec2types.IpPermission{{IpProtocol: awssdk.String("-1")}, {IpProtocol: awssdk.String("tcp")}},
		},
	}}}}
	assets, _, err := collectSecurityGroups(context.Background(), client, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 2)
	require.Equal(t, "0", assets[0].Metadata["ingress_rules"])
	require.Equal(t, "0", assets[0].Metadata["egress_rules"])
	require.Equal(t, "1", assets[1].Metadata["ingress_rules"])
	require.Equal(t, "2", assets[1].Metadata["egress_rules"])
}
