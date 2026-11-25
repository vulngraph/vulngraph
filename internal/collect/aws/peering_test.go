package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

// peeringEC2 serves paginated peering connections.
type peeringEC2 struct {
	fakeEC2
	pages [][]ec2types.VpcPeeringConnection
	calls int
}

func (p *peeringEC2) DescribeVpcPeeringConnections(_ context.Context, in *ec2.DescribeVpcPeeringConnectionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcPeeringConnectionsOutput, error) {
	idx := 0
	if in.NextToken != nil {
		idx = 1
	}
	p.calls++
	out := &ec2.DescribeVpcPeeringConnectionsOutput{VpcPeeringConnections: p.pages[idx]}
	if idx+1 < len(p.pages) {
		out.NextToken = awssdk.String("next")
	}
	return out, nil
}

func peering(id, req, acc string) ec2types.VpcPeeringConnection {
	return ec2types.VpcPeeringConnection{
		VpcPeeringConnectionId: awssdk.String(id),
		Status:                 &ec2types.VpcPeeringConnectionStateReason{Code: ec2types.VpcPeeringConnectionStateReasonCodeActive},
		RequesterVpcInfo:       &ec2types.VpcPeeringConnectionVpcInfo{VpcId: awssdk.String(req)},
		AccepterVpcInfo:        &ec2types.VpcPeeringConnectionVpcInfo{VpcId: awssdk.String(acc)},
	}
}

func TestCollectVPCPeerings_Paginates(t *testing.T) {
	p := &peeringEC2{pages: [][]ec2types.VpcPeeringConnection{
		{peering("pcx-1", "vpc-a", "vpc-b")},
		{peering("pcx-2", "vpc-c", "vpc-d")},
	}}
	got, err := collectVPCPeerings(context.Background(), p)
	require.NoError(t, err)
	require.Equal(t, 2, p.calls)
	require.Len(t, got, 2)
	require.Len(t, got[1].edges, 2, "both directions of the second page's peering")
}

// Peering is collected in every region, and a cross-region peering listed in
// both of its regions is emitted once.
func TestCollect_PeeringPerRegionDeduped(t *testing.T) {
	pages := [][]ec2types.VpcPeeringConnection{{peering("pcx-x", "vpc-eu", "vpc-us")}}
	c := &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return &peeringEC2{
			fakeEC2: fakeEC2{sgPages: []*ec2.DescribeSecurityGroupsOutput{{}}, instancePages: []*ec2.DescribeInstancesOutput{{}}},
			pages:   pages,
		}, "eu-west-1", nil
	}}
	res, err := c.Collect(context.Background(), map[string]string{"regions": "eu-west-1,us-east-1"})
	require.NoError(t, err)
	n := 0
	for _, e := range res.Edges {
		if e.EdgeType == "peered_with" {
			n++
		}
	}
	require.Equal(t, 2, n, "one peering, two directions, not duplicated per region")
}
