package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// vpcPeering is one active peering connection's pair of peered_with edges,
// keyed by peering ID so a cross-region peering listed in both regions is
// emitted once.
type vpcPeering struct {
	id    string
	edges []asset.Edge
}

// collectVPCPeerings lists the region's active VPC peering connections, every
// page, and returns bidirectional peered_with edges between the two VPC assets.
// Peering expands the blast radius of compromised instances: an attacker who
// owns a host in VPC A can reach all resources in peered VPC B if routing and
// security groups permit — a key input for blast-radius enrichment.
func collectVPCPeerings(ctx context.Context, client ec2API) ([]vpcPeering, error) {
	var (
		out   []vpcPeering
		token *string
	)
	for {
		page, err := client.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("collectVPCPeerings: %w", err)
		}
		for _, pc := range page.VpcPeeringConnections {
			if pc.Status == nil || string(pc.Status.Code) != "active" {
				continue
			}
			if pc.RequesterVpcInfo == nil || pc.AccepterVpcInfo == nil {
				continue
			}
			reqID := awssdk.ToString(pc.RequesterVpcInfo.VpcId)
			accID := awssdk.ToString(pc.AccepterVpcInfo.VpcId)
			if reqID == "" || accID == "" {
				continue
			}
			pcID := awssdk.ToString(pc.VpcPeeringConnectionId)
			props := map[string]string{
				"peering_id":      pcID,
				"requester_owner": awssdk.ToString(pc.RequesterVpcInfo.OwnerId),
				"accepter_owner":  awssdk.ToString(pc.AccepterVpcInfo.OwnerId),
			}
			key := pcID
			if key == "" {
				key = reqID + "|" + accID
			}
			// Bidirectional — traffic flows both ways in an active peering.
			out = append(out, vpcPeering{id: key, edges: []asset.Edge{
				{SrcID: reqID, SrcType: "vpc", DstID: accID, DstType: "vpc", EdgeType: "peered_with", Properties: props},
				{SrcID: accID, SrcType: "vpc", DstID: reqID, DstType: "vpc", EdgeType: "peered_with", Properties: props},
			}})
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}
