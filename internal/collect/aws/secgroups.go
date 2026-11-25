package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// sgIngressRule is the JSON shape serialized into a security_group asset's
// metadata["ingress"]. The reachability and sg-allows correlation rules parse
// it to build the SG graph and compute internet exposure without a second API
// call. CIDRs, SGRefs and PrefixLists are the rule's sources.
//
// CIDRs carries IPv4 AND IPv6 ranges in one list (0.0.0.0/0 and ::/0 are both
// the world): every consumer — internal/checks and correlate's secgroups.go —
// already parses cidrs and matches both world forms, so an IPv6-only world rule
// is visible to all of them without a second field each would have to learn.
// PrefixLists are managed prefix-list IDs (pl-…); their CIDRs live behind
// another API, so they are recorded as references, never as the world.
type sgIngressRule struct {
	Protocol    string   `json:"protocol"`
	FromPort    int32    `json:"from_port"`
	ToPort      int32    `json:"to_port"`
	CIDRs       []string `json:"cidrs,omitempty"`
	SGRefs      []string `json:"sg_refs,omitempty"`
	PrefixLists []string `json:"prefix_lists,omitempty"`
}

func collectSecurityGroups(ctx context.Context, client ec2API, region, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	var (
		assets []asset.Asset
		edges  []asset.Edge
		token  *string
	)
	for {
		out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{NextToken: token})
		if err != nil {
			return nil, nil, fmt.Errorf("collectSecurityGroups: %w", err)
		}
		for _, sg := range out.SecurityGroups {
			id := awssdk.ToString(sg.GroupId)
			meta := map[string]string{
				"vpc_id":      awssdk.ToString(sg.VpcId),
				"description": awssdk.ToString(sg.Description),
				// Rule counts are written on every described group, unlike
				// ingress/egress which are omitted when empty: a check asking
				// "does this group allow anything at all" (the default-group
				// rule) needs "zero rules" as an observation, and an absent JSON
				// key cannot say that.
				"ingress_rules": strconv.Itoa(len(sg.IpPermissions)),
				"egress_rules":  strconv.Itoa(len(sg.IpPermissionsEgress)),
			}
			if ingress := sgIngress(sg.IpPermissions); ingress != "" {
				meta["ingress"] = ingress
			}
			// Egress rules — same serialization. Unrestricted egress (0.0.0.0/0)
			// is a data-exfil path the egress check flags.
			if egress := sgIngress(sg.IpPermissionsEgress); egress != "" {
				meta["egress"] = egress
			}
			assets = append(assets, asset.Asset{
				ID:           id,
				Name:         awssdk.ToString(sg.GroupName),
				Type:         "security_group",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Tags:         tagMap(sg.Tags),
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
			if vpc := awssdk.ToString(sg.VpcId); vpc != "" {
				edges = append(edges, asset.Edge{
					SrcID: id, SrcType: "security_group",
					DstID: vpc, DstType: "vpc",
					EdgeType: "in_vpc",
				})
			}
		}
		if out.NextToken == nil {
			return assets, edges, nil
		}
		token = out.NextToken
	}
}

// sgIngress serializes a security group's inbound rules into the JSON shape the
// reachability rules consume. Returns "" when there are no rules.
func sgIngress(perms []ec2types.IpPermission) string {
	if len(perms) == 0 {
		return ""
	}
	rules := make([]sgIngressRule, 0, len(perms))
	for _, p := range perms {
		r := sgIngressRule{
			Protocol: awssdk.ToString(p.IpProtocol),
			FromPort: awssdk.ToInt32(p.FromPort),
			ToPort:   awssdk.ToInt32(p.ToPort),
		}
		for _, ip := range p.IpRanges {
			if c := awssdk.ToString(ip.CidrIp); c != "" {
				r.CIDRs = append(r.CIDRs, c)
			}
		}
		for _, ip := range p.Ipv6Ranges {
			if c := awssdk.ToString(ip.CidrIpv6); c != "" {
				r.CIDRs = append(r.CIDRs, c)
			}
		}
		for _, pl := range p.PrefixListIds {
			if id := awssdk.ToString(pl.PrefixListId); id != "" {
				r.PrefixLists = append(r.PrefixLists, id)
			}
		}
		for _, g := range p.UserIdGroupPairs {
			if gid := awssdk.ToString(g.GroupId); gid != "" {
				r.SGRefs = append(r.SGRefs, gid)
			}
		}
		rules = append(rules, r)
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return ""
	}
	return string(b)
}
