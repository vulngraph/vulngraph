package aws

// ec2_network.go — the VPC-edge resources the CIS AWS 6.x and AWS FSBP EC2
// controls grade that collectAll's own EC2 tasks do not list: network ACLs,
// transit gateways, Site-to-Site VPN connections and Client VPN endpoints.
// Each is its own regional collector (regionalServices), so a role denied
// one Describe call loses only that resource type for the region.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type ec2NetworkAPI interface {
	DescribeNetworkAcls(context.Context, *ec2.DescribeNetworkAclsInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
	DescribeTransitGateways(context.Context, *ec2.DescribeTransitGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeTransitGatewaysOutput, error)
	DescribeVpnConnections(context.Context, *ec2.DescribeVpnConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpnConnectionsOutput, error)
	DescribeClientVpnEndpoints(context.Context, *ec2.DescribeClientVpnEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error)
}

// ec2NetworkClient builds the region-scoped EC2 client the collectors below
// share.
func ec2NetworkClient(ctx context.Context, cfg map[string]string) (*ec2.Client, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("ec2NetworkClient: %w", err)
	}
	return ec2.NewFromConfig(awsCfg), nil
}

// naclEntry is one ingress entry of a network ACL, as stored in the
// network_acl `ingress_entries` key. Protocol is AWS's IANA number string
// ("6" TCP, "17" UDP, "-1" all); an entry without a port range covers every
// port. CIDR is the IPv4 or the IPv6 block, whichever the entry carries.
type naclEntry struct {
	RuleNumber int32  `json:"rule_number"`
	Protocol   string `json:"protocol"`
	Action     string `json:"action"`
	CIDR       string `json:"cidr"`
	FromPort   int32  `json:"from_port"`
	ToPort     int32  `json:"to_port"`
}

func collectNetworkACLs(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	client, err := ec2NetworkClient(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectNetworkACLs: %w", err)
	}
	return readNetworkACLs(ctx, client, region, accountID, now)
}

// readNetworkACLs lists every network ACL in the region. The subnets an ACL
// filters are its associations; whether any of them is public is stamped
// later by annotateRouting, once the region's route tables are read.
func readNetworkACLs(ctx context.Context, client ec2NetworkAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("readNetworkACLs: %w", err)
		}
		for _, acl := range out.NetworkAcls {
			id := awssdk.ToString(acl.NetworkAclId)
			if id == "" {
				continue
			}
			var subnets []string
			for _, as := range acl.Associations {
				if sn := awssdk.ToString(as.SubnetId); sn != "" {
					subnets = append(subnets, sn)
				}
			}
			entries, err := json.Marshal(naclIngressEntries(acl.Entries))
			if err != nil {
				return nil, fmt.Errorf("readNetworkACLs: %s: %w", id, err)
			}
			assets = append(assets, asset.Asset{
				ID:        id,
				Name:      nameTag(acl.Tags, id),
				Type:      "network_acl",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Tags:      tagMap(acl.Tags),
				Metadata: map[string]string{
					"vpc_id":                   awssdk.ToString(acl.VpcId),
					"is_default":               strconv.FormatBool(awssdk.ToBool(acl.IsDefault)),
					"subnet_ids":               strings.Join(subnets, ","),
					"subnet_association_count": strconv.Itoa(len(subnets)),
					"ingress_entries":          string(entries),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}

// naclIngressEntries keeps the inbound entries in evaluation order (lowest
// rule number first, which is how AWS evaluates them: the first match
// decides). The catch-all `*` entry arrives as rule 32767 and sorts last.
func naclIngressEntries(entries []ec2types.NetworkAclEntry) []naclEntry {
	out := []naclEntry{}
	for _, e := range entries {
		if awssdk.ToBool(e.Egress) {
			continue
		}
		cidr := awssdk.ToString(e.CidrBlock)
		if cidr == "" {
			cidr = awssdk.ToString(e.Ipv6CidrBlock)
		}
		ne := naclEntry{
			RuleNumber: awssdk.ToInt32(e.RuleNumber),
			Protocol:   awssdk.ToString(e.Protocol),
			Action:     string(e.RuleAction),
			CIDR:       cidr,
			FromPort:   0,
			ToPort:     65535,
		}
		if e.PortRange != nil && e.PortRange.From != nil && e.PortRange.To != nil {
			ne.FromPort, ne.ToPort = *e.PortRange.From, *e.PortRange.To
		}
		out = append(out, ne)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleNumber < out[j].RuleNumber })
	return out
}

func collectTransitGateways(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	client, err := ec2NetworkClient(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectTransitGateways: %w", err)
	}
	return readTransitGateways(ctx, client, region, accountID, now)
}

// readTransitGateways lists the transit gateways this account owns. One shared
// in through RAM is listed too but only its owner can change its options, so
// it is left to the owner's connector.
func readTransitGateways(ctx context.Context, client ec2NetworkAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("readTransitGateways: %w", err)
		}
		for _, tgw := range out.TransitGateways {
			id := awssdk.ToString(tgw.TransitGatewayId)
			owner := awssdk.ToString(tgw.OwnerId)
			if id == "" || tgw.State == ec2types.TransitGatewayStateDeleted || tgw.State == ec2types.TransitGatewayStateDeleting ||
				(owner != "" && accountID != "" && owner != accountID) {
				continue
			}
			meta := map[string]string{"state": string(tgw.State)}
			if tgw.Options != nil && tgw.Options.AutoAcceptSharedAttachments != "" {
				meta["auto_accept_shared_attachments"] = string(tgw.Options.AutoAcceptSharedAttachments)
			}
			assets = append(assets, asset.Asset{
				ID:           id,
				Name:         nameTag(tgw.Tags, id),
				Type:         "transit_gateway",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Tags:         tagMap(tgw.Tags),
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}
