package aws

// network.go — VPC network topology: VPCs, subnets, and the route tables that
// decide whether a subnet is public.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// region is the AWS region being collected (e.g. "eu-west-1"), stored on each
// subnet's Region field — not the API response's own AvailabilityZone
// ("eu-west-1a"), which is a finer grain than every other asset type in this
// codebase uses for Region (Azure's azure_subnet does the same). The AZ is
// still collected, just as metadata.
func collectSubnets(ctx context.Context, client ec2API, region string, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	var (
		assets []asset.Asset
		edges  []asset.Edge
		token  *string
	)
	for {
		out, err := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{NextToken: token})
		if err != nil {
			return nil, nil, fmt.Errorf("collectSubnets: %w", err)
		}
		for _, sn := range out.Subnets {
			id := awssdk.ToString(sn.SubnetId)
			assets = append(assets, asset.Asset{
				ID:        id,
				Name:      nameTag(sn.Tags, id),
				Type:      "subnet",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Tags:      tagMap(sn.Tags),
				Metadata: map[string]string{
					"vpc_id":                  awssdk.ToString(sn.VpcId),
					"cidr_block":              awssdk.ToString(sn.CidrBlock),
					"available_ip_count":      fmt.Sprintf("%d", awssdk.ToInt32(sn.AvailableIpAddressCount)),
					"map_public_ip_on_launch": fmt.Sprintf("%t", awssdk.ToBool(sn.MapPublicIpOnLaunch)),
					"state":                   string(sn.State),
					"availability_zone":       awssdk.ToString(sn.AvailabilityZone),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
			if vpc := awssdk.ToString(sn.VpcId); vpc != "" {
				edges = append(edges, asset.Edge{
					SrcID: id, SrcType: "subnet",
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

// collectVPCs pulls VPCs as first-class nodes so the in_vpc edges from
// instances/subnets/security groups resolve to a real asset the blast-radius
// walk can traverse, rather than a dangling stub.
func collectVPCs(ctx context.Context, client ec2API, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets []asset.Asset
		token  *string
	)
	for {
		out, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("collectVPCs: %w", err)
		}
		for _, v := range out.Vpcs {
			id := awssdk.ToString(v.VpcId)
			assets = append(assets, asset.Asset{
				ID:        id,
				Name:      nameTag(v.Tags, id),
				Type:      "vpc",
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Tags:      tagMap(v.Tags),
				Metadata: map[string]string{
					"cidr_block": awssdk.ToString(v.CidrBlock),
					"is_default": fmt.Sprintf("%t", awssdk.ToBool(v.IsDefault)),
					"state":      string(v.State),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	services, err := vpcEndpointServices(ctx, client, region)
	if err != nil {
		// The VPCs are real either way; only their endpoint coverage is unread,
		// so the key stays absent rather than reading as "no endpoints".
		log.FromContext(ctx).Warn().Err(err).Str("region", region).
			Msg("vpc endpoint listing failed; endpoint coverage unknown this sweep")
		return assets, nil
	}
	for i := range assets {
		assets[i].Metadata["endpoint_services"] = strings.Join(services[assets[i].ID], ",")
	}
	return assets, nil
}

// vpcEndpointServices maps each VPC to the sorted short names of the AWS
// services it has a live endpoint for ("ec2", "ecr.api", "ssm", ...: the
// service name with its "com.amazonaws.<region>." prefix removed). Any page
// error fails the whole read: a short list would read as missing endpoints.
func vpcEndpointServices(ctx context.Context, client ec2API, region string) (map[string][]string, error) {
	prefix := "com.amazonaws." + region + "."
	sets := map[string]map[string]bool{}
	var token *string
	for {
		out, err := client.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("vpcEndpointServices: %w", err)
		}
		for _, ep := range out.VpcEndpoints {
			if deadEndpointState(ep.State) {
				continue
			}
			vpc, svc := awssdk.ToString(ep.VpcId), strings.TrimPrefix(awssdk.ToString(ep.ServiceName), prefix)
			if vpc == "" || svc == "" {
				continue
			}
			if sets[vpc] == nil {
				sets[vpc] = map[string]bool{}
			}
			sets[vpc][svc] = true
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	result := make(map[string][]string, len(sets))
	for vpc, set := range sets {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		result[vpc] = names
	}
	return result, nil
}

// deadEndpointState reports an endpoint that carries no traffic. The SDK's
// State constants are capitalised ("Deleted") but DescribeVpcEndpoints
// returns lowercase ("deleted"), so the comparison ignores case.
func deadEndpointState(s ec2types.State) bool {
	for _, dead := range []ec2types.State{ec2types.StateDeleted, ec2types.StateDeleting, ec2types.StateFailed, ec2types.StateRejected, ec2types.StateExpired} {
		if strings.EqualFold(string(s), string(dead)) {
			return true
		}
	}
	return false
}

// Values of the subnet `egress_via` key. It answers "how does this subnet's
// default route leave the VPC", strongest confirmed path first: a default
// route to an internet gateway beats one to an outbound-only gateway (a NAT
// gateway, or an IPv6 egress-only IGW), which beats a default route to a hop
// whose onward path is invisible from here, which beats no default route.
const (
	egressIGW     = "igw"
	egressNAT     = "nat"
	egressUnknown = "unknown"
	egressNone    = "none"
)

// routeVerdict is what one route table says about the subnets that use it.
// public and publicV6 are "true", "false", or "" for unknown — never a zero
// value standing in for a measurement. publicV6 is the IPv6-only answer: an
// address reachable only over IPv6 needs an IPv6 route to an internet gateway,
// and an IPv4 one does not carry its replies.
type routeVerdict struct {
	public   string
	publicV6 string
	egress   string
}

// regionRoutes is one region's complete DescribeRouteTables read: explicit
// subnet associations, each VPC's main table, and every table's verdict.
type regionRoutes struct {
	explicit map[string]string // subnet id → route table id
	main     map[string]string // vpc id → main route table id
	verdicts map[string]routeVerdict
}

// collectRouteTables reads every route table in the region. Like every other
// paginated collector here it returns (nil, err) on any page error, so a nil
// error means the whole region's routing was read — the only condition under
// which classifyRoutes' "false" (no internet gateway route) is an observation.
func collectRouteTables(ctx context.Context, client ec2API) (*regionRoutes, error) {
	out := &regionRoutes{
		explicit: map[string]string{},
		main:     map[string]string{},
		verdicts: map[string]routeVerdict{},
	}
	var token *string
	for {
		page, err := client.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("collectRouteTables: %w", err)
		}
		for _, rt := range page.RouteTables {
			id := awssdk.ToString(rt.RouteTableId)
			out.verdicts[id] = classifyRoutes(rt.Routes)
			for _, as := range rt.Associations {
				if as.AssociationState != nil && as.AssociationState.State != ec2types.RouteTableAssociationStateCodeAssociated {
					continue
				}
				if awssdk.ToBool(as.Main) {
					out.main[awssdk.ToString(rt.VpcId)] = id
				}
				if sn := awssdk.ToString(as.SubnetId); sn != "" {
					out.explicit[sn] = id
				}
			}
		}
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}

// classifyRoutes decides whether a route table makes its subnets public.
//
//   - true: some active route targets an internet gateway (igw-*). Any
//     destination counts, not only 0.0.0.0/0 and ::/0 — a route to an IGW for
//     a narrower public range still lets those internet hosts reach a public
//     IP in the subnet and get replies.
//   - unknown: no IGW route, but a DEFAULT route (0.0.0.0/0 or ::/0) goes to a
//     hop whose onward path cannot be seen from this table — transit gateway,
//     peering, VPN/virtual private gateway, an appliance ENI/instance, a
//     gateway-load-balancer endpoint, a carrier/local gateway, Cloud WAN. A
//     firewall-inspection VPC routes exactly like this and still serves
//     internet traffic, so "false" would be a guess.
//   - false: neither. The default route is absent or goes only to a NAT
//     gateway / egress-only IGW, both outbound-only, so a public IP in the
//     subnet cannot complete an inbound connection: replies leave through the
//     NAT, not the IGW the request arrived on.
//
// publicV6 asks the same question of IPv6 routes alone: true needs an IGW
// route with an IPv6 destination; an IGW route to a prefix list (whose family
// this table does not show) or a ::/0 route to an opaque hop leaves it unknown.
//
// Blackhole routes (a detached IGW, a deleted NAT gateway) carry no traffic
// and are ignored, which is why DescribeInternetGateways/DescribeNatGateways
// are not needed to tell a live gateway from a dead one.
func classifyRoutes(routes []ec2types.Route) routeVerdict {
	var igw, defaultIGW, defaultNAT, defaultOpaque bool
	var igwV6, igwAnyFamily, defaultOpaqueV6 bool
	for _, r := range routes {
		if r.State == ec2types.RouteStateBlackhole {
			continue
		}
		gw := awssdk.ToString(r.GatewayId)
		if gw == "local" {
			continue
		}
		dst4, dst6 := awssdk.ToString(r.DestinationCidrBlock), awssdk.ToString(r.DestinationIpv6CidrBlock)
		isDefaultV6 := dst6 == "::/0"
		isDefault := dst4 == "0.0.0.0/0" || isDefaultV6
		switch {
		case strings.HasPrefix(gw, "igw-"):
			igw = true
			defaultIGW = defaultIGW || isDefault
			igwV6 = igwV6 || dst6 != ""
			igwAnyFamily = igwAnyFamily || (dst4 == "" && dst6 == "")
		case awssdk.ToString(r.NatGatewayId) != "" || awssdk.ToString(r.EgressOnlyInternetGatewayId) != "":
			defaultNAT = defaultNAT || isDefault
		default:
			defaultOpaque = defaultOpaque || isDefault
			defaultOpaqueV6 = defaultOpaqueV6 || isDefaultV6
		}
	}

	v := routeVerdict{public: "false", publicV6: "false", egress: egressNone}
	switch {
	case igw:
		v.public = "true"
	case defaultOpaque:
		v.public = ""
	}
	switch {
	case igwV6:
		v.publicV6 = "true"
	case igwAnyFamily || defaultOpaqueV6:
		v.publicV6 = ""
	}
	switch {
	case defaultIGW:
		v.egress = egressIGW
	case defaultNAT:
		v.egress = egressNAT
	case defaultOpaque:
		v.egress = egressUnknown
	}
	return v
}

// forSubnet resolves a subnet's effective route table: its explicit
// association, else its VPC's main table. ok is false when neither is in the
// read (a subnet created between the two listings) — unknown, not private.
func (r *regionRoutes) forSubnet(subnetID, vpcID string) (string, routeVerdict, bool) {
	id, ok := r.explicit[subnetID]
	if !ok {
		id, ok = r.main[vpcID]
	}
	if !ok {
		return "", routeVerdict{}, false
	}
	v, ok := r.verdicts[id]
	return id, v, ok
}

// annotateRouting stamps routing facts onto the sweep's assets once every
// region has been collected. Subnets get `public_subnet` (true/false, ABSENT
// when unknown), `egress_via` and `route_table_id`; EC2 and RDS instances get
// `in_public_subnet`, the fact the exposure correlator and
// aws-rds-public-subnet-igw read without joining across asset types, and
// network ACLs get `filters_public_subnet` for the same reason. EC2 instances
// also get `in_public_subnet_v6`, the IPv6-route answer the correlator reads
// for an instance reachable only over IPv6.
//
// routes holds one entry per region whose route tables were fully read. A
// region missing from it leaves its subnets without any routing key at all,
// so a failed DescribeRouteTables can never read as "private".
func annotateRouting(assets []asset.Asset, routes map[string]*regionRoutes) {
	subnetPublic, subnetPublicV6 := map[string]string{}, map[string]string{}
	for i := range assets {
		a := &assets[i]
		if a.Type != "subnet" || a.Provider != asset.ProviderAWS {
			continue
		}
		rr := routes[a.Region]
		if rr == nil {
			continue
		}
		rtID, v, ok := rr.forSubnet(a.ID, a.Metadata["vpc_id"])
		if !ok {
			a.Metadata["egress_via"] = egressUnknown
			continue
		}
		a.Metadata["route_table_id"] = rtID
		a.Metadata["egress_via"] = v.egress
		if v.public != "" {
			a.Metadata["public_subnet"] = v.public
			subnetPublic[a.ID] = v.public
		}
		if v.publicV6 != "" {
			subnetPublicV6[a.ID] = v.publicV6
		}
	}

	for i := range assets {
		a := &assets[i]
		var ids []string
		key := "in_public_subnet"
		switch a.Type {
		case "ec2_instance":
			ids = splitCSV(a.Metadata["subnet_id"])
		case "rds_instance":
			ids = splitCSV(a.Metadata["subnet_ids"])
		case "network_acl":
			// An ACL filters every subnet associated with it, so one public
			// subnet puts its inbound entries on an internet path.
			ids = splitCSV(a.Metadata["subnet_ids"])
			key = "filters_public_subnet"
		default:
			continue
		}
		if v, ok := anyPublicSubnet(ids, subnetPublic); ok {
			a.Metadata[key] = strconv.FormatBool(v)
		}
		if a.Type != "ec2_instance" {
			continue
		}
		if v, ok := anyPublicSubnet(ids, subnetPublicV6); ok {
			a.Metadata["in_public_subnet_v6"] = strconv.FormatBool(v)
		}
	}
}

// anyPublicSubnet folds the public-ness of the subnets a resource can sit in.
// One known-public subnet is enough for true: an RDS instance can be placed in
// (or fail over to) any subnet of its group. False needs EVERY subnet known
// private; any unknown member leaves the answer unknown.
func anyPublicSubnet(ids []string, public map[string]string) (bool, bool) {
	if len(ids) == 0 {
		return false, false
	}
	allKnown := true
	for _, id := range ids {
		switch public[id] {
		case "true":
			return true, true
		case "false":
		default:
			allKnown = false
		}
	}
	return false, allKnown
}

func splitCSV(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
