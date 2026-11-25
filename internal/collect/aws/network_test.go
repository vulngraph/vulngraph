package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func v4Route(dst string, set func(*ec2types.Route)) ec2types.Route {
	r := ec2types.Route{DestinationCidrBlock: awssdk.String(dst), State: ec2types.RouteStateActive}
	set(&r)
	return r
}

func v6Route(dst string, set func(*ec2types.Route)) ec2types.Route {
	r := ec2types.Route{DestinationIpv6CidrBlock: awssdk.String(dst), State: ec2types.RouteStateActive}
	set(&r)
	return r
}

func viaGateway(id string) func(*ec2types.Route) {
	return func(r *ec2types.Route) { r.GatewayId = awssdk.String(id) }
}

func viaNAT(r *ec2types.Route)  { r.NatGatewayId = awssdk.String("nat-1") }
func viaEIGW(r *ec2types.Route) { r.EgressOnlyInternetGatewayId = awssdk.String("eigw-1") }
func viaTGW(r *ec2types.Route)  { r.TransitGatewayId = awssdk.String("tgw-1") }
func viaPCX(r *ec2types.Route)  { r.VpcPeeringConnectionId = awssdk.String("pcx-1") }
func viaENI(r *ec2types.Route)  { r.NetworkInterfaceId = awssdk.String("eni-1") }

var localRoute = v4Route("10.0.0.0/16", viaGateway("local"))

func TestClassifyRoutes(t *testing.T) {
	tests := []struct {
		name   string
		routes []ec2types.Route
		public string
		egress string
	}{
		{"default IPv4 route to an IGW is public", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaGateway("igw-1"))}, "true", egressIGW},
		{"default IPv6 route to an IGW is public", []ec2types.Route{localRoute, v6Route("::/0", viaGateway("igw-1"))}, "true", egressIGW},
		{"a narrower IGW route still makes the subnet public", []ec2types.Route{localRoute, v4Route("203.0.113.0/24", viaGateway("igw-1")), v4Route("0.0.0.0/0", viaNAT)}, "true", egressNAT},
		{"default route to a NAT gateway is private", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaNAT)}, "false", egressNAT},
		{"egress-only IGW is outbound-only", []ec2types.Route{localRoute, v6Route("::/0", viaEIGW)}, "false", egressNAT},
		{"no default route is private and isolated", []ec2types.Route{localRoute}, "false", egressNone},
		{"no routes at all is private", nil, "false", egressNone},
		{"a blackholed IGW route carries nothing", []ec2types.Route{localRoute, func() ec2types.Route {
			r := v4Route("0.0.0.0/0", viaGateway("igw-gone"))
			r.State = ec2types.RouteStateBlackhole
			return r
		}()}, "false", egressNone},
		{"default route to a transit gateway is unknown", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaTGW)}, "", egressUnknown},
		{"default route over peering is unknown", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaPCX)}, "", egressUnknown},
		{"default route to an appliance ENI is unknown", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaENI)}, "", egressUnknown},
		{"default route to a GWLB endpoint is unknown", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaGateway("vpce-1"))}, "", egressUnknown},
		{"default route to a VPN gateway is unknown", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaGateway("vgw-1"))}, "", egressUnknown},
		{"a confirmed NAT path wins egress, the opaque one keeps public unknown", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaNAT), v6Route("::/0", viaTGW)}, "", egressNAT},
		{"a non-default TGW route does not make public-ness unknown", []ec2types.Route{localRoute, v4Route("10.0.0.0/8", viaTGW), v4Route("0.0.0.0/0", viaNAT)}, "false", egressNAT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := classifyRoutes(tt.routes)
			require.Equal(t, tt.public, v.public)
			require.Equal(t, tt.egress, v.egress)
		})
	}
}

func TestClassifyRoutes_IPv6(t *testing.T) {
	blackholed := v6Route("::/0", viaGateway("igw-gone"))
	blackholed.State = ec2types.RouteStateBlackhole
	prefixList := ec2types.Route{DestinationPrefixListId: awssdk.String("pl-1"), GatewayId: awssdk.String("igw-1"), State: ec2types.RouteStateActive}
	tests := []struct {
		name     string
		routes   []ec2types.Route
		public   string
		publicV6 string
	}{
		{"IPv4 to an IGW, IPv6 to an egress-only IGW", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaGateway("igw-1")), v6Route("::/0", viaEIGW)}, "true", "false"},
		{"IPv6 default to an IGW", []ec2types.Route{localRoute, v6Route("::/0", viaGateway("igw-1"))}, "true", "true"},
		{"a narrower IPv6 IGW route", []ec2types.Route{localRoute, v6Route("2001:db8::/32", viaGateway("igw-1")), v6Route("::/0", viaEIGW)}, "true", "true"},
		{"an IGW route to a prefix list is unknown for IPv6", []ec2types.Route{localRoute, prefixList}, "true", ""},
		{"IPv6 default to a transit gateway is unknown", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaGateway("igw-1")), v6Route("::/0", viaTGW)}, "true", ""},
		{"an IPv4 opaque default leaves IPv6 known", []ec2types.Route{localRoute, v4Route("0.0.0.0/0", viaTGW)}, "", "false"},
		{"a blackholed IPv6 IGW route carries nothing", []ec2types.Route{localRoute, blackholed}, "false", "false"},
		{"no routes at all", nil, "false", "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := classifyRoutes(tt.routes)
			require.Equal(t, tt.public, v.public)
			require.Equal(t, tt.publicV6, v.publicV6)
		})
	}
}

func routeTable(id, vpc string, main bool, subnets []string, routes ...ec2types.Route) ec2types.RouteTable {
	rt := ec2types.RouteTable{RouteTableId: awssdk.String(id), VpcId: awssdk.String(vpc), Routes: routes}
	if main {
		rt.Associations = append(rt.Associations, ec2types.RouteTableAssociation{Main: awssdk.Bool(true)})
	}
	for _, sn := range subnets {
		rt.Associations = append(rt.Associations, ec2types.RouteTableAssociation{SubnetId: awssdk.String(sn)})
	}
	return rt
}

func TestCollectRouteTables_PaginatesAndResolvesAssociations(t *testing.T) {
	f := &fakeEC2{routeTablePages: [][]ec2types.RouteTable{
		{routeTable("rtb-main", "vpc-1", true, nil, localRoute, v4Route("0.0.0.0/0", viaNAT))},
		{routeTable("rtb-pub", "vpc-1", false, []string{"subnet-pub"}, localRoute, v4Route("0.0.0.0/0", viaGateway("igw-1"))),
			{
				RouteTableId: awssdk.String("rtb-stale"), VpcId: awssdk.String("vpc-1"),
				Associations: []ec2types.RouteTableAssociation{{
					SubnetId:         awssdk.String("subnet-old"),
					AssociationState: &ec2types.RouteTableAssociationState{State: ec2types.RouteTableAssociationStateCodeDisassociated},
				}},
			}},
	}}
	rr, err := collectRouteTables(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, 2, f.routeTableCall, "every page must be read")

	id, v, ok := rr.forSubnet("subnet-pub", "vpc-1")
	require.True(t, ok)
	require.Equal(t, "rtb-pub", id)
	require.Equal(t, "true", v.public)

	id, v, ok = rr.forSubnet("subnet-priv", "vpc-1")
	require.True(t, ok)
	require.Equal(t, "rtb-main", id, "an unassociated subnet falls back to its VPC's main table")
	require.Equal(t, "false", v.public)

	id, _, ok = rr.forSubnet("subnet-old", "vpc-1")
	require.True(t, ok)
	require.Equal(t, "rtb-main", id, "a disassociated association no longer routes the subnet")

	_, _, ok = rr.forSubnet("subnet-x", "vpc-unknown")
	require.False(t, ok, "no explicit and no main table is unknown, not private")
}

func TestCollectRouteTables_ErrorReturnsNothing(t *testing.T) {
	rr, err := collectRouteTables(context.Background(), &fakeEC2{routeTablesErr: apiErr{code: "UnauthorizedOperation"}})
	require.Error(t, err)
	require.Nil(t, rr, "a failed read must not yield a partial routing table that reads as private")
}

func subnetAsset(id, region, vpc string) asset.Asset {
	return asset.Asset{ID: id, Type: "subnet", Provider: asset.ProviderAWS, Region: region,
		Metadata: map[string]string{"vpc_id": vpc}}
}

func TestAnnotateRouting(t *testing.T) {
	rr := &regionRoutes{
		explicit: map[string]string{"subnet-pub": "rtb-pub", "subnet-tgw": "rtb-tgw", "subnet-v4igw": "rtb-v4igw"},
		main:     map[string]string{"vpc-1": "rtb-main"},
		verdicts: map[string]routeVerdict{
			"rtb-pub":   {public: "true", publicV6: "true", egress: egressIGW},
			"rtb-main":  {public: "false", publicV6: "false", egress: egressNAT},
			"rtb-tgw":   {public: "", publicV6: "", egress: egressUnknown},
			"rtb-v4igw": {public: "true", publicV6: "false", egress: egressIGW},
		},
	}
	assets := []asset.Asset{
		subnetAsset("subnet-pub", "eu-west-1", "vpc-1"),
		subnetAsset("subnet-priv", "eu-west-1", "vpc-1"),
		subnetAsset("subnet-tgw", "eu-west-1", "vpc-1"),
		subnetAsset("subnet-orphan", "eu-west-1", "vpc-gone"),
		subnetAsset("subnet-unread", "us-east-1", "vpc-2"),
		subnetAsset("subnet-v4igw", "eu-west-1", "vpc-1"),
		{ID: "i-pub", Type: "ec2_instance", Metadata: map[string]string{"subnet_id": "subnet-pub"}},
		{ID: "i-priv", Type: "ec2_instance", Metadata: map[string]string{"subnet_id": "subnet-priv"}},
		{ID: "i-tgw", Type: "ec2_instance", Metadata: map[string]string{"subnet_id": "subnet-tgw"}},
		{ID: "i-unread", Type: "ec2_instance", Metadata: map[string]string{"subnet_id": "subnet-unread"}},
		{ID: "i-nosubnet", Type: "ec2_instance", Metadata: map[string]string{"subnet_id": ""}},
		{ID: "i-v4igw", Type: "ec2_instance", Metadata: map[string]string{"subnet_id": "subnet-v4igw"}},
		{ID: "db-mixed", Type: "rds_instance", Metadata: map[string]string{"subnet_ids": "subnet-priv,subnet-pub"}},
		{ID: "db-private", Type: "rds_instance", Metadata: map[string]string{"subnet_ids": "subnet-priv"}},
		{ID: "db-partly-unknown", Type: "rds_instance", Metadata: map[string]string{"subnet_ids": "subnet-priv,subnet-tgw"}},
		{ID: "db-no-group", Type: "rds_instance", Metadata: map[string]string{}},
	}
	annotateRouting(assets, map[string]*regionRoutes{"eu-west-1": rr})

	by := map[string]map[string]string{}
	for _, a := range assets {
		by[a.ID] = a.Metadata
	}

	require.Equal(t, map[string]string{"vpc_id": "vpc-1", "public_subnet": "true", "egress_via": egressIGW, "route_table_id": "rtb-pub"}, by["subnet-pub"])
	require.Equal(t, map[string]string{"vpc_id": "vpc-1", "public_subnet": "false", "egress_via": egressNAT, "route_table_id": "rtb-main"}, by["subnet-priv"])
	require.Equal(t, map[string]string{"vpc_id": "vpc-1", "egress_via": egressUnknown, "route_table_id": "rtb-tgw"}, by["subnet-tgw"],
		"an opaque default route leaves public_subnet ABSENT")
	require.Equal(t, map[string]string{"vpc_id": "vpc-gone", "egress_via": egressUnknown}, by["subnet-orphan"])
	require.Equal(t, map[string]string{"vpc_id": "vpc-2"}, by["subnet-unread"],
		"a region whose route tables were not read gets no routing keys at all")

	in := func(id string) (string, bool) { v, ok := by[id]["in_public_subnet"]; return v, ok }
	for _, tc := range []struct {
		id   string
		want string // "" = key absent
	}{
		{"i-pub", "true"}, {"i-priv", "false"}, {"i-tgw", ""}, {"i-unread", ""}, {"i-nosubnet", ""},
		{"db-mixed", "true"}, {"db-private", "false"}, {"db-partly-unknown", ""}, {"db-no-group", ""},
	} {
		v, ok := in(tc.id)
		if tc.want == "" {
			require.Falsef(t, ok, "%s: unknown placement must leave in_public_subnet absent, got %q", tc.id, v)
			continue
		}
		require.Equalf(t, tc.want, v, tc.id)
	}

	for _, tc := range []struct {
		id   string
		want string // "" = key absent
	}{
		{"i-pub", "true"}, {"i-priv", "false"}, {"i-v4igw", "false"}, {"i-tgw", ""}, {"i-unread", ""},
		{"db-mixed", ""}, {"db-private", ""},
	} {
		v, ok := by[tc.id]["in_public_subnet_v6"]
		if tc.want == "" {
			require.Falsef(t, ok, "%s: in_public_subnet_v6 must be absent, got %q", tc.id, v)
			continue
		}
		require.Equalf(t, tc.want, v, tc.id)
	}
	require.Equal(t, "true", by["i-v4igw"]["in_public_subnet"], "an IPv4-only IGW route still makes the subnet public for IPv4")
}

func TestCollect_RoutingFlowsToSubnetsAndInstances(t *testing.T) {
	newFake := func() *fakeEC2 {
		return &fakeEC2{
			sgPages: []*ec2.DescribeSecurityGroupsOutput{{}},
			subnets: []ec2types.Subnet{
				{SubnetId: awssdk.String("subnet-pub"), VpcId: awssdk.String("vpc-1")},
				{SubnetId: awssdk.String("subnet-priv"), VpcId: awssdk.String("vpc-1")},
			},
			routeTablePages: [][]ec2types.RouteTable{{
				routeTable("rtb-main", "vpc-1", true, nil, localRoute, v4Route("0.0.0.0/0", viaNAT)),
				routeTable("rtb-pub", "vpc-1", false, []string{"subnet-pub"}, localRoute, v4Route("0.0.0.0/0", viaGateway("igw-1"))),
			}},
			instancePages: []*ec2.DescribeInstancesOutput{{Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{
				InstanceId:      awssdk.String("i-1"),
				PublicIpAddress: awssdk.String("1.2.3.4"),
				SubnetId:        awssdk.String("subnet-priv"),
				State:           &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
			}}}}}},
		}
	}

	res, err := withFake(newFake()).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, res.Partial)
	by := map[string]asset.Asset{}
	for _, a := range res.Assets {
		by[a.ID] = a
	}
	require.Equal(t, "true", by["subnet-pub"].Metadata["public_subnet"])
	require.Equal(t, "false", by["subnet-priv"].Metadata["public_subnet"])
	require.Equal(t, "false", by["i-1"].Metadata["in_public_subnet"])

	// A refused DescribeRouteTables flags the sweep partial and writes no
	// routing key anywhere — never "false".
	f := newFake()
	f.routeTablesErr = apiErr{code: "UnauthorizedOperation"}
	res, err = withFake(f).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, res.Partial)
	for _, a := range res.Assets {
		require.NotContains(t, a.Metadata, "public_subnet", a.ID)
		require.NotContains(t, a.Metadata, "in_public_subnet", a.ID)
		require.NotContains(t, a.Metadata, "egress_via", a.ID)
	}
}

func TestRDSSubnetIDs(t *testing.T) {
	require.Empty(t, rdsSubnetIDs(nil), "no subnet group in the response is unknown placement")
	require.Equal(t, "subnet-a,subnet-b", rdsSubnetIDs(&rdstypes.DBSubnetGroup{Subnets: []rdstypes.Subnet{
		{SubnetIdentifier: awssdk.String("subnet-a")}, {SubnetIdentifier: awssdk.String("")}, {SubnetIdentifier: awssdk.String("subnet-b")},
	}}))
}
