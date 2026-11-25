package aws

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fakeEC2Network serves one page per call from each *Pages slice; err fails
// every call.
type fakeEC2Network struct {
	aclPages [][]ec2types.NetworkAcl
	aclCall  int
	tgws     []ec2types.TransitGateway
	vpns     []ec2types.VpnConnection
	cvpnPage [][]ec2types.ClientVpnEndpoint
	cvpnCall int
	err      error
	// failPage fails the call serving this page index (1-based; 0 = never).
	failPage int
}

func (f *fakeEC2Network) DescribeNetworkAcls(context.Context, *ec2.DescribeNetworkAclsInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.aclCall++
	if f.failPage == f.aclCall {
		return nil, errors.New("throttled")
	}
	out := &ec2.DescribeNetworkAclsOutput{}
	if f.aclCall <= len(f.aclPages) {
		out.NetworkAcls = f.aclPages[f.aclCall-1]
	}
	if f.aclCall < len(f.aclPages) {
		out.NextToken = awssdk.String("next")
	}
	return out, nil
}

func (f *fakeEC2Network) DescribeTransitGateways(context.Context, *ec2.DescribeTransitGatewaysInput, ...func(*ec2.Options)) (*ec2.DescribeTransitGatewaysOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeTransitGatewaysOutput{TransitGateways: f.tgws}, nil
}

func (f *fakeEC2Network) DescribeVpnConnections(context.Context, *ec2.DescribeVpnConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpnConnectionsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeVpnConnectionsOutput{VpnConnections: f.vpns}, nil
}

func (f *fakeEC2Network) DescribeClientVpnEndpoints(context.Context, *ec2.DescribeClientVpnEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.cvpnCall++
	out := &ec2.DescribeClientVpnEndpointsOutput{}
	if f.cvpnCall <= len(f.cvpnPage) {
		out.ClientVpnEndpoints = f.cvpnPage[f.cvpnCall-1]
	}
	if f.cvpnCall < len(f.cvpnPage) {
		out.NextToken = awssdk.String("next")
	}
	return out, nil
}

func aclEntry(n int32, egress bool, proto, action, cidr string, ports *ec2types.PortRange) ec2types.NetworkAclEntry {
	e := ec2types.NetworkAclEntry{
		RuleNumber: awssdk.Int32(n), Egress: awssdk.Bool(egress), Protocol: awssdk.String(proto),
		RuleAction: ec2types.RuleAction(action), PortRange: ports,
	}
	if cidr == "::/0" || (len(cidr) > 0 && cidr[0] == ':') {
		e.Ipv6CidrBlock = awssdk.String(cidr)
	} else {
		e.CidrBlock = awssdk.String(cidr)
	}
	return e
}

func naclPorts(from, to int32) *ec2types.PortRange {
	return &ec2types.PortRange{From: awssdk.Int32(from), To: awssdk.Int32(to)}
}

// The stock default ACL as DescribeNetworkAcls returns it.
func defaultACL(id, vpc string, subnets ...string) ec2types.NetworkAcl {
	acl := ec2types.NetworkAcl{
		NetworkAclId: awssdk.String(id), VpcId: awssdk.String(vpc), IsDefault: awssdk.Bool(true),
		Entries: []ec2types.NetworkAclEntry{
			aclEntry(32767, false, "-1", "deny", "0.0.0.0/0", nil),
			aclEntry(100, false, "-1", "allow", "0.0.0.0/0", nil),
			aclEntry(100, true, "-1", "allow", "0.0.0.0/0", nil),
			aclEntry(32767, true, "-1", "deny", "0.0.0.0/0", nil),
		},
	}
	for _, sn := range subnets {
		acl.Associations = append(acl.Associations, ec2types.NetworkAclAssociation{SubnetId: awssdk.String(sn)})
	}
	return acl
}

func TestReadNetworkACLs(t *testing.T) {
	now := time.Now()
	custom := ec2types.NetworkAcl{
		NetworkAclId: awssdk.String("acl-custom"), VpcId: awssdk.String("vpc-1"), IsDefault: awssdk.Bool(false),
		Tags: []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("web")}},
		Entries: []ec2types.NetworkAclEntry{
			aclEntry(200, false, "6", "allow", "0.0.0.0/0", naclPorts(22, 22)),
			aclEntry(100, false, "6", "deny", "0.0.0.0/0", naclPorts(22, 22)),
			aclEntry(32767, false, "-1", "deny", "0.0.0.0/0", nil),
		},
	}
	f := &fakeEC2Network{aclPages: [][]ec2types.NetworkAcl{{defaultACL("acl-def", "vpc-1", "subnet-a", "subnet-b")}, {custom}}}
	got, err := readNetworkACLs(context.Background(), f, "eu-west-1", "111", now)
	require.NoError(t, err)
	require.Len(t, got, 2, "both pages are read")

	def := got[0]
	require.Equal(t, "network_acl", def.Type)
	require.Equal(t, "true", def.Metadata["is_default"])
	require.Equal(t, "subnet-a,subnet-b", def.Metadata["subnet_ids"])
	require.Equal(t, "2", def.Metadata["subnet_association_count"])
	var entries []naclEntry
	require.NoError(t, json.Unmarshal([]byte(def.Metadata["ingress_entries"]), &entries))
	require.Equal(t, []naclEntry{
		{RuleNumber: 100, Protocol: "-1", Action: "allow", CIDR: "0.0.0.0/0", FromPort: 0, ToPort: 65535},
		{RuleNumber: 32767, Protocol: "-1", Action: "deny", CIDR: "0.0.0.0/0", FromPort: 0, ToPort: 65535},
	}, entries, "egress entries dropped; ingress sorted by rule number; no port range covers every port")

	c := got[1]
	require.Equal(t, "web", c.Name)
	require.Equal(t, "0", c.Metadata["subnet_association_count"], "no associations is an observation")
	require.Equal(t, "", c.Metadata["subnet_ids"])
	require.NoError(t, json.Unmarshal([]byte(c.Metadata["ingress_entries"]), &entries))
	require.Equal(t, int32(100), entries[0].RuleNumber, "the lower-numbered deny is evaluated first")
	require.Equal(t, int32(22), entries[0].FromPort)
}

func TestReadNetworkACLs_PageErrorFailsTheRead(t *testing.T) {
	f := &fakeEC2Network{aclPages: [][]ec2types.NetworkAcl{{defaultACL("a", "v")}, {defaultACL("b", "v")}}, failPage: 2}
	got, err := readNetworkACLs(context.Background(), f, "r", "1", time.Now())
	require.Error(t, err)
	require.Nil(t, got, "a short listing must not stand in for the region's ACLs")
}

func TestReadNetworkACLs_EmptyIngressIsObserved(t *testing.T) {
	f := &fakeEC2Network{aclPages: [][]ec2types.NetworkAcl{{{NetworkAclId: awssdk.String("acl-1")}}}}
	got, err := readNetworkACLs(context.Background(), f, "r", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "[]", got[0].Metadata["ingress_entries"])
	require.Equal(t, "false", got[0].Metadata["is_default"], "an omitted IsDefault is a custom ACL")
}

func TestAnnotateRouting_NetworkACLFiltersPublicSubnet(t *testing.T) {
	assets := []asset.Asset{
		{ID: "subnet-pub", Type: "subnet", Provider: asset.ProviderAWS, Region: "r", Metadata: map[string]string{"vpc_id": "vpc-1"}},
		{ID: "subnet-priv", Type: "subnet", Provider: asset.ProviderAWS, Region: "r", Metadata: map[string]string{"vpc_id": "vpc-1"}},
		{ID: "acl-pub", Type: "network_acl", Provider: asset.ProviderAWS, Region: "r", Metadata: map[string]string{"subnet_ids": "subnet-priv,subnet-pub"}},
		{ID: "acl-priv", Type: "network_acl", Provider: asset.ProviderAWS, Region: "r", Metadata: map[string]string{"subnet_ids": "subnet-priv"}},
		{ID: "acl-unknown", Type: "network_acl", Provider: asset.ProviderAWS, Region: "r", Metadata: map[string]string{"subnet_ids": "subnet-other"}},
		{ID: "acl-unused", Type: "network_acl", Provider: asset.ProviderAWS, Region: "r", Metadata: map[string]string{"subnet_ids": ""}},
	}
	routes := map[string]*regionRoutes{"r": {
		explicit: map[string]string{"subnet-pub": "rtb-pub"},
		main:     map[string]string{"vpc-1": "rtb-main"},
		verdicts: map[string]routeVerdict{"rtb-pub": {public: "true", egress: egressIGW}, "rtb-main": {public: "false", egress: egressNAT}},
	}}
	annotateRouting(assets, routes)
	require.Equal(t, "true", assets[2].Metadata["filters_public_subnet"])
	require.Equal(t, "false", assets[3].Metadata["filters_public_subnet"])
	require.NotContains(t, assets[4].Metadata, "filters_public_subnet", "a subnet the sweep did not classify leaves it unknown")
	require.NotContains(t, assets[5].Metadata, "filters_public_subnet")
}

func TestReadTransitGateways(t *testing.T) {
	f := &fakeEC2Network{tgws: []ec2types.TransitGateway{
		{TransitGatewayId: awssdk.String("tgw-auto"), OwnerId: awssdk.String("111"), State: ec2types.TransitGatewayStateAvailable,
			Options: &ec2types.TransitGatewayOptions{AutoAcceptSharedAttachments: ec2types.AutoAcceptSharedAttachmentsValueEnable}},
		{TransitGatewayId: awssdk.String("tgw-manual"), OwnerId: awssdk.String("111"), State: ec2types.TransitGatewayStateAvailable,
			Options: &ec2types.TransitGatewayOptions{AutoAcceptSharedAttachments: ec2types.AutoAcceptSharedAttachmentsValueDisable}},
		{TransitGatewayId: awssdk.String("tgw-noopts"), OwnerId: awssdk.String("111"), State: ec2types.TransitGatewayStateAvailable},
		{TransitGatewayId: awssdk.String("tgw-shared-in"), OwnerId: awssdk.String("222"), State: ec2types.TransitGatewayStateAvailable},
		{TransitGatewayId: awssdk.String("tgw-gone"), OwnerId: awssdk.String("111"), State: ec2types.TransitGatewayStateDeleted},
	}}
	got, err := readTransitGateways(context.Background(), f, "r", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3, "another account's gateway and a deleted one are skipped")
	require.Equal(t, "enable", got[0].Metadata["auto_accept_shared_attachments"])
	require.Equal(t, "disable", got[1].Metadata["auto_accept_shared_attachments"])
	require.NotContains(t, got[2].Metadata, "auto_accept_shared_attachments", "no options returned is unknown")

	_, err = readTransitGateways(context.Background(), &fakeEC2Network{err: errors.New("denied")}, "r", "111", time.Now())
	require.Error(t, err)
}

func vpnTunnel(logging bool, ike ...string) ec2types.TunnelOption {
	t := ec2types.TunnelOption{LogOptions: &ec2types.VpnTunnelLogOptions{
		CloudWatchLogOptions: &ec2types.CloudWatchLogOptions{LogEnabled: awssdk.Bool(logging)}}}
	for _, v := range ike {
		t.IkeVersions = append(t.IkeVersions, ec2types.IKEVersionsListValue{Value: awssdk.String(v)})
	}
	return t
}

func TestReadVPNConnections(t *testing.T) {
	f := &fakeEC2Network{vpns: []ec2types.VpnConnection{
		{VpnConnectionId: awssdk.String("vpn-good"), State: ec2types.VpnStateAvailable,
			VgwTelemetry: []ec2types.VgwTelemetry{{Status: ec2types.TelemetryStatusUp}, {Status: ec2types.TelemetryStatusUp}},
			Options:      &ec2types.VpnConnectionOptions{TunnelOptions: []ec2types.TunnelOption{vpnTunnel(true, "ikev2"), vpnTunnel(true, "ikev2")}}},
		{VpnConnectionId: awssdk.String("vpn-bad"), State: ec2types.VpnStateAvailable,
			VgwTelemetry: []ec2types.VgwTelemetry{{Status: ec2types.TelemetryStatusUp}, {Status: ec2types.TelemetryStatusDown}},
			Options: &ec2types.VpnConnectionOptions{TunnelOptions: []ec2types.TunnelOption{
				vpnTunnel(true, "ikev1", "ikev2"), {}, // the second tunnel: no log options, no IKE list (both versions)
			}}},
		{VpnConnectionId: awssdk.String("vpn-bare"), State: ec2types.VpnStatePending},
		{VpnConnectionId: awssdk.String("vpn-deleted"), State: ec2types.VpnStateDeleted},
	}}
	got, err := readVPNConnections(context.Background(), f, "r", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, map[string]string{"tunnel_count": "2", "tunnels_down": "0", "tunnels_without_logging": "0", "tunnels_allowing_ikev1": "0"},
		metaSubset(got[0].Metadata, "tunnel_count", "tunnels_down", "tunnels_without_logging", "tunnels_allowing_ikev1"))
	require.Equal(t, map[string]string{"tunnel_count": "2", "tunnels_down": "1", "tunnels_without_logging": "1", "tunnels_allowing_ikev1": "2"},
		metaSubset(got[1].Metadata, "tunnel_count", "tunnels_down", "tunnels_without_logging", "tunnels_allowing_ikev1"))
	for _, k := range []string{"tunnel_count", "tunnels_down", "tunnels_without_logging", "tunnels_allowing_ikev1"} {
		require.NotContains(t, got[2].Metadata, k, "no telemetry or tunnel options is unknown, not healthy")
	}
}

func TestReadClientVPNEndpoints(t *testing.T) {
	f := &fakeEC2Network{cvpnPage: [][]ec2types.ClientVpnEndpoint{
		{{ClientVpnEndpointId: awssdk.String("cvpn-off"), Status: &ec2types.ClientVpnEndpointStatus{Code: ec2types.ClientVpnEndpointStatusCodeAvailable},
			ConnectionLogOptions: &ec2types.ConnectionLogResponseOptions{Enabled: awssdk.Bool(false)}}},
		{{ClientVpnEndpointId: awssdk.String("cvpn-on"), ConnectionLogOptions: &ec2types.ConnectionLogResponseOptions{Enabled: awssdk.Bool(true)}},
			{ClientVpnEndpointId: awssdk.String("cvpn-unread")},
			{ClientVpnEndpointId: awssdk.String("cvpn-gone"), Status: &ec2types.ClientVpnEndpointStatus{Code: ec2types.ClientVpnEndpointStatusCodeDeleted}}},
	}}
	got, err := readClientVPNEndpoints(context.Background(), f, "r", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, "false", got[0].Metadata["connection_logging"])
	require.Equal(t, "true", got[1].Metadata["connection_logging"])
	require.NotContains(t, got[2].Metadata, "connection_logging")
}

func metaSubset(m map[string]string, keys ...string) map[string]string {
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

func TestCollectVPCs_EndpointServices(t *testing.T) {
	ep := func(vpc, svc string, state ec2types.State) ec2types.VpcEndpoint {
		return ec2types.VpcEndpoint{VpcId: awssdk.String(vpc), ServiceName: awssdk.String(svc), State: state}
	}
	f := &fakeEC2{
		vpcs: []ec2types.Vpc{{VpcId: awssdk.String("vpc-1")}, {VpcId: awssdk.String("vpc-2")}, {VpcId: awssdk.String("vpc-3")}},
		vpcEndpoints: []ec2types.VpcEndpoint{
			ep("vpc-1", "com.amazonaws.eu-west-1.ssm", ec2types.StateAvailable),
			ep("vpc-1", "com.amazonaws.eu-west-1.ec2", ec2types.StatePending),
			ep("vpc-1", "com.amazonaws.eu-west-1.ecr.api", ec2types.StateDeleted),
			ep("vpc-1", "com.amazonaws.eu-west-1.ssm", ec2types.StateAvailable),
			// The API's own lowercase spelling of the dead states.
			ep("vpc-1", "com.amazonaws.eu-west-1.ecr.dkr", "deleted"),
			ep("vpc-1", "com.amazonaws.eu-west-1.ssm-contacts", "rejected"),
			ep("vpc-1", "com.amazonaws.eu-west-1.ssm-incidents", "failed"),
			ep("vpc-1", "com.amazonaws.eu-west-1.sqs", "expired"),
			ep("vpc-1", "com.amazonaws.eu-west-1.sns", "deleting"),
			ep("vpc-2", "com.amazonaws.eu-west-1.logs", "available"),
		},
	}
	got, err := collectVPCs(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "ec2,ssm", got[0].Metadata["endpoint_services"], "deduplicated, sorted, deleted endpoints dropped")
	require.Equal(t, "logs", got[1].Metadata["endpoint_services"])
	require.Equal(t, "", got[2].Metadata["endpoint_services"], "no endpoints is an observation")

	f.vpcEndpointsErr = errors.New("denied")
	got, err = collectVPCs(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err, "the VPCs themselves were read")
	require.NotContains(t, got[0].Metadata, "endpoint_services", "an unread endpoint listing is not 'no endpoints'")
}

func TestSourceDestCheckDisabled(t *testing.T) {
	ni := func(id, typ string, check *bool) ec2types.InstanceNetworkInterface {
		n := ec2types.InstanceNetworkInterface{NetworkInterfaceId: awssdk.String(id), SourceDestCheck: check}
		if typ != "" {
			n.InterfaceType = awssdk.String(typ)
		}
		return n
	}
	got := sourceDestCheckDisabled([]ec2types.InstanceNetworkInterface{
		ni("eni-off", "", awssdk.Bool(false)),
		ni("eni-on", "interface", awssdk.Bool(true)),
		ni("eni-efa", "efa", awssdk.Bool(false)),
		ni("eni-trunk", "trunk", awssdk.Bool(false)),
		ni("eni-unset", "interface", nil),
	})
	require.Equal(t, []string{"eni-off", "eni-efa"}, got)
	require.Empty(t, sourceDestCheckDisabled(nil))
}
