package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/stretchr/testify/require"
)

type fakeClassicELB struct {
	pages       [][]elbtypes.LoadBalancerDescription
	pageErr     error
	attrs       map[string]*elbtypes.LoadBalancerAttributes
	attrErr     error
	policies    map[string][]elbtypes.PolicyDescription
	policyErr   error
	policyCalls int
}

func (f *fakeClassicELB) DescribeLoadBalancers(_ context.Context, in *elasticloadbalancing.DescribeLoadBalancersInput, _ ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancersOutput, error) {
	i := 0
	if in.Marker != nil {
		i = 1
		if f.pageErr != nil {
			return nil, f.pageErr
		}
	}
	out := &elasticloadbalancing.DescribeLoadBalancersOutput{}
	if i < len(f.pages) {
		out.LoadBalancerDescriptions = f.pages[i]
	}
	if i == 0 && len(f.pages) > 1 {
		out.NextMarker = awssdk.String("1")
	}
	return out, nil
}

func (f *fakeClassicELB) DescribeLoadBalancerAttributes(_ context.Context, in *elasticloadbalancing.DescribeLoadBalancerAttributesInput, _ ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancerAttributesOutput, error) {
	if f.attrErr != nil {
		return nil, f.attrErr
	}
	return &elasticloadbalancing.DescribeLoadBalancerAttributesOutput{LoadBalancerAttributes: f.attrs[awssdk.ToString(in.LoadBalancerName)]}, nil
}

func (f *fakeClassicELB) DescribeLoadBalancerPolicies(_ context.Context, in *elasticloadbalancing.DescribeLoadBalancerPoliciesInput, _ ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancerPoliciesOutput, error) {
	f.policyCalls++
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	return &elasticloadbalancing.DescribeLoadBalancerPoliciesOutput{PolicyDescriptions: f.policies[awssdk.ToString(in.LoadBalancerName)]}, nil
}

func classicListener(proto string, port int32, cert string, policies ...string) elbtypes.ListenerDescription {
	l := &elbtypes.Listener{Protocol: awssdk.String(proto), LoadBalancerPort: port, InstancePort: awssdk.Int32(port)}
	if cert != "" {
		l.SSLCertificateId = awssdk.String(cert)
	}
	return elbtypes.ListenerDescription{Listener: l, PolicyNames: policies}
}

func negotiationPolicy(name, reference string) elbtypes.PolicyDescription {
	p := elbtypes.PolicyDescription{PolicyName: awssdk.String(name), PolicyTypeName: awssdk.String(sslNegotiationPolicyType),
		PolicyAttributeDescriptions: []elbtypes.PolicyAttributeDescription{{AttributeName: awssdk.String("Protocol-TLSv1.2"), AttributeValue: awssdk.String("true")}}}
	if reference != "" {
		p.PolicyAttributeDescriptions = append(p.PolicyAttributeDescriptions,
			elbtypes.PolicyAttributeDescription{AttributeName: awssdk.String(referenceSecurityPolicy), AttributeValue: awssdk.String(reference)})
	}
	return p
}

func TestListClassicELBs(t *testing.T) {
	f := &fakeClassicELB{
		pages: [][]elbtypes.LoadBalancerDescription{
			{{LoadBalancerName: awssdk.String("web"), DNSName: awssdk.String("web-1.eu-west-1.elb.amazonaws.com"),
				Scheme: awssdk.String("internet-facing"), VPCId: awssdk.String("vpc-1"), SecurityGroups: []string{"sg-1"},
				AvailabilityZones: []string{"eu-west-1a"},
				ListenerDescriptions: []elbtypes.ListenerDescription{
					classicListener("HTTPS", 443, "arn:aws:iam::1:server-certificate/old", "neg-ref"),
					classicListener("HTTP", 80, ""),
					classicListener("SSL", 8443, "arn:aws:acm:eu-west-1:1:certificate/x", "neg-custom", "stick"),
				}}},
			// Second page: a short read of the first would drop this balancer.
			{{LoadBalancerName: awssdk.String("tcp"), Scheme: awssdk.String("internal"),
				AvailabilityZones:    []string{"eu-west-1a", "eu-west-1b"},
				ListenerDescriptions: []elbtypes.ListenerDescription{classicListener("TCP", 5432, "")}}},
		},
		attrs: map[string]*elbtypes.LoadBalancerAttributes{
			"web": {ConnectionDraining: &elbtypes.ConnectionDraining{Enabled: false}, CrossZoneLoadBalancing: &elbtypes.CrossZoneLoadBalancing{Enabled: true}, AccessLog: &elbtypes.AccessLog{Enabled: false},
				AdditionalAttributes: []elbtypes.AdditionalAttribute{{Key: awssdk.String(classicDesyncAttribute), Value: awssdk.String("monitor")}}},
			// No AdditionalAttributes: desync mode is unread, not defensive.
			"tcp": {ConnectionDraining: &elbtypes.ConnectionDraining{Enabled: true}},
		},
		policies: map[string][]elbtypes.PolicyDescription{"web": {
			negotiationPolicy("neg-ref", "ELBSecurityPolicy-2016-08"),
			negotiationPolicy("neg-custom", ""),
			{PolicyName: awssdk.String("stick"), PolicyTypeName: awssdk.String("LBCookieStickinessPolicyType")},
		}},
	}
	got, err := listClassicELBs(context.Background(), f, "eu-west-1", "123456789012", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)
	web := got[0]
	require.Equal(t, "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/web", web.ID)
	require.Equal(t, "load_balancer", web.Type)
	md := web.Metadata
	require.Equal(t, lbTypeClassic, md["type"])
	require.Equal(t, "true", md["public"])
	require.Equal(t, "1", md["availability_zone_count"])
	require.Equal(t, "HTTP:80", md["plaintext_listeners"])
	require.Equal(t, "HTTPS:443", md["non_acm_certificate_listeners"])
	require.Equal(t, "HTTPS:443=ELBSecurityPolicy-2016-08,SSL:8443=custom:neg-custom", md["tls_listener_policies"])
	require.Equal(t, "false", md["connection_draining"])
	require.Equal(t, "true", md["cross_zone_load_balancing"])
	require.Equal(t, "monitor", md["desync_mitigation_mode"])
	require.Equal(t, "false", md["access_logs_s3_enabled"], "the ALB key, so ELB.5 grades Classic balancers too")

	tcp := got[1].Metadata
	require.Equal(t, "false", tcp["public"])
	require.Equal(t, "TCP:5432", tcp["plaintext_listeners"])
	require.Equal(t, "", tcp["tls_listener_policies"], "no TLS listener is an observation")
	require.NotContains(t, tcp, "desync_mitigation_mode")
	require.NotContains(t, tcp, "cross_zone_load_balancing")
	require.NotContains(t, tcp, "access_logs_s3_enabled", "an attribute set without AccessLog is unread")
	require.Equal(t, 1, f.policyCalls, "policies are read only for balancers with TLS listeners")
}

func TestListClassicELBs_FailedReads(t *testing.T) {
	lb := elbtypes.LoadBalancerDescription{LoadBalancerName: awssdk.String("web"),
		ListenerDescriptions: []elbtypes.ListenerDescription{classicListener("HTTPS", 443, "arn:aws:acm:x")}}
	f := &fakeClassicELB{pages: [][]elbtypes.LoadBalancerDescription{{lb}},
		attrErr: errors.New("AccessDenied"), policyErr: errors.New("Throttling")}
	got, err := listClassicELBs(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	for _, k := range []string{"connection_draining", "cross_zone_load_balancing", "desync_mitigation_mode", "access_logs_s3_enabled", "tls_listener_policies"} {
		require.NotContains(t, got[0].Metadata, k)
	}
	require.Equal(t, "", got[0].Metadata["non_acm_certificate_listeners"], "the listing itself still observed the certificates")

	_, err = listClassicELBs(context.Background(), &fakeClassicELB{pages: [][]elbtypes.LoadBalancerDescription{{lb}, {lb}}, pageErr: errors.New("x")},
		"eu-west-1", "1", time.Now())
	require.Error(t, err, "a failed page is a failed listing")
}
