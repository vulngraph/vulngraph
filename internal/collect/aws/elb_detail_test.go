package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/require"
)

// fakeELBv2Detail serves the per-balancer reads. listenerPages[arn] is the
// page sequence DescribeListeners returns; a nil entry is an empty listing.
type fakeELBv2Detail struct {
	attrs         map[string][]elbv2types.LoadBalancerAttribute
	attrErr       error
	listenerPages map[string][][]elbv2types.Listener
	listenerErr   error
	rules         map[string][]elbv2types.Rule
	ruleErr       map[string]error
}

func (f fakeELBv2Detail) DescribeLoadBalancerAttributes(_ context.Context, in *elasticloadbalancingv2.DescribeLoadBalancerAttributesInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput, error) {
	if f.attrErr != nil {
		return nil, f.attrErr
	}
	return &elasticloadbalancingv2.DescribeLoadBalancerAttributesOutput{Attributes: f.attrs[awssdk.ToString(in.LoadBalancerArn)]}, nil
}

func (f fakeELBv2Detail) DescribeListeners(_ context.Context, in *elasticloadbalancingv2.DescribeListenersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	if f.listenerErr != nil {
		return nil, f.listenerErr
	}
	pages := f.listenerPages[awssdk.ToString(in.LoadBalancerArn)]
	i := 0
	if in.Marker != nil {
		i = int(awssdk.ToString(in.Marker)[0] - '0')
	}
	if i >= len(pages) {
		return &elasticloadbalancingv2.DescribeListenersOutput{}, nil
	}
	out := &elasticloadbalancingv2.DescribeListenersOutput{Listeners: pages[i]}
	if i+1 < len(pages) {
		out.NextMarker = awssdk.String(string(rune('0' + i + 1)))
	}
	return out, nil
}

func (f fakeELBv2Detail) DescribeRules(_ context.Context, in *elasticloadbalancingv2.DescribeRulesInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeRulesOutput, error) {
	if err := f.ruleErr[awssdk.ToString(in.ListenerArn)]; err != nil {
		return nil, err
	}
	return &elasticloadbalancingv2.DescribeRulesOutput{Rules: f.rules[awssdk.ToString(in.ListenerArn)]}, nil
}

func attr(k, v string) elbv2types.LoadBalancerAttribute {
	return elbv2types.LoadBalancerAttribute{Key: awssdk.String(k), Value: awssdk.String(v)}
}

func listener(arn string, proto elbv2types.ProtocolEnum, port int32, policy string, defaults ...elbv2types.Action) elbv2types.Listener {
	l := elbv2types.Listener{ListenerArn: awssdk.String(arn), Protocol: proto, Port: awssdk.Int32(port), DefaultActions: defaults}
	if policy != "" {
		l.SslPolicy = awssdk.String(policy)
	}
	return l
}

func redirectTo(proto string) elbv2types.Action {
	return elbv2types.Action{Type: elbv2types.ActionTypeEnumRedirect, RedirectConfig: &elbv2types.RedirectActionConfig{Protocol: awssdk.String(proto)}}
}

var forward = elbv2types.Action{Type: elbv2types.ActionTypeEnumForward, TargetGroupArn: awssdk.String("arn:tg")}

func albFake(detail fakeELBv2Detail) fakeELBv2 {
	return fakeELBv2{lbs: []elbv2types.LoadBalancer{{
		LoadBalancerArn: awssdk.String("arn:alb"), Type: elbv2types.LoadBalancerTypeEnumApplication,
		Scheme: elbv2types.LoadBalancerSchemeEnumInternetFacing,
	}}, fakeELBv2Detail: detail}
}

func TestCollectLoadBalancers_ALBPosture(t *testing.T) {
	f := albFake(fakeELBv2Detail{
		attrs: map[string][]elbv2types.LoadBalancerAttribute{"arn:alb": {
			attr("deletion_protection.enabled", "false"),
			attr("routing.http.drop_invalid_header_fields.enabled", "true"),
			attr("routing.http.desync_mitigation_mode", "monitor"),
			attr("access_logs.s3.enabled", "false"), // stored for the logging checks
		}},
		// Two pages: a short read of the first would hide the forwarding listener.
		listenerPages: map[string][][]elbv2types.Listener{"arn:alb": {
			{listener("l-443", elbv2types.ProtocolEnumHttps, 443, "ELBSecurityPolicy-2016-08", forward),
				listener("l-80", elbv2types.ProtocolEnumHttp, 80, "", redirectTo("HTTPS"))},
			{listener("l-8080", elbv2types.ProtocolEnumHttp, 8080, "", redirectTo("HTTPS"))},
		}},
		rules: map[string][]elbv2types.Rule{
			"l-80": {{IsDefault: awssdk.Bool(true), Actions: []elbv2types.Action{redirectTo("HTTPS")}}},
			// A non-default rule on 8080 forwards in clear text despite the redirect default.
			"l-8080": {{Actions: []elbv2types.Action{forward}}, {IsDefault: awssdk.Bool(true), Actions: []elbv2types.Action{redirectTo("HTTPS")}}},
		},
	})
	got, _, err := collectLoadBalancers(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	md := got[0].Metadata
	require.Equal(t, "false", md["deletion_protection"])
	require.Equal(t, "true", md["drop_invalid_header_fields"])
	require.Equal(t, "monitor", md["desync_mitigation_mode"])
	require.Equal(t, "false", md["access_logs_s3_enabled"])
	require.Equal(t, "3", md["listener_count"])
	require.Equal(t, "HTTP:80,HTTP:8080", md["plaintext_listeners"])
	require.Equal(t, "HTTPS:443=ELBSecurityPolicy-2016-08", md["tls_listener_policies"])
	require.Equal(t, "8080", md["http_listeners_without_https_redirect"])
}

// access_logs_s3_enabled is an ALB key: an NLB's attribute of the same name is
// not stored.
func TestCollectLoadBalancers_AccessLogKeyIsALBOnly(t *testing.T) {
	f := fakeELBv2{lbs: []elbv2types.LoadBalancer{{
		LoadBalancerArn: awssdk.String("arn:nlb"), Type: elbv2types.LoadBalancerTypeEnumNetwork,
		Scheme: elbv2types.LoadBalancerSchemeEnumInternetFacing,
	}}, fakeELBv2Detail: fakeELBv2Detail{attrs: map[string][]elbv2types.LoadBalancerAttribute{"arn:nlb": {
		attr("access_logs.s3.enabled", "false"), attr("deletion_protection.enabled", "true"),
	}}}}
	got, _, err := collectLoadBalancers(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.NotContains(t, got[0].Metadata, "access_logs_s3_enabled")
	require.Equal(t, "true", got[0].Metadata["deletion_protection"])
}

func TestCollectLoadBalancers_FailedReadsOmitTheirKeys(t *testing.T) {
	t.Run("rules", func(t *testing.T) {
		f := albFake(fakeELBv2Detail{
			listenerPages: map[string][][]elbv2types.Listener{"arn:alb": {{listener("l-80", elbv2types.ProtocolEnumHttp, 80, "")}}},
			ruleErr:       map[string]error{"l-80": errors.New("AccessDenied")},
		})
		got, _, err := collectLoadBalancers(context.Background(), f, "eu-west-1", "1", time.Now())
		require.NoError(t, err)
		require.NotContains(t, got[0].Metadata, "http_listeners_without_https_redirect",
			"an unread rule set is not a listener that redirects")
		require.Equal(t, "HTTP:80", got[0].Metadata["plaintext_listeners"])
	})
	t.Run("attributes", func(t *testing.T) {
		f := albFake(fakeELBv2Detail{attrErr: errors.New("Throttling")})
		got, _, err := collectLoadBalancers(context.Background(), f, "eu-west-1", "1", time.Now())
		require.NoError(t, err)
		for _, k := range []string{"deletion_protection", "drop_invalid_header_fields", "desync_mitigation_mode", "access_logs_s3_enabled"} {
			require.NotContains(t, got[0].Metadata, k)
		}
		require.Equal(t, "", got[0].Metadata["plaintext_listeners"], "the listener read still succeeded")
	})
	t.Run("listeners", func(t *testing.T) {
		f := albFake(fakeELBv2Detail{listenerErr: errors.New("AccessDenied")})
		got, _, err := collectLoadBalancers(context.Background(), f, "eu-west-1", "1", time.Now())
		require.NoError(t, err)
		for _, k := range []string{"listener_count", "plaintext_listeners", "tls_listener_policies", "http_listeners_without_https_redirect"} {
			require.NotContains(t, got[0].Metadata, k)
		}
	})
}

func TestCollectLoadBalancers_NetworkAndGatewayListeners(t *testing.T) {
	f := fakeELBv2{lbs: []elbv2types.LoadBalancer{
		{LoadBalancerArn: awssdk.String("arn:nlb"), Type: elbv2types.LoadBalancerTypeEnumNetwork},
		{LoadBalancerArn: awssdk.String("arn:gwlb"), Type: elbv2types.LoadBalancerTypeEnumGateway},
	}, fakeELBv2Detail: fakeELBv2Detail{listenerPages: map[string][][]elbv2types.Listener{
		"arn:nlb": {{listener("n1", elbv2types.ProtocolEnumTls, 443, "ELBSecurityPolicy-TLS13-1-2-Res-2021-06"),
			listener("n2", elbv2types.ProtocolEnumTcp, 22, ""), listener("n3", elbv2types.ProtocolEnumQuic, 8443, "")}},
		"arn:gwlb": {{listener("g1", elbv2types.ProtocolEnumGeneve, 6081, "")}},
	}}}
	got, _, err := collectLoadBalancers(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "TCP:22", got[0].Metadata["plaintext_listeners"], "QUIC is encrypted")
	require.Equal(t, "TLS:443=ELBSecurityPolicy-TLS13-1-2-Res-2021-06", got[0].Metadata["tls_listener_policies"])
	require.NotContains(t, got[0].Metadata, "http_listeners_without_https_redirect", "ELB.1 grades ALBs only")
	require.Equal(t, "", got[1].Metadata["plaintext_listeners"], "GENEVE carries no client session")
}

func TestRedirectsToHTTPS(t *testing.T) {
	fixed := elbv2types.Action{Type: elbv2types.ActionTypeEnumFixedResponse}
	tests := []struct {
		name     string
		defaults []elbv2types.Action
		rules    []elbv2types.Rule
		want     bool
	}{
		{"default redirect to HTTPS", []elbv2types.Action{redirectTo("HTTPS")}, nil, true},
		{"lower-case protocol", []elbv2types.Action{redirectTo("https")}, nil, true},
		{"#{protocol} keeps HTTP", []elbv2types.Action{redirectTo("#{protocol}")}, nil, false},
		{"default forward", []elbv2types.Action{forward}, nil, false},
		{"rule forward beside a redirect default", []elbv2types.Action{redirectTo("HTTPS")},
			[]elbv2types.Rule{{Actions: []elbv2types.Action{forward}}}, false},
		{"redirect rule with a fixed-response default", []elbv2types.Action{fixed},
			[]elbv2types.Rule{{Actions: []elbv2types.Action{redirectTo("HTTPS")}}}, true},
		{"fixed response only never redirects", []elbv2types.Action{fixed}, nil, false},
		{"redirect without config", []elbv2types.Action{{Type: elbv2types.ActionTypeEnumRedirect}}, nil, false},
		{"no actions", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, redirectsToHTTPS(tt.defaults, tt.rules))
		})
	}
}

type fakeTargetGroupPages struct {
	pages [][]elbv2types.TargetGroup
	err   error
}

func (f fakeTargetGroupPages) DescribeTargetGroups(_ context.Context, in *elasticloadbalancingv2.DescribeTargetGroupsInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	i := 0
	if in.Marker != nil {
		i = 1
		if f.err != nil {
			return nil, f.err
		}
	}
	out := &elasticloadbalancingv2.DescribeTargetGroupsOutput{}
	if i < len(f.pages) {
		out.TargetGroups = f.pages[i]
	}
	if i == 0 && len(f.pages) > 1 {
		out.NextMarker = awssdk.String("1")
	}
	return out, nil
}

func TestListTargetGroups(t *testing.T) {
	f := fakeTargetGroupPages{pages: [][]elbv2types.TargetGroup{
		{{TargetGroupArn: awssdk.String("arn:tg/http"), TargetGroupName: awssdk.String("web"), Protocol: elbv2types.ProtocolEnumHttp,
			HealthCheckProtocol: elbv2types.ProtocolEnumHttp, HealthCheckEnabled: awssdk.Bool(true),
			TargetType: elbv2types.TargetTypeEnumInstance, LoadBalancerArns: []string{"arn:alb"}}},
		{{TargetGroupArn: awssdk.String("arn:tg/fn"), TargetType: elbv2types.TargetTypeEnumLambda, HealthCheckEnabled: awssdk.Bool(false)},
			{TargetGroupName: awssdk.String("no-arn")}},
	}}
	got, err := listTargetGroups(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2, "both pages, and an ARN-less group is dropped")
	require.Equal(t, lbTargetGroupType, got[0].Type)
	require.Equal(t, "HTTP", got[0].Metadata["protocol"])
	require.Equal(t, "HTTP", got[0].Metadata["health_check_protocol"])
	require.Equal(t, "arn:alb", got[0].Metadata["load_balancer_arns"])
	require.Equal(t, "lambda", got[1].Metadata["target_type"])
	require.NotContains(t, got[1].Metadata, "health_check_protocol", "a Lambda group has no health-check protocol to grade")

	_, err = listTargetGroups(context.Background(), fakeTargetGroupPages{pages: f.pages, err: errors.New("Throttling")}, "eu-west-1", "1", time.Now())
	require.Error(t, err, "a failed second page is a failed listing, not a short one")
}
