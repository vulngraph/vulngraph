package aws

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ELBv2 listener and attribute posture (AWS FSBP ELB.1/4/6/12/17/18). Each
// load balancer needs one attribute read, one listener listing, and a rule
// listing per ALB HTTP listener; lbDetailConcurrency bounds the fan-out the
// same way s3BucketConcurrency does for buckets.
const lbDetailConcurrency = 4

// ELBv2 attribute keys read from DescribeLoadBalancerAttributes, mapped to the
// asset metadata key each is stored under. access_logs_s3_enabled is written
// for ALBs only (elbv2ALBOnlyAttributes) and is graded by the logging checks,
// not here.
var elbv2AttributeKeys = map[string]string{
	"deletion_protection.enabled":                     "deletion_protection",
	"routing.http.drop_invalid_header_fields.enabled": "drop_invalid_header_fields",
	"routing.http.desync_mitigation_mode":             "desync_mitigation_mode",
	"access_logs.s3.enabled":                          "access_logs_s3_enabled",
}

// elbv2ALBOnlyAttributes are stored only for Application Load Balancers.
var elbv2ALBOnlyAttributes = map[string]bool{"access_logs.s3.enabled": true}

// annotateLoadBalancers stamps each load balancer's attribute and listener
// facts onto its asset, bounded by lbDetailConcurrency. A failed read leaves
// that read's keys absent — the checks then cannot evaluate the balancer,
// which is what an unread setting is — and never fails the listing itself.
func annotateLoadBalancers(ctx context.Context, client elbv2API, assets []asset.Asset) {
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, lbDetailConcurrency)
		mu  sync.Mutex
	)
	for i := range assets {
		if ctx.Err() != nil {
			return
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(a *asset.Asset) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("load_balancer", a.ID).
						Msg("elbv2 posture read panicked; its listener and attribute keys stay absent")
				}
			}()
			meta := loadBalancerPosture(ctx, client, a.ID, a.Metadata["type"])
			mu.Lock()
			defer mu.Unlock()
			for k, v := range meta {
				a.Metadata[k] = v
			}
		}(&assets[i])
	}
	wg.Wait()
}

// loadBalancerPosture reads one balancer's attributes and listeners. The two
// halves fail independently: the keys of a read that errored are omitted.
func loadBalancerPosture(ctx context.Context, client elbv2API, arn, lbType string) map[string]string {
	meta := map[string]string{}
	if attrs, err := client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
		LoadBalancerArn: awssdk.String(arn),
	}); err == nil && attrs != nil {
		for _, at := range attrs.Attributes {
			name := awssdk.ToString(at.Key)
			if elbv2ALBOnlyAttributes[name] && lbType != string(elbv2types.LoadBalancerTypeEnumApplication) {
				continue
			}
			if key, ok := elbv2AttributeKeys[name]; ok && at.Value != nil {
				meta[key] = awssdk.ToString(at.Value)
			}
		}
	} else {
		log.FromContext(ctx).Warn().Err(orEmpty(err)).Str("load_balancer", arn).Msg("elbv2 DescribeLoadBalancerAttributes failed; deletion-protection and desync keys omitted")
	}
	listeners, err := describeListeners(ctx, client, arn)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("load_balancer", arn).Msg("elbv2 DescribeListeners failed; listener keys omitted")
		return meta
	}
	for k, v := range listenerPosture(ctx, client, lbType, listeners) {
		meta[k] = v
	}
	return meta
}

func describeListeners(ctx context.Context, client elbv2API, arn string) ([]elbv2types.Listener, error) {
	var (
		out    []elbv2types.Listener
		marker *string
	)
	for {
		page, err := client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
			LoadBalancerArn: awssdk.String(arn), Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("describeListeners: %w", err)
		}
		out = append(out, page.Listeners...)
		if page.NextMarker == nil {
			return out, nil
		}
		marker = page.NextMarker
	}
}

// listenerPosture summarises a balancer's listeners:
//
//   - plaintext_listeners: "PROTO:port" of every listener that does not
//     encrypt client traffic (HTTP, TCP, UDP, TCP_UDP, TCP_QUIC). GENEVE
//     (Gateway Load Balancer) carries no client session and is not listed.
//   - tls_listener_policies: "PROTO:port=SslPolicy" of every HTTPS/TLS listener.
//   - http_listeners_without_https_redirect (ALB only): ports of HTTP
//     listeners that forward traffic or never redirect to HTTPS. Omitted when
//     any of their rule listings failed — one unread listener leaves the
//     balancer unknown, not clean.
//
// An empty value is an observation ("none"), written only after the listing
// succeeded.
func listenerPosture(ctx context.Context, client elbv2API, lbType string, listeners []elbv2types.Listener) map[string]string {
	var plaintext, policies, noRedirect []string
	redirectKnown := true
	sort.Slice(listeners, func(i, j int) bool { return awssdk.ToInt32(listeners[i].Port) < awssdk.ToInt32(listeners[j].Port) })
	for _, l := range listeners {
		port := strconv.Itoa(int(awssdk.ToInt32(l.Port)))
		proto := string(l.Protocol)
		switch l.Protocol {
		case elbv2types.ProtocolEnumHttps, elbv2types.ProtocolEnumTls:
			policies = append(policies, proto+":"+port+"="+awssdk.ToString(l.SslPolicy))
		case elbv2types.ProtocolEnumGeneve, elbv2types.ProtocolEnumQuic, "":
		default:
			plaintext = append(plaintext, proto+":"+port)
		}
		if lbType != string(elbv2types.LoadBalancerTypeEnumApplication) || l.Protocol != elbv2types.ProtocolEnumHttp {
			continue
		}
		rules, err := describeRules(ctx, client, awssdk.ToString(l.ListenerArn))
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("listener", awssdk.ToString(l.ListenerArn)).
				Msg("elbv2 DescribeRules failed; the balancer's HTTPS-redirect verdict is omitted")
			redirectKnown = false
			continue
		}
		if !redirectsToHTTPS(l.DefaultActions, rules) {
			noRedirect = append(noRedirect, port)
		}
	}
	meta := map[string]string{
		"listener_count":        strconv.Itoa(len(listeners)),
		"plaintext_listeners":   strings.Join(plaintext, ","),
		"tls_listener_policies": strings.Join(policies, ","),
	}
	if lbType == string(elbv2types.LoadBalancerTypeEnumApplication) && redirectKnown {
		meta["http_listeners_without_https_redirect"] = strings.Join(noRedirect, ",")
	}
	return meta
}

func describeRules(ctx context.Context, client elbv2API, listenerARN string) ([]elbv2types.Rule, error) {
	var (
		out    []elbv2types.Rule
		marker *string
	)
	for {
		page, err := client.DescribeRules(ctx, &elasticloadbalancingv2.DescribeRulesInput{
			ListenerArn: awssdk.String(listenerARN), Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("describeRules: %w", err)
		}
		out = append(out, page.Rules...)
		if page.NextMarker == nil {
			return out, nil
		}
		marker = page.NextMarker
	}
}

// redirectsToHTTPS is the AWS Config rule alb-http-to-https-redirection-check
// on one HTTP listener: it passes only when some action redirects to HTTPS
// and no action, default or rule, forwards the request to a target group —
// a forward on an HTTP listener serves the application in clear text.
// Fixed responses carry no application data and are allowed beside the
// redirect. DescribeRules returns the default rule too; the listener's own
// DefaultActions are folded in so a rule listing that omits it changes nothing.
func redirectsToHTTPS(defaults []elbv2types.Action, rules []elbv2types.Rule) bool {
	actions := append([]elbv2types.Action(nil), defaults...)
	for _, r := range rules {
		actions = append(actions, r.Actions...)
	}
	redirect := false
	for _, a := range actions {
		switch a.Type {
		case elbv2types.ActionTypeEnumForward:
			return false
		case elbv2types.ActionTypeEnumRedirect:
			if a.RedirectConfig != nil && strings.EqualFold(awssdk.ToString(a.RedirectConfig.Protocol), "HTTPS") {
				redirect = true
			}
		}
	}
	return redirect
}
