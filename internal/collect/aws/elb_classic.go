package aws

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Classic Load Balancers (AWS FSBP ELB.2/3/7/8/9/10/14). They are emitted as
// load_balancer assets with type=classic, so the scheme-based exposure checks
// and aws-elb-single-az grade them exactly like ALB/NLB/GWLB.

// lbTypeClassic is the load_balancer `type` value of a Classic Load Balancer
// (ELBv2 uses application / network / gateway).
const lbTypeClassic = "classic"

// sslNegotiationPolicyType is the Classic policy type that carries a
// listener's TLS protocols and ciphers; a predefined one names its source
// policy in the Reference-Security-Policy attribute.
const (
	sslNegotiationPolicyType = "SSLNegotiationPolicyType"
	referenceSecurityPolicy  = "Reference-Security-Policy"
	classicDesyncAttribute   = "elb.http.desyncmitigationmode"
)

type classicELBAPI interface {
	DescribeLoadBalancers(context.Context, *elasticloadbalancing.DescribeLoadBalancersInput, ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancersOutput, error)
	DescribeLoadBalancerAttributes(context.Context, *elasticloadbalancing.DescribeLoadBalancerAttributesInput, ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancerAttributesOutput, error)
	DescribeLoadBalancerPolicies(context.Context, *elasticloadbalancing.DescribeLoadBalancerPoliciesInput, ...func(*elasticloadbalancing.Options)) (*elasticloadbalancing.DescribeLoadBalancerPoliciesOutput, error)
}

func collectClassicELBs(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectClassicELBs: %w", err)
	}
	return listClassicELBs(ctx, elasticloadbalancing.NewFromConfig(awsCfg), region, accountID, now)
}

// listClassicELBs lists every Classic Load Balancer in the region, then reads
// each one's attributes and TLS policies under lbDetailConcurrency. A page
// error fails the listing; a per-balancer read failure leaves only that
// read's keys absent.
func listClassicELBs(ctx context.Context, client classicELBAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		lbs    []elbtypes.LoadBalancerDescription
		marker *string
	)
	for {
		out, err := client.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("listClassicELBs: %w", err)
		}
		lbs = append(lbs, out.LoadBalancerDescriptions...)
		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}
	assets := make([]asset.Asset, 0, len(lbs))
	kept := make([]elbtypes.LoadBalancerDescription, 0, len(lbs)) // kept[i] backs assets[i]
	for _, lb := range lbs {
		if awssdk.ToString(lb.LoadBalancerName) != "" {
			assets = append(assets, classicAsset(lb, region, accountID, now))
			kept = append(kept, lb)
		}
	}
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, lbDetailConcurrency)
	)
	for i := range assets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(a *asset.Asset, lb elbtypes.LoadBalancerDescription) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("load_balancer", a.ID).
						Msg("classic elb posture read panicked; its attribute and policy keys stay absent")
				}
			}()
			classicPosture(ctx, client, lb, a.Metadata)
		}(&assets[i], kept[i])
	}
	wg.Wait()
	return assets, nil
}

// classicAsset maps the listing's own fields. Listener protocols and
// certificates come with the listing, so plaintext_listeners and
// non_acm_certificate_listeners are observations as soon as it succeeds.
func classicAsset(lb elbtypes.LoadBalancerDescription, region, accountID string, now time.Time) asset.Asset {
	name := awssdk.ToString(lb.LoadBalancerName)
	dns := awssdk.ToString(lb.DNSName)
	scheme := awssdk.ToString(lb.Scheme)
	var plaintext, nonACM []string
	for _, l := range sortedClassicListeners(lb.ListenerDescriptions) {
		proto := strings.ToUpper(awssdk.ToString(l.Protocol))
		ref := proto + ":" + strconv.Itoa(int(l.LoadBalancerPort))
		if !classicEncrypted(proto) {
			plaintext = append(plaintext, ref)
			continue
		}
		if cert := awssdk.ToString(l.SSLCertificateId); !strings.Contains(cert, ":acm:") {
			nonACM = append(nonACM, ref)
		}
	}
	return asset.Asset{
		ID:        "arn:" + partitionFor(region) + ":elasticloadbalancing:" + region + ":" + accountID + ":loadbalancer/" + name,
		Name:      name,
		Type:      "load_balancer",
		Provider:  asset.ProviderAWS,
		Region:    region,
		AccountID: accountID,
		Domain:    dns,
		Endpoint:  "https://" + dns,
		Metadata: map[string]string{
			"scheme":                        scheme,
			"type":                          lbTypeClassic,
			"vpc_id":                        awssdk.ToString(lb.VPCId),
			"security_groups":               strings.Join(lb.SecurityGroups, ","),
			"public":                        strconv.FormatBool(scheme == "internet-facing"),
			"availability_zone_count":       strconv.Itoa(len(lb.AvailabilityZones)),
			"listener_count":                strconv.Itoa(len(lb.ListenerDescriptions)),
			"plaintext_listeners":           strings.Join(plaintext, ","),
			"non_acm_certificate_listeners": strings.Join(nonACM, ","),
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

func classicEncrypted(proto string) bool { return proto == "HTTPS" || proto == "SSL" }

func sortedClassicListeners(ds []elbtypes.ListenerDescription) []elbtypes.Listener {
	var out []elbtypes.Listener
	for _, d := range ds {
		if d.Listener != nil {
			out = append(out, *d.Listener)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LoadBalancerPort < out[j].LoadBalancerPort })
	return out
}

// classicPosture adds the attribute and TLS-policy keys to meta. Each read is
// independent: a failure omits only its own keys.
func classicPosture(ctx context.Context, client classicELBAPI, lb elbtypes.LoadBalancerDescription, meta map[string]string) {
	name := awssdk.ToString(lb.LoadBalancerName)
	if out, err := client.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{
		LoadBalancerName: awssdk.String(name),
	}); err == nil && out != nil && out.LoadBalancerAttributes != nil {
		attrs := out.LoadBalancerAttributes
		if attrs.ConnectionDraining != nil {
			meta["connection_draining"] = strconv.FormatBool(attrs.ConnectionDraining.Enabled)
		}
		if attrs.CrossZoneLoadBalancing != nil {
			meta["cross_zone_load_balancing"] = strconv.FormatBool(attrs.CrossZoneLoadBalancing.Enabled)
		}
		// The same key the ALB attribute read writes (elb_detail.go), graded
		// by aws-alb-access-logs-disabled (FSBP ELB.5, CIS 4.10).
		if attrs.AccessLog != nil {
			meta["access_logs_s3_enabled"] = strconv.FormatBool(attrs.AccessLog.Enabled)
		}
		for _, at := range attrs.AdditionalAttributes {
			if awssdk.ToString(at.Key) == classicDesyncAttribute && at.Value != nil {
				meta["desync_mitigation_mode"] = awssdk.ToString(at.Value)
			}
		}
	} else {
		log.FromContext(ctx).Warn().Err(orEmpty(err)).Str("load_balancer", name).
			Msg("classic elb DescribeLoadBalancerAttributes failed; draining, cross-zone and desync keys omitted")
	}
	if p, ok := classicTLSPolicies(ctx, client, lb); ok {
		meta["tls_listener_policies"] = p
	}
}

// classicTLSPolicies renders "PROTO:port=<predefined policy>" for every
// HTTPS/SSL listener. A listener whose negotiation policy is custom (no
// Reference-Security-Policy) renders "custom:<name>"; one with no negotiation
// policy at all renders an empty name. ok is false when the policy read
// failed — the policies are then unknown.
func classicTLSPolicies(ctx context.Context, client classicELBAPI, lb elbtypes.LoadBalancerDescription) (string, bool) {
	var tls []elbtypes.ListenerDescription
	for _, d := range lb.ListenerDescriptions {
		if d.Listener != nil && classicEncrypted(strings.ToUpper(awssdk.ToString(d.Listener.Protocol))) {
			tls = append(tls, d)
		}
	}
	if len(tls) == 0 {
		return "", true
	}
	name := awssdk.ToString(lb.LoadBalancerName)
	out, err := client.DescribeLoadBalancerPolicies(ctx, &elasticloadbalancing.DescribeLoadBalancerPoliciesInput{
		LoadBalancerName: awssdk.String(name),
	})
	if err != nil || out == nil {
		log.FromContext(ctx).Warn().Err(orEmpty(err)).Str("load_balancer", name).
			Msg("classic elb DescribeLoadBalancerPolicies failed; TLS policy key omitted")
		return "", false
	}
	negotiation := map[string]string{} // policy name → reference policy or custom:<name>
	for _, p := range out.PolicyDescriptions {
		if awssdk.ToString(p.PolicyTypeName) != sslNegotiationPolicyType {
			continue
		}
		ref := "custom:" + awssdk.ToString(p.PolicyName)
		for _, at := range p.PolicyAttributeDescriptions {
			if awssdk.ToString(at.AttributeName) == referenceSecurityPolicy && awssdk.ToString(at.AttributeValue) != "" {
				ref = awssdk.ToString(at.AttributeValue)
			}
		}
		negotiation[awssdk.ToString(p.PolicyName)] = ref
	}
	sort.Slice(tls, func(i, j int) bool { return tls[i].Listener.LoadBalancerPort < tls[j].Listener.LoadBalancerPort })
	parts := make([]string, 0, len(tls))
	for _, d := range tls {
		policy := ""
		for _, pn := range d.PolicyNames {
			if ref, ok := negotiation[pn]; ok {
				policy = ref
			}
		}
		parts = append(parts, strings.ToUpper(awssdk.ToString(d.Listener.Protocol))+":"+
			strconv.Itoa(int(d.Listener.LoadBalancerPort))+"="+policy)
	}
	return strings.Join(parts, ","), true
}
