package gcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// lbAPI is the slice of Compute the load-balancer posture needs. Aggregated
// listings also return the scopes they could not reach.
type lbAPI interface {
	BackendServices(ctx context.Context, projectID string) ([]*compute.BackendService, []string, error)
	TargetHTTPSProxies(ctx context.Context, projectID string) ([]*compute.TargetHttpsProxy, []string, error)
	TargetSSLProxies(ctx context.Context, projectID string) ([]*compute.TargetSslProxy, error)
	SSLPolicies(ctx context.Context, projectID string) ([]*compute.SslPolicy, []string, error)
	// GroupInstances lists the instance URLs in an instance group, named by
	// its zonal or regional URL.
	GroupInstances(ctx context.Context, projectID, groupURL string) ([]string, error)
}

// weakTLSCiphers are the cipher suites CIS GCP 3.11 requires a CUSTOM SSL
// policy to leave disabled: RSA key exchange (no forward secrecy) and 3DES.
var weakTLSCiphers = []string{
	"TLS_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_RSA_WITH_AES_128_CBC_SHA",
	"TLS_RSA_WITH_AES_256_CBC_SHA",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}

// httpLBProtocols are the backend protocols of an HTTP(S) load balancer,
// the only kind whose request logging CIS GCP 2.17 covers.
var httpLBProtocols = []string{"HTTP", "HTTPS", "HTTP2", "H2C"}

// collectLoadBalancing inventories backend services (logging, IAP) and TLS
// target proxies (SSL policy strength, certificates). A failed or partial
// listing returns what was read beside the error.
func collectLoadBalancing(ctx context.Context, client lbAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	var errs []error
	var assets []asset.Asset

	backends, unreachable, err := client.BackendServices(ctx, projectID)
	errs = append(errs, err, unreachableErr("backend services", unreachable))
	for _, b := range backends {
		if b == nil || b.Name == "" {
			continue
		}
		scope := scopeName(b.Region)
		md := backendServiceMetadata(b)
		if b.Iap != nil && b.Iap.Enabled {
			if ids, ok := iapMembers(ctx, client, projectID, b); ok {
				md["iap_backend_instances"] = strings.Join(ids, ",")
			}
		}
		assets = append(assets, asset.Asset{
			ID:   projectID + "/backend-service/" + scope + "/" + b.Name,
			Name: b.Name, Type: "gcp_backend_service", Provider: asset.ProviderGCP,
			Region: scope, AccountID: projectID, Metadata: md, DiscoveredAt: now, LastSeen: now,
		})
	}

	policies, polUnreachable, polErr := client.SSLPolicies(ctx, projectID)
	errs = append(errs, polErr, unreachableErr("ssl policies", polUnreachable))
	byLink := map[string]*compute.SslPolicy{}
	for _, p := range policies {
		if p != nil {
			byLink[p.SelfLink] = p
		}
	}
	proxy := func(kind, name, region, policy string, certs []string) {
		scope := scopeName(region)
		md := map[string]string{
			"kind":              kind,
			"ssl_policy":        lastSegment(policy),
			"certificate_links": strings.Join(certs, ","),
			// GKE's Ingress controller names the proxies it creates k8s2-ts-…
			// (and k8s-tps-… before ingress v2).
			"gke_ingress": strconv.FormatBool(strings.HasPrefix(name, "k8s2-ts-") || strings.HasPrefix(name, "k8s-tps-")),
		}
		if weak, why, ok := sslPolicyWeakness(policy, byLink); ok {
			md["ssl_policy_weak"] = strconv.FormatBool(weak)
			md["ssl_policy_weakness"] = why
		}
		assets = append(assets, asset.Asset{
			ID:   projectID + "/target-proxy/" + scope + "/" + name,
			Name: name, Type: "gcp_target_proxy", Provider: asset.ProviderGCP,
			Region: scope, AccountID: projectID, Metadata: md, DiscoveredAt: now, LastSeen: now,
		})
	}
	https, httpsUnreachable, err := client.TargetHTTPSProxies(ctx, projectID)
	errs = append(errs, err, unreachableErr("target https proxies", httpsUnreachable))
	for _, p := range https {
		if p != nil && p.Name != "" {
			proxy("https", p.Name, p.Region, p.SslPolicy, p.SslCertificates)
		}
	}
	ssl, err := client.TargetSSLProxies(ctx, projectID)
	errs = append(errs, err)
	for _, p := range ssl {
		if p != nil && p.Name != "" {
			proxy("ssl", p.Name, "", p.SslPolicy, p.SslCertificates)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return assets, fmt.Errorf("collectLoadBalancing: %w", err)
	}
	return assets, nil
}

func unreachableErr(what string, scopes []string) error {
	if len(scopes) == 0 {
		return nil
	}
	return fmt.Errorf("%s unreachable in %s", what, strings.Join(scopes, ","))
}

// scopeName is a resource's region, or "global" for a global resource.
func scopeName(regionURL string) string {
	if regionURL == "" {
		return "global"
	}
	return lastSegment(regionURL)
}

// backendServiceMetadata records whether a backend service fronts an HTTP(S)
// load balancer and, if so, whether it logs requests (CIS GCP 2.17), plus
// its IAP state (3.12). An omitted logConfig is logging off.
func backendServiceMetadata(b *compute.BackendService) map[string]string {
	protocol := b.Protocol
	if protocol == "" {
		protocol = "HTTP" // the API default
	}
	httpLB := slices.Contains(httpLBProtocols, protocol)
	md := map[string]string{
		"protocol":    protocol,
		"scheme":      b.LoadBalancingScheme,
		"http_lb":     strconv.FormatBool(httpLB),
		"iap_enabled": strconv.FormatBool(b.Iap != nil && b.Iap.Enabled),
	}
	if httpLB {
		md["logging"] = strconv.FormatBool(b.LogConfig != nil && b.LogConfig.Enable)
	}
	return md
}

// iapMembers resolves the instances behind an IAP-protected backend service
// to gce_instance asset IDs. Only instance-group backends can be resolved; a
// network endpoint group, or a failed group listing, makes the membership
// unknown.
func iapMembers(ctx context.Context, client lbAPI, projectID string, b *compute.BackendService) ([]string, bool) {
	var ids []string
	for _, be := range b.Backends {
		if be == nil {
			continue
		}
		if !strings.Contains(be.Group, "/instanceGroups/") {
			return nil, false
		}
		urls, err := client.GroupInstances(ctx, projectID, be.Group)
		if err != nil {
			return nil, false
		}
		for _, u := range urls {
			ids = append(ids, gceInstanceID(projectID, zoneOf(u), lastSegment(u)))
		}
	}
	return ids, true
}

// zoneOf extracts the zone from a ".../zones/<zone>/instances/<name>" URL.
func zoneOf(instanceURL string) string {
	_, rest, ok := strings.Cut(instanceURL, "/zones/")
	if !ok {
		return ""
	}
	zone, _, _ := strings.Cut(rest, "/")
	return zone
}

// sslPolicyWeakness grades a proxy's SSL policy against CIS GCP 3.11:
// MODERN with a TLS 1.2 floor, RESTRICTED, or CUSTOM with none of the weak
// ciphers passes. A proxy with no policy uses the GCP default, COMPATIBLE
// with TLS 1.0, which fails. ok is false when the named policy could not be
// read.
func sslPolicyWeakness(link string, byLink map[string]*compute.SslPolicy) (weak bool, why string, ok bool) {
	if link == "" {
		return true, "default policy (COMPATIBLE, TLS 1.0)", true
	}
	// A policy missing from the listing (unread, or listed partially) is
	// unknown, never strong.
	p, found := byLink[link]
	if !found {
		return false, "", false
	}
	profile := p.Profile
	if profile == "" {
		profile = "COMPATIBLE"
	}
	minTLS := p.MinTlsVersion
	if minTLS == "" {
		minTLS = "TLS_1_0"
	}
	switch profile {
	case "RESTRICTED":
		return false, "", true
	case "MODERN":
		if minTLS == "TLS_1_2" || minTLS == "TLS_1_3" {
			return false, "", true
		}
		return true, "MODERN profile with minimum " + minTLS, true
	case "CUSTOM":
		var bad []string
		for _, f := range p.CustomFeatures {
			if slices.Contains(weakTLSCiphers, f) {
				bad = append(bad, f)
			}
		}
		if len(bad) == 0 {
			return false, "", true
		}
		return true, "CUSTOM profile enables " + strings.Join(bad, ","), true
	default:
		return true, profile + " profile", true
	}
}

// newLBClient builds the real Compute-backed lbAPI via ADC.
func newLBClient(ctx context.Context) (lbAPI, error) {
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newLBClient: %w", err)
	}
	return &realLB{svc: svc}, nil
}

type realLB struct{ svc *compute.Service }

// scopedWarning reports whether an aggregated-list scope came back with a
// warning other than "no results" — GCP's in-band form of an unreachable scope.
func scopedWarning(code string) bool { return code != "" && code != "NO_RESULTS_ON_PAGE" }

func (r *realLB) BackendServices(ctx context.Context, projectID string) ([]*compute.BackendService, []string, error) {
	var out []*compute.BackendService
	var unreachable []string
	err := r.svc.BackendServices.AggregatedList(projectID).Pages(ctx, func(p *compute.BackendServiceAggregatedList) error {
		unreachable = append(unreachable, p.Unreachables...)
		for scope, s := range p.Items {
			if s.Warning != nil && scopedWarning(s.Warning.Code) {
				unreachable = append(unreachable, scope)
			}
			out = append(out, s.BackendServices...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("BackendServices: %w", err)
	}
	return out, unreachable, nil
}

func (r *realLB) TargetHTTPSProxies(ctx context.Context, projectID string) ([]*compute.TargetHttpsProxy, []string, error) {
	var out []*compute.TargetHttpsProxy
	var unreachable []string
	err := r.svc.TargetHttpsProxies.AggregatedList(projectID).Pages(ctx, func(p *compute.TargetHttpsProxyAggregatedList) error {
		unreachable = append(unreachable, p.Unreachables...)
		for scope, s := range p.Items {
			if s.Warning != nil && scopedWarning(s.Warning.Code) {
				unreachable = append(unreachable, scope)
			}
			out = append(out, s.TargetHttpsProxies...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("TargetHTTPSProxies: %w", err)
	}
	return out, unreachable, nil
}

func (r *realLB) TargetSSLProxies(ctx context.Context, projectID string) ([]*compute.TargetSslProxy, error) {
	var out []*compute.TargetSslProxy
	if err := r.svc.TargetSslProxies.List(projectID).Pages(ctx, func(p *compute.TargetSslProxyList) error {
		out = append(out, p.Items...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("TargetSSLProxies: %w", err)
	}
	return out, nil
}

func (r *realLB) SSLPolicies(ctx context.Context, projectID string) ([]*compute.SslPolicy, []string, error) {
	var out []*compute.SslPolicy
	var unreachable []string
	err := r.svc.SslPolicies.AggregatedList(projectID).Pages(ctx, func(p *compute.SslPoliciesAggregatedList) error {
		unreachable = append(unreachable, p.Unreachables...)
		for scope, s := range p.Items {
			if s.Warning != nil && scopedWarning(s.Warning.Code) {
				unreachable = append(unreachable, scope)
			}
			out = append(out, s.SslPolicies...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("SSLPolicies: %w", err)
	}
	return out, unreachable, nil
}

func (r *realLB) GroupInstances(ctx context.Context, projectID, groupURL string) ([]string, error) {
	var out []string
	name := lastSegment(groupURL)
	if _, rest, ok := strings.Cut(groupURL, "/zones/"); ok {
		zone, _, _ := strings.Cut(rest, "/")
		err := r.svc.InstanceGroups.ListInstances(projectID, zone, name, &compute.InstanceGroupsListInstancesRequest{}).
			Pages(ctx, func(p *compute.InstanceGroupsListInstances) error {
				for _, i := range p.Items {
					out = append(out, i.Instance)
				}
				return nil
			})
		if err != nil {
			return nil, fmt.Errorf("GroupInstances: %w", err)
		}
		return out, nil
	}
	_, rest, _ := strings.Cut(groupURL, "/regions/")
	region, _, _ := strings.Cut(rest, "/")
	err := r.svc.RegionInstanceGroups.ListInstances(projectID, region, name, &compute.RegionInstanceGroupsListInstancesRequest{}).
		Pages(ctx, func(p *compute.RegionInstanceGroupsListInstances) error {
			for _, i := range p.Items {
				out = append(out, i.Instance)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("GroupInstances: %w", err)
	}
	return out, nil
}
