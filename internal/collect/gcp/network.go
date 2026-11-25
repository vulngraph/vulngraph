package gcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// networkAPI is the slice of Compute and Cloud DNS the VPC inventory needs.
type networkAPI interface {
	ListNetworks(ctx context.Context, projectID string) ([]*compute.Network, error)
	// ListSubnetworks returns the subnets and the regions the aggregated
	// listing could not reach (reported inside a successful response).
	ListSubnetworks(ctx context.Context, projectID string) ([]*compute.Subnetwork, []string, error)
	ListDNSPolicies(ctx context.Context, projectID string) ([]*dns.Policy, error)
}

// vpcNetworkID is the vpc_network asset ID, shared with the networks the
// instance loop infers from NICs so both name the same asset.
func vpcNetworkID(projectID, name string) string { return projectID + "/network/" + name }

// collectNetworks inventories the project's VPC networks (CIS GCP 3.1, 3.2,
// 2.13) and subnets (3.10, CIS GKE 5.6.1). Networks and subnets come from
// separate listings; a failed subnet or DNS-policy read leaves the keys it
// feeds absent and is returned as an error beside what was read, so the
// sweep is flagged partial.
func collectNetworks(ctx context.Context, client networkAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	networks, err := client.ListNetworks(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectNetworks: %w", err)
	}
	var errs []error
	// DNS logging is decided by the DNS policies bound to each network: a
	// network no policy names, or only policies with logging off, logs no
	// queries. An unread policy list leaves dns_logging absent.
	policies, polErr := client.ListDNSPolicies(ctx, projectID)
	if polErr != nil && !serviceDisabledErr(ctx, polErr) {
		errs = append(errs, polErr)
	}
	logged := map[string]bool{}
	for _, p := range policies {
		if p == nil || !p.EnableLogging {
			continue
		}
		for _, n := range p.Networks {
			if n != nil {
				logged[lastSegment(n.NetworkUrl)] = true
			}
		}
	}
	var assets []asset.Asset
	for _, n := range networks {
		if n == nil || n.Name == "" {
			continue
		}
		md := map[string]string{
			// A legacy network has a single network-wide IPv4 range and no
			// subnets; every subnet-mode network leaves IPv4Range empty.
			"legacy_network":          strconv.FormatBool(n.IPv4Range != ""),
			"auto_create_subnetworks": strconv.FormatBool(n.AutoCreateSubnetworks),
			// The network GCP creates in every new project (CIS GCP 3.1),
			// stamped only on listed networks, never on ones inferred from NICs.
			"default_network": strconv.FormatBool(n.Name == "default"),
		}
		switch {
		case polErr == nil:
			md["dns_logging"] = strconv.FormatBool(logged[n.Name])
		case serviceDisabledErr(ctx, polErr):
			// Cloud DNS never enabled: no policy can exist, so none logs.
			md["dns_logging"] = "false"
		}
		assets = append(assets, asset.Asset{
			ID: vpcNetworkID(projectID, n.Name), Name: n.Name, Type: "vpc_network", Provider: asset.ProviderGCP,
			Region: "global", AccountID: projectID, Metadata: md, DiscoveredAt: now, LastSeen: now,
		})
	}

	subnets, unreachable, subErr := client.ListSubnetworks(ctx, projectID)
	if subErr != nil {
		errs = append(errs, subErr)
	}
	if len(unreachable) > 0 {
		errs = append(errs, unreachableErr("subnetworks", unreachable))
	}
	for _, s := range subnets {
		if s == nil || s.Name == "" {
			continue
		}
		region := lastSegment(s.Region)
		assets = append(assets, asset.Asset{
			ID:   subnetworkID(projectID, region, s.Name),
			Name: s.Name, Type: "gcp_subnetwork", Provider: asset.ProviderGCP,
			Region: region, AccountID: projectID, Metadata: subnetMetadata(s), DiscoveredAt: now, LastSeen: now,
		})
	}
	if err := errors.Join(errs...); err != nil {
		return assets, fmt.Errorf("collectNetworks: %w", err)
	}
	return assets, nil
}

// subnetworkID keys a subnet by region: subnet names are unique per region.
func subnetworkID(projectID, region, name string) string {
	return projectID + "/subnetwork/" + region + "/" + name
}

// Flow-log settings CIS GCP 3.10 requires beyond enablement: every flow
// captured (sampling 1), at the finest aggregation, with all metadata and no
// filter.
const (
	flowLogInterval = "INTERVAL_5_SEC"
	flowLogMetadata = "INCLUDE_ALL_METADATA"
)

// subnetMetadata records a subnet's flow-log posture. Only PRIVATE
// (ordinary) subnets carry VM traffic and support flow logs; proxy-only and
// Private Service Connect subnets are stamped with their purpose and no
// flow-log key, because they have no setting to grade.
func subnetMetadata(s *compute.Subnetwork) map[string]string {
	purpose := s.Purpose
	if purpose == "" {
		purpose = "PRIVATE"
	}
	md := map[string]string{
		"network":               lastSegment(s.Network),
		"purpose":               purpose,
		"self_link":             s.SelfLink,
		"private_google_access": strconv.FormatBool(s.PrivateIpGoogleAccess),
	}
	if purpose != "PRIVATE" {
		return md
	}
	enabled := s.EnableFlowLogs || (s.LogConfig != nil && s.LogConfig.Enable)
	md["flow_logs"] = strconv.FormatBool(enabled)
	// Only the legacy enableFlowLogs flag came back: the settings are unread.
	c := s.LogConfig
	if !enabled || c == nil {
		return md
	}
	var gaps []string
	if c.AggregationInterval != "" && c.AggregationInterval != flowLogInterval {
		gaps = append(gaps, "aggregation_interval="+c.AggregationInterval)
	}
	if c.FlowSampling < 1 {
		gaps = append(gaps, "flow_sampling="+strconv.FormatFloat(c.FlowSampling, 'f', -1, 64))
	}
	if c.Metadata != "" && c.Metadata != flowLogMetadata {
		gaps = append(gaps, "metadata="+c.Metadata)
	}
	if c.FilterExpr != "" {
		gaps = append(gaps, "filter_expr")
	}
	md["flow_logs_config_gaps"] = strings.Join(gaps, ",")
	return md
}

// newNetworkClient builds the real Compute + Cloud DNS networkAPI via ADC.
func newNetworkClient(ctx context.Context) (networkAPI, error) {
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newNetworkClient: %w", err)
	}
	dnsSvc, err := dns.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newNetworkClient: %w", err)
	}
	return &realNetwork{svc: svc, dns: dnsSvc}, nil
}

type realNetwork struct {
	svc *compute.Service
	dns *dns.Service
}

func (r *realNetwork) ListNetworks(ctx context.Context, projectID string) ([]*compute.Network, error) {
	var out []*compute.Network
	if err := r.svc.Networks.List(projectID).Pages(ctx, func(p *compute.NetworkList) error {
		out = append(out, p.Items...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("ListNetworks: %w", err)
	}
	return out, nil
}

func (r *realNetwork) ListSubnetworks(ctx context.Context, projectID string) ([]*compute.Subnetwork, []string, error) {
	var out []*compute.Subnetwork
	var unreachable []string
	err := r.svc.Subnetworks.AggregatedList(projectID).Pages(ctx, func(p *compute.SubnetworkAggregatedList) error {
		unreachable = append(unreachable, p.Unreachables...)
		for scope, scoped := range p.Items {
			if scoped.Warning != nil && scoped.Warning.Code != "NO_RESULTS_ON_PAGE" {
				unreachable = append(unreachable, scope)
			}
			out = append(out, scoped.Subnetworks...)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("ListSubnetworks: %w", err)
	}
	return out, unreachable, nil
}

func (r *realNetwork) ListDNSPolicies(ctx context.Context, projectID string) ([]*dns.Policy, error) {
	var out []*dns.Policy
	if err := r.dns.Policies.List(projectID).Pages(ctx, func(p *dns.PoliciesListResponse) error {
		out = append(out, p.Policies...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("ListDNSPolicies: %w", err)
	}
	return out, nil
}
