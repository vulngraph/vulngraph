package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

// internetCIDR / internetCIDRv6 are source ranges that mean "open to the whole internet".
const (
	internetCIDR   = "0.0.0.0/0"
	internetCIDRv6 = "::/0"
)

// gcpFirewall is a provider-neutral view of a Compute firewall rule.
type gcpFirewall struct {
	Name         string
	Network      string
	Direction    string
	Disabled     bool
	Priority     int64 // GCP priority: lower number = higher precedence (default 1000)
	SourceRanges []string
	SourceSAs    []string // source service accounts; prevents the default world source
	SourceTags   []string // source network tags — intra-VPC rules allowing ingress from tagged instances
	TargetTags   []string // network tags the rule applies to ("" list = whole network)
	TargetSAs    []string // service-account emails the rule applies to (mutually exclusive with TargetTags)
	// DestinationRanges limit the destination IPs the rule matches; they apply
	// to INGRESS rules too ("" list = every address in the network).
	DestinationRanges []string
	Allowed           string // "tcp:22,443;udp:53" summary of allowed protocol:ports
	Denied            string // same summary format, for a deny rule
	OpenToInternet    bool   // enabled INGRESS allow rule with 0.0.0.0/0 or ::/0
	DenyWorld         bool   // enabled INGRESS deny rule with 0.0.0.0/0 or ::/0 — overrides lower-priority allows
}

// firewallAPI is the slice of Compute the firewall collector needs.
type firewallAPI interface {
	ListFirewalls(ctx context.Context, projectID string) ([]gcpFirewall, error)
}

// collectFirewalls lists the project's firewall rules and maps each to a
// gcp_firewall asset, flagging internet-open ingress. An instance's public IP
// alone does not decide reachability; these firewall rules do.
func collectFirewalls(ctx context.Context, client firewallAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	rules, err := client.ListFirewalls(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectFirewalls: %w", err)
	}

	exposure := internetExposure(rules)
	var assets []asset.Asset
	for _, fw := range rules {
		if fw.Name == "" {
			continue
		}
		ex := exposure[fw.Name]
		assets = append(assets, asset.Asset{
			ID:        projectID + "/firewall/" + fw.Name,
			Name:      fw.Name,
			Type:      "gcp_firewall",
			Provider:  asset.ProviderGCP,
			AccountID: projectID,
			Metadata: map[string]string{
				"network":          fw.Network,
				"direction":        fw.Direction,
				"disabled":         fmt.Sprintf("%t", fw.Disabled),
				"priority":         fmt.Sprintf("%d", fw.Priority),
				"source_ranges":    strings.Join(fw.SourceRanges, ","),
				"source_tags":      strings.Join(fw.SourceTags, ","),
				"source_sas":       strings.Join(fw.SourceSAs, ","),
				"target_tags":      strings.Join(fw.TargetTags, ","),
				"target_sas":       strings.Join(fw.TargetSAs, ","),
				"allowed":          fw.Allowed,
				"denied":           fw.Denied,
				"open_to_internet": fmt.Sprintf("%t", fw.OpenToInternet),
				"deny_world":       fmt.Sprintf("%t", fw.DenyWorld),
				// The listing is all-or-nothing, so every rule's precedence
				// against the rest of the project's rules is known.
				"destination_ranges":         strings.Join(fw.DestinationRanges, ","),
				"all_ports_open_to_internet": fmt.Sprintf("%t", ex.AllPorts),
				"ssh_open_to_internet":       fmt.Sprintf("%t", ex.SSH),
				"rdp_open_to_internet":       fmt.Sprintf("%t", ex.RDP),
				"shadowed_by_deny":           fmt.Sprintf("%t", ex.Shadowed),
				// open_ports: what stays reachable from the internet after the
				// denies, which is what the exposure severity is graded on.
				"open_ports": ex.Open,
			},
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

// newFirewallClient builds a real Compute-backed firewallAPI via ADC.
func newFirewallClient(ctx context.Context) (firewallAPI, error) {
	svc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newFirewallClient: %w", err)
	}
	return &realFirewall{svc: svc}, nil
}

// realFirewall adapts the Compute SDK to the provider-neutral firewallAPI.
type realFirewall struct {
	svc *compute.Service
}

func (r *realFirewall) ListFirewalls(ctx context.Context, projectID string) ([]gcpFirewall, error) {
	var out []gcpFirewall
	err := r.svc.Firewalls.List(projectID).Pages(ctx, func(page *compute.FirewallList) error {
		for _, fw := range page.Items {
			out = append(out, toNeutralFirewall(fw))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ListFirewalls: %w", err)
	}
	return out, nil
}

// toNeutralFirewall maps a Compute firewall rule and resolves its exposure. A
// rule is internet-open when it is an enabled INGRESS rule whose source ranges
// include 0.0.0.0/0 and that actually allows traffic. Direction defaults to
// INGRESS when the API omits it.
func toNeutralFirewall(fw *compute.Firewall) gcpFirewall {
	g := gcpFirewall{
		Name:         fw.Name,
		Network:      lastSegment(fw.Network),
		Direction:    fw.Direction,
		Disabled:     fw.Disabled,
		Priority:     fw.Priority,
		SourceRanges: fw.SourceRanges,
		SourceTags:   fw.SourceTags,
		SourceSAs:    fw.SourceServiceAccounts,
		TargetTags:   fw.TargetTags,
		TargetSAs:    fw.TargetServiceAccounts,

		DestinationRanges: fw.DestinationRanges,
	}
	if g.Direction == "" {
		g.Direction = "INGRESS"
	}
	if g.Direction == "INGRESS" && len(g.SourceRanges) == 0 && len(g.SourceTags) == 0 && len(g.SourceSAs) == 0 {
		g.SourceRanges = []string{internetCIDR}
	}
	// Priority is kept as returned. The API always populates it on a read (the
	// 1000 default is applied server-side when the rule is created), so a 0
	// here is a real priority-0 rule — the HIGHEST precedence — and rewriting
	// it to 1000 would let a priority-0 Deny lose to a priority-500 Allow.

	var allowed []string
	for _, a := range fw.Allowed {
		allowed = append(allowed, protoPorts(a.IPProtocol, a.Ports))
	}
	g.Allowed = strings.Join(allowed, ";")
	var denied []string
	for _, d := range fw.Denied {
		denied = append(denied, protoPorts(d.IPProtocol, d.Ports))
	}
	g.Denied = strings.Join(denied, ";")

	worldOpen := cidrset.CoversWorld(g.SourceRanges)
	isIngress := !fw.Disabled && g.Direction == "INGRESS" && worldOpen

	g.OpenToInternet = isIngress && len(fw.Allowed) > 0
	// DenyWorld: a deny rule at higher priority can block a lower-priority allow.
	// We model this for both GCP and Azure rather than just allow-rule presence.
	g.DenyWorld = isIngress && len(fw.Denied) > 0
	return g
}

// protoPorts renders one allowed/denied entry as "proto" or "proto:p1,p2-p3".
func protoPorts(proto string, ports []string) string {
	proto = normaliseProto(proto)
	if len(ports) == 0 {
		return proto
	}
	return proto + ":" + strings.Join(ports, ",")
}

func containsCIDR(ranges []string, cidr string) bool {
	for _, r := range ranges {
		if strings.TrimSpace(r) == cidr {
			return true
		}
	}
	return false
}
