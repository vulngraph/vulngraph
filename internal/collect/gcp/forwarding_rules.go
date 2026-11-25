package gcp

import (
	"context"
	"fmt"
	"path"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectForwardingRules fetches all EXTERNAL GCP Forwarding Rules (cloud load
// balancer VIPs) for a project. These are direct internet entry points — a
// forwarding rule with load_balancing_scheme=EXTERNAL has a public IP that
// receives traffic straight from the internet, and can be a high-value target
// for downstream scanning.
func collectForwardingRules(ctx context.Context, svc *compute.Service, projectID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset
	err := svc.ForwardingRules.AggregatedList(projectID).Pages(ctx, func(page *compute.ForwardingRuleAggregatedList) error {
		for _, scoped := range page.Items {
			for _, fr := range scoped.ForwardingRules {
				if fr.LoadBalancingScheme != "EXTERNAL" && fr.LoadBalancingScheme != "EXTERNAL_MANAGED" {
					continue
				}
				region := lastSegment(fr.Region)
				if region == "" {
					region = "global"
				}
				assets = append(assets, asset.Asset{
					ID:        projectID + "/forwarding-rule/" + fr.Name,
					Name:      fr.Name,
					Type:      "gcp_forwarding_rule",
					Provider:  asset.ProviderGCP,
					Region:    region,
					AccountID: projectID,
					PublicIP:  fr.IPAddress,
					Metadata: map[string]string{
						"scheme":     fr.LoadBalancingScheme,
						"port_range": fr.PortRange,
						"target":     path.Base(fr.Target),
						"public":     "true",
					},
					DiscoveredAt: now,
					LastSeen:     now,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("collectForwardingRules: %w", err)
	}
	return assets, nil
}
