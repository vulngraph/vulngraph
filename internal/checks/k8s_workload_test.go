package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// A public LoadBalancer limited by loadBalancerSourceRanges, or one whose
// scheme was left to an AWS controller's default, is still reported, but not
// as open to the world.
func TestK8sServicePublicLoadBalancer(t *testing.T) {
	tests := []struct {
		name     string
		publicIP string
		md       map[string]string
		fires    bool
		severity finding.Severity
		title    string
	}{
		{"open LB", "1.2.3.4", map[string]string{"type": "LoadBalancer", "source_restricted": "false"}, true,
			finding.SeverityHigh, "Kubernetes Service is exposed via a public load balancer"},
		{"source-restricted LB", "1.2.3.4", map[string]string{"type": "LoadBalancer", "source_restricted": "true", "source_ranges": "203.0.113.0/24"}, true,
			finding.SeverityMedium, "Kubernetes Service is exposed via a public load balancer limited to source ranges"},
		{"controller NLB with no scheme", "nlb.example.com", map[string]string{"type": "LoadBalancer", "scheme_assumed": "true", "source_restricted": "false"}, true,
			finding.SeverityMedium, "Kubernetes Service may be exposed via a public load balancer (scheme not set)"},
		{"no scheme, source-restricted", "nlb.example.com", map[string]string{"type": "LoadBalancer", "scheme_assumed": "true", "source_restricted": "true"}, true,
			finding.SeverityMedium, "Kubernetes Service may be exposed via a public load balancer (scheme not set)"},
		{"restriction unread", "1.2.3.4", map[string]string{"type": "LoadBalancer"}, true,
			finding.SeverityHigh, "Kubernetes Service is exposed via a public load balancer"},
		{"internal LB", "", map[string]string{"type": "LoadBalancer", "internal": "true"}, false, "", ""},
		{"ClusterIP", "", map[string]string{"type": "ClusterIP"}, false, "", ""},
	}
	c := registered(t, k8sServicePublicLoadBalancer.ID)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{ID: "c/service/prod/web", Type: "k8s_service", Provider: asset.ProviderKubernetes, PublicIP: tt.publicIP, Metadata: tt.md}
			require.Equal(t, tt.fires, c.Violates(a))
			if tt.fires {
				require.Equal(t, tt.severity, c.SeverityFor(a))
				require.Equal(t, tt.title, c.TitleFor(a))
			}
		})
	}
}
