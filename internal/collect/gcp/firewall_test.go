package gcp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	compute "google.golang.org/api/compute/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeFirewall struct {
	rules []gcpFirewall
	err   error
}

func (f *fakeFirewall) ListFirewalls(context.Context, string) ([]gcpFirewall, error) {
	return f.rules, f.err
}

func TestCollectFirewalls_MapsRulesAndOpenFlag(t *testing.T) {
	client := &fakeFirewall{rules: []gcpFirewall{
		{Name: "allow-ssh-world", Network: "default", Direction: "INGRESS", SourceRanges: []string{"0.0.0.0/0"}, Allowed: "tcp:22", OpenToInternet: true},
		{Name: "allow-internal", Network: "default", Direction: "INGRESS", SourceRanges: []string{"10.0.0.0/8"}, Allowed: "tcp:5432", OpenToInternet: false},
	}}

	assets, err := collectFirewalls(context.Background(), client, "proj-1", gcsNow)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	byID := map[string]asset.Asset{}
	for _, a := range assets {
		byID[a.ID] = a
	}

	open := byID["proj-1/firewall/allow-ssh-world"]
	require.Equal(t, "gcp_firewall", open.Type)
	require.Equal(t, asset.ProviderGCP, open.Provider)
	require.Equal(t, "proj-1", open.AccountID)
	require.Equal(t, "true", open.Metadata["open_to_internet"])
	require.Equal(t, "0.0.0.0/0", open.Metadata["source_ranges"])

	require.Equal(t, "false", byID["proj-1/firewall/allow-internal"].Metadata["open_to_internet"])
}

func TestCollectFirewalls_ListError(t *testing.T) {
	_, err := collectFirewalls(context.Background(), &fakeFirewall{err: errors.New("permission denied")}, "p", gcsNow)
	require.ErrorContains(t, err, "permission denied")
}

func TestToNeutralFirewall_OpenExposureLogic(t *testing.T) {
	tests := []struct {
		name string
		fw   *compute.Firewall
		open bool
	}{
		{"open ingress to world", &compute.Firewall{Name: "a", Direction: "INGRESS", SourceRanges: []string{"0.0.0.0/0"}, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}}}, true},
		{"empty direction defaults ingress", &compute.Firewall{Name: "b", SourceRanges: []string{"0.0.0.0/0"}, Allowed: []*compute.FirewallAllowed{{IPProtocol: "all"}}}, true},
		{"disabled is not open", &compute.Firewall{Name: "c", Direction: "INGRESS", Disabled: true, SourceRanges: []string{"0.0.0.0/0"}, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}}, false},
		{"egress is not ingress exposure", &compute.Firewall{Name: "d", Direction: "EGRESS", SourceRanges: []string{"0.0.0.0/0"}, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}}, false},
		{"internal range not open", &compute.Firewall{Name: "e", Direction: "INGRESS", SourceRanges: []string{"10.0.0.0/8"}, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp"}}}, false},
		{"no allow rules not open", &compute.Firewall{Name: "f", Direction: "INGRESS", SourceRanges: []string{"0.0.0.0/0"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.open, toNeutralFirewall(tt.fw).OpenToInternet)
		})
	}
}

func TestToNeutralFirewall_KeepsPriorityZeroDeniedAndTargetSAs(t *testing.T) {
	g := toNeutralFirewall(&compute.Firewall{
		Name: "deny-first", Direction: "INGRESS", Priority: 0, SourceRanges: []string{"0.0.0.0/0"},
		Denied:                []*compute.FirewallDenied{{IPProtocol: "tcp", Ports: []string{"22", "3389"}}, {IPProtocol: "icmp"}},
		TargetServiceAccounts: []string{"web@p.iam.gserviceaccount.com"},
	})
	require.Equal(t, int64(0), g.Priority, "priority 0 is the highest precedence, not unset")
	require.Equal(t, "tcp:22,3389;icmp", g.Denied)
	require.True(t, g.DenyWorld)
	require.Equal(t, []string{"web@p.iam.gserviceaccount.com"}, g.TargetSAs)

	assets, err := collectFirewalls(context.Background(), &fakeFirewall{rules: []gcpFirewall{g}}, "p", gcsNow)
	require.NoError(t, err)
	require.Equal(t, "0", assets[0].Metadata["priority"])
	require.Equal(t, "tcp:22,3389;icmp", assets[0].Metadata["denied"])
	require.Equal(t, "web@p.iam.gserviceaccount.com", assets[0].Metadata["target_sas"])
}

func TestToNeutralFirewall_AllowedSummary(t *testing.T) {
	g := toNeutralFirewall(&compute.Firewall{
		Name: "x", Direction: "INGRESS",
		Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22", "443"}}, {IPProtocol: "udp", Ports: []string{"53"}}},
	})
	require.Equal(t, "tcp:22,443;udp:53", g.Allowed)
}
