package gcp

import (
	"testing"

	"github.com/stretchr/testify/require"
	compute "google.golang.org/api/compute/v1"
)

func TestNetworkSemanticsGCPOmittedIngressSource(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		sourceTags, sourceSA []string
		world                bool
	}{
		{"no-source-selector", nil, nil, true}, {"source-tag-only", []string{"backend"}, nil, false}, {"source-SA-only", nil, []string{"worker@p.iam.gserviceaccount.com"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := toNeutralFirewall(&compute.Firewall{Name: "checked", Direction: "INGRESS", SourceTags: tc.sourceTags, SourceServiceAccounts: tc.sourceSA, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"443"}}}})
			t.Logf("source=%v world=%t", r.SourceRanges, r.OpenToInternet)
			require.Equal(t, tc.world, r.OpenToInternet)
		})
	}
}

func TestNetworkSemanticsGCECollectorKeepsEveryNIC(t *testing.T) {
	in := &compute.Instance{NetworkInterfaces: []*compute.NetworkInterface{
		{Network: "projects/p/global/networks/private", NetworkIP: "10.0.0.1"},
		{Network: "projects/p/global/networks/public", NetworkIP: "10.1.0.1", AccessConfigs: []*compute.AccessConfig{{NatIP: "34.1.2.3"}}, Ipv6AccessConfigs: []*compute.AccessConfig{{ExternalIpv6: "2600:1234::", ExternalIpv6PrefixLength: 96}}},
	}}
	n := toNeutral(in)
	require.Equal(t, "34.1.2.3", n.PublicIP)
	require.Equal(t, "private", n.Network)
	require.Len(t, n.NetworkInterfaces, 2)
	require.Equal(t, gceNetworkInterface{Network: "public", PrivateIPv4: "10.1.0.1", PublicIPv4: "34.1.2.3", ExternalIPv6: []string{"2600:1234::/96"}}, n.NetworkInterfaces[1])
	require.Contains(t, gceMetadata(n, nil, false), "network_interfaces")
	n = toNeutral(&compute.Instance{NetworkInterfaces: []*compute.NetworkInterface{nil}})
	require.True(t, n.NetworkInterfaces[0].Unknown)
}

func TestNetworkUncertaintyGCPMissingInterfaceEvidence(t *testing.T) {
	for _, interfaces := range [][]*compute.NetworkInterface{
		nil, {},
		{{Network: "net", NetworkIP: "10.0.0.1", AccessConfigs: []*compute.AccessConfig{nil}}},
		{{Network: "net", NetworkIP: "10.0.0.1", AccessConfigs: []*compute.AccessConfig{{Type: "ONE_TO_ONE_NAT"}}}},
	} {
		var g gceInstance
		applyGCENetworkInterfaces(&g, interfaces)
		require.Len(t, g.NetworkInterfaces, 1)
		require.True(t, g.NetworkInterfaces[0].Unknown)
		if len(interfaces) == 0 {
			require.NotContains(t, gceMetadata(g, nil, false), "external_ip_configured")
		} else {
			require.Equal(t, "true", gceMetadata(g, nil, false)["external_ip_configured"])
		}
	}
	var private gceInstance
	applyGCENetworkInterfaces(&private, []*compute.NetworkInterface{{Network: "net", NetworkIP: "10.0.0.1"}})
	require.False(t, private.NetworkInterfaces[0].Unknown)
	require.False(t, private.ExternalIPConfigured)
	require.Equal(t, "false", gceMetadata(private, nil, false)["external_ip_configured"])
}
