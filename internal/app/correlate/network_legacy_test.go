package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestNetworkLegacyGCEPositiveAndMalformedAddressEvidence(t *testing.T) {
	for _, tc := range []struct{ name, nics string }{{"legacy positive access config", ""}, {"malformed IPv4", `[{"network":"default","public_ipv4":"unreadable"}]`}, {"malformed IPv6", `[{"network":"default","external_ipv6":["unreadable"]}]`}} {
		t.Run(tc.name, func(t *testing.T) {
			inst := publicGCE()
			inst.PublicIP = ""
			inst.Metadata["external_ip_configured"] = "true"
			inst.Metadata["firewall_rules_complete"] = "true"
			if tc.nics == "" {
				delete(inst.Metadata, "network_interfaces")
			} else {
				inst.Metadata["network_interfaces"] = tc.nics
			}
			es := (InternetReachability{}).Correlate(NewGraph([]asset.Asset{inst, worldFW("allow", "200", "::/0", "tcp:443", ""), worldFW("allow4", "200", "0.0.0.0/0", "tcp:443", "")}))
			t.Logf("edges=%v", es)
			if len(es) != 1 || es[0].Properties[asset.EdgePropPublicAccess] != asset.PublicAccessPossible {
				t.Error("positive access config with unknown interface or address should preserve a possible path")
			}
		})
	}
}

func TestNetworkLegacyGCEConfiguredEndpointMayUseAnotherNetwork(t *testing.T) {
	inst := publicGCE("external_ip_configured", "true")
	delete(inst.Metadata, "network_interfaces")
	inst.PublicIP = ""
	fw := worldFW("other-nic", "200", "0.0.0.0/0", "tcp:443", "", "network", "secondary-network")
	es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{inst, fw}))
	require.Len(t, es, 1)
	require.Equal(t, asset.PublicAccessPossible, es[0].Properties[asset.EdgePropPublicAccess])
}

func TestNetworkLegacyGCEPrivateControls(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		inst := publicGCE("external_ip_configured", "false")
		inst.PublicIP = ""
		if legacy {
			delete(inst.Metadata, "network_interfaces")
		} else {
			inst.Metadata["network_interfaces"] = `[{"network":"default","private_ipv4":"10.0.0.1"}]`
		}
		es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{inst, worldFW("allow", "200", "0.0.0.0/0", "tcp:443", "")}))
		require.Empty(t, es)
	}
	require.Contains(t, metadataProjectedKeys, "external_ip_configured", "legacy positive evidence must survive the SQL projection")
}
