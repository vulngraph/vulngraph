package correlate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestNetworkUncertaintyMixedPortGrades(t *testing.T) {
	for _, provider := range []string{"gcp", "azure"} {
		t.Run(provider, func(t *testing.T) {
			var assets []asset.Asset
			if provider == "gcp" {
				assets = []asset.Asset{publicGCE(), worldFW("limited", "100", "192.0.2.0/24", "", "tcp:22"), worldFW("allow", "200", "0.0.0.0/0", "tcp:22,443", "")}
			} else {
				assets = []asset.Asset{azureVM("vm", `[{"public":true,"public_ip":"20.0.0.1","private_ip":"10.0.0.1","endpoint_known":true,"nsg_ids":["nsg"]}]`), sg("nsg", `[
     {"protocol":"tcp","from_port":22,"to_port":22,"source_ports":["*"],"cidrs":["Internet"],"destinations":["UnknownServiceTag"],"access":"allow","priority":100},
     {"protocol":"tcp","from_port":443,"to_port":443,"source_ports":["*"],"cidrs":["Internet"],"destinations":["*"],"access":"allow","priority":200}]`)}
			}
			es := InternetReachability{}.Correlate(NewGraph(assets))
			require.Len(t, es, 1)
			require.Equal(t, asset.PublicAccessConfirmed, es[0].Properties[asset.EdgePropPublicAccess])
			require.Equal(t, "tcp:443", es[0].Properties["ports"])
			require.Equal(t, "tcp:22", es[0].Properties["possible_ports"])
		})
	}
}

func TestNetworkUncertaintyAzureUnknownFamily(t *testing.T) {
	for _, source := range []string{"0.0.0.0/0", "::/0"} {
		t.Run(source, func(t *testing.T) {
			vm := azureVM("vm", `[{"public":true,"nsg_ids":["nsg"]}]`)
			vm.PublicIP = ""
			vm.Metadata["direct_public_ip"] = "true"
			nsg := sg("nsg", `[{"protocol":"tcp","from_port":443,"to_port":443,"source_ports":["*"],"cidrs":["`+source+`"],"destinations":["*"],"access":"allow","priority":100}]`)
			es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{vm, nsg}))
			require.Len(t, es, 1)
			require.Equal(t, asset.PublicAccessPossible, es[0].Properties[asset.EdgePropPublicAccess])
		})
	}
}

func TestNetworkUncertaintyGCPUnknownEndpointKeepsCandidate(t *testing.T) {
	for _, nics := range []string{`[{"network":"default","private_ipv4":"10.0.0.1","unknown":true}]`, `[{"unknown":true}]`} {
		inst := publicGCE("network_interfaces", nics)
		inst.PublicIP = ""
		es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{inst, worldFW("allow", "200", "0.0.0.0/0", "tcp:443", "")}))
		require.Len(t, es, 1)
		require.Equal(t, asset.PublicAccessPossible, es[0].Properties[asset.EdgePropPublicAccess])
	}
}

func TestNetworkUncertaintyNonPortProtocolsStayCandidates(t *testing.T) {
	for _, provider := range []string{"gcp", "azure"} {
		for _, proto := range []string{"all", "icmp"} {
			t.Run(provider+"/"+proto, func(t *testing.T) {
				var assets []asset.Asset
				if provider == "gcp" {
					assets = []asset.Asset{publicGCE(), worldFW("allow", "200", "0.0.0.0/0", proto, ""), worldFW("deny", "100", "0.0.0.0/0", "", "tcp;udp")}
				} else {
					azureProto := proto
					if proto == "all" {
						azureProto = "*"
					}
					assets = []asset.Asset{azureVM("vm", `[{"public":true,"public_ip":"20.0.0.1","private_ip":"10.0.0.1","endpoint_known":true,"nsg_ids":["nsg"]}]`), sg("nsg", `[
      {"protocol":"tcp","from_port":0,"to_port":65535,"source_ports":["*"],"cidrs":["Internet"],"destinations":["*"],"access":"deny","priority":100},
      {"protocol":"udp","from_port":0,"to_port":65535,"source_ports":["*"],"cidrs":["Internet"],"destinations":["*"],"access":"deny","priority":110},
      {"protocol":"`+azureProto+`","from_port":0,"to_port":65535,"source_ports":["*"],"cidrs":["Internet"],"destinations":["*"],"access":"allow","priority":200}]`)}
				}
				es := InternetReachability{}.Correlate(NewGraph(assets))
				require.Len(t, es, 1)
				require.Equal(t, asset.PublicAccessPossible, es[0].Properties[asset.EdgePropPublicAccess])
				require.False(t, strings.Contains(es[0].Properties["ports"], "tcp"))
			})
		}
	}
}

func TestNetworkUncertaintyKnownEmptyNSGShortCircuits(t *testing.T) {
	// Even a large irrelevant rule set must not construct an address/port
	// cross product when another fully observed NSG denies all by default.
	rules := make([]ingressRule, 10000)
	for i := range rules {
		rules[i] = ingressRule{Protocol: "tcp", FromPort: int32(i), ToPort: int32(i)}
	}
	for _, sets := range [][][]ingressRule{{nil, rules}, {rules, nil}} {
		require.Equal(t, networkPorts{}, nsgPacketPorts(sets, azureNIC{}))
	}
}
