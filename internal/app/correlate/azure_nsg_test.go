package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// anyDst is the destination "*": every address the NSG guards.
var anyDst = checks.NSGDestination{Prefixes: []string{"*"}}

func azureVM(id, nicNSGs string) asset.Asset {
	return asset.Asset{ID: id, Type: "azure_vm", PublicIP: "20.0.0.1",
		Metadata: map[string]string{"nic_nsgs": nicNSGs}}
}

func TestNSGOpenPorts(t *testing.T) {
	cases := []struct {
		name  string
		rules [][]ingressRule
		want  string
	}{
		{"no NSG is not evidence of exposure", nil, ""},
		{"empty NSG hits default deny", [][]ingressRule{{}}, ""},
		{"Azure world spellings count as internet", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"Internet"}, Access: "allow", Priority: 100}},
		}, "tcp:22"},
		{"Any and * sources", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 80, ToPort: 80, CIDRs: []string{"Any"}, Access: "allow", Priority: 100},
				{Protocol: "udp", FromPort: 53, ToPort: 53, CIDRs: []string{"10.0.0.0/8", "*"}, Access: "allow", Priority: 110}},
		}, "tcp:80,udp:53"},
		{"non-internet source does not match", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"VirtualNetwork"}, Access: "allow", Priority: 100}},
		}, ""},
		{"higher-priority deny closes the port", [][]ingressRule{
			{{Protocol: "*", FromPort: 0, ToPort: 65535, CIDRs: []string{"*"}, Access: "allow", Priority: 200},
				{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"*"}, Access: "deny", Priority: 100, NSGDestination: anyDst}},
		}, "other,tcp:0-21,tcp:23-65535,udp:0-65535"},
		// A Deny closes only the destinations it names: one subnet denied
		// above an Allow to everything leaves every other destination open.
		{"deny on one subnet does not close an allow to everything", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"Internet"}, Access: "deny", Priority: 100,
				NSGDestination: checks.NSGDestination{Prefixes: []string{"10.0.2.0/24"}}},
				{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"Internet"}, Access: "allow", Priority: 200, NSGDestination: anyDst}},
		}, "tcp:22"},
		{"deny on the allow's subnet closes it", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"Internet"}, Access: "deny", Priority: 100,
				NSGDestination: checks.NSGDestination{Prefixes: []string{"10.0.0.0/16"}}},
				{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"Internet"}, Access: "allow", Priority: 200,
					NSGDestination: checks.NSGDestination{Prefixes: []string{"10.0.1.4"}}}},
		}, ""},
		{"deny with no recorded destination is not credited", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"Internet"}, Access: "deny", Priority: 100},
				{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"Internet"}, Access: "allow", Priority: 200, NSGDestination: anyDst}},
		}, "tcp:22"},
		{"lower-priority deny is shadowed by the allow", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"0.0.0.0/0"}, Access: "allow", Priority: 100},
				{Protocol: "*", FromPort: 0, ToPort: 65535, CIDRs: []string{"*"}, Access: "deny", Priority: 4000, NSGDestination: anyDst}},
		}, "tcp:22"},
		{"subnet NSG and NIC NSG must both allow", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 22, ToPort: 443, CIDRs: []string{"*"}, Access: "allow", Priority: 100}},
			{{Protocol: "tcp", FromPort: 443, ToPort: 8443, CIDRs: []string{"Internet"}, Access: "allow", Priority: 100}},
		}, "tcp:443"},
		{"one NSG denying everything closes the NIC", [][]ingressRule{
			{{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"*"}, Access: "allow", Priority: 100}},
			{{Protocol: "*", FromPort: 0, ToPort: 65535, CIDRs: []string{"*"}, Access: "deny", Priority: 100, NSGDestination: anyDst}},
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// These are fully read source-port wildcards; degraded source ports
			// have separate possible-tier controls in network_semantics_test.go.
			for i := range tc.rules {
				for j := range tc.rules[i] {
					tc.rules[i][j].SourcePorts = []string{"*"}
				}
			}
			require.Equal(t, tc.want, nsgOpenPorts(tc.rules))
		})
	}
}

func TestInternetReachability_AzureNSG(t *testing.T) {
	const (
		allow22 = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["*"],"destinations":["*"],"source_ports":["*"],"access":"allow","priority":200}]`
		deny22  = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["Internet"],"destinations":["*"],"source_ports":["*"],"access":"deny","priority":100},` +
			`{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["*"],"destinations":["*"],"source_ports":["*"],"access":"allow","priority":200}]`
		denyOtherSubnet22 = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["Internet"],"destinations":["10.0.2.0/24"],"source_ports":["*"],"access":"deny","priority":100},` +
			`{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["*"],"destinations":["*"],"source_ports":["*"],"access":"allow","priority":200}]`
		denyAll = `[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["*"],"destinations":["*"],"source_ports":["*"],"access":"deny","priority":100}]`
	)
	cases := []struct {
		name    string
		vm      asset.Asset
		nsgs    []asset.Asset
		exposed bool
		nsgProp string
	}{
		{"NIC NSG allows world on 22",
			azureVM("vm", `[{"public":true,"nsg_ids":["nsg-nic"]}]`),
			[]asset.Asset{sg("nsg-nic", allow22)}, true, "nsg-nic"},
		{"higher-priority deny wins",
			azureVM("vm", `[{"public":true,"nsg_ids":["nsg-nic"]}]`),
			[]asset.Asset{sg("nsg-nic", deny22)}, false, ""},
		{"deny on another subnet leaves the allow open",
			azureVM("vm", `[{"public":true,"nsg_ids":["nsg-nic"]}]`),
			[]asset.Asset{sg("nsg-nic", denyOtherSubnet22)}, true, "nsg-nic"},
		{"subnet NSG denies, NIC NSG allows",
			azureVM("vm", `[{"public":true,"nsg_ids":["nsg-subnet","nsg-nic"]}]`),
			[]asset.Asset{sg("nsg-subnet", denyAll), sg("nsg-nic", allow22)}, false, ""},
		{"subnet and NIC NSG both allow",
			azureVM("vm", `[{"public":true,"nsg_ids":["nsg-subnet","nsg-nic"]}]`),
			[]asset.Asset{sg("nsg-subnet", allow22), sg("nsg-nic", allow22)}, true, "nsg-subnet,nsg-nic"},
		{"second public NIC is open",
			azureVM("vm", `[{"public":true,"nsg_ids":["nsg-closed"]},{"public":true,"nsg_ids":["nsg-open"]}]`),
			[]asset.Asset{sg("nsg-closed", denyAll), sg("nsg-open", allow22)}, true, "nsg-open"},
		{"open NSG on a private NIC does not expose",
			azureVM("vm", `[{"public":true,"nsg_ids":["nsg-closed"]},{"public":false,"nsg_ids":["nsg-open"]}]`),
			[]asset.Asset{sg("nsg-closed", denyAll), sg("nsg-open", allow22)}, false, ""},
		{"NSG ID compared case-insensitively",
			azureVM("vm", `[{"public":true,"nsg_ids":["/subscriptions/s/resourceGroups/RG/providers/Microsoft.Network/networkSecurityGroups/N"]}]`),
			[]asset.Asset{sg("/subscriptions/s/resourcegroups/rg/providers/microsoft.network/networksecuritygroups/n", allow22)}, true,
			"/subscriptions/s/resourceGroups/RG/providers/Microsoft.Network/networkSecurityGroups/N"},
		{"legacy nsg_ids only",
			asset.Asset{ID: "vm", Type: "azure_vm", PublicIP: "20.0.0.1", Metadata: map[string]string{"nsg_ids": "nsg-nic"}},
			[]asset.Asset{sg("nsg-nic", allow22)}, true, "nsg-nic"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edges := InternetReachability{}.Correlate(NewGraph(append([]asset.Asset{tc.vm}, tc.nsgs...)))
			if !tc.exposed {
				require.Empty(t, edges)
				return
			}
			require.Len(t, edges, 1)
			require.Equal(t, "azure_nsg_world_open", edges[0].Properties["via"])
			require.Equal(t, tc.nsgProp, edges[0].Properties["nsg"])
			require.Equal(t, "tcp:22", edges[0].Properties["ports"])
		})
	}
}

// An NSG or public IP SKU that was not read is unknown, never closed: the NSGs
// that were read can still close a NIC, but what they leave open, and a NIC
// with nothing read at all, is possible. With no NSG anywhere the SKU decides:
// Basic admits everything, Standard nothing.
func TestInternetReachability_AzureUnreadNSGOrSKU(t *testing.T) {
	const (
		allow22 = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["*"],"destinations":["*"],"source_ports":["*"],"access":"allow","priority":200}]`
		denyAll = `[{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["*"],"destinations":["*"],"source_ports":["*"],"access":"deny","priority":100}]`
	)
	cases := []struct {
		name  string
		nics  string
		nsgs  []asset.Asset
		tier  string // "" = no edge
		via   string
		ports string
	}{
		{"NSG not in the view", `[{"public":true,"nsg_ids":["nsg-missing"]}]`, nil,
			asset.PublicAccessPossible, "azure_nsg_unknown", "all"},
		{"unread subnet NSG, NIC NSG allows", `[{"public":true,"nsg_ids":["nsg-nic"],"nsg_unknown":true}]`,
			[]asset.Asset{sg("nsg-nic", allow22)}, asset.PublicAccessPossible, "azure_nsg_world_open", "tcp:22"},
		{"unread subnet NSG, NIC NSG denies", `[{"public":true,"nsg_ids":["nsg-nic"],"nsg_unknown":true}]`,
			[]asset.Asset{sg("nsg-nic", denyAll)}, "", "", ""},
		{"one NSG missing, the other denies", `[{"public":true,"nsg_ids":["nsg-missing","nsg-nic"]}]`,
			[]asset.Asset{sg("nsg-nic", denyAll)}, "", "", ""},
		{"unread subnet NSG and no NIC NSG", `[{"public":true,"nsg_ids":null,"nsg_unknown":true,"public_ip_sku":"Standard"}]`, nil,
			asset.PublicAccessPossible, "azure_nsg_unknown", "all"},
		{"no NSG, Basic IP", `[{"public":true,"nsg_ids":null,"public_ip_sku":"Basic"}]`, nil,
			asset.PublicAccessConfirmed, "azure_no_nsg_basic_ip", "all"},
		{"no NSG, Standard IP", `[{"public":true,"nsg_ids":null,"public_ip_sku":"Standard"}]`, nil, "", "", ""},
		{"no NSG, SKU not read", `[{"public":true,"nsg_ids":null}]`, nil,
			asset.PublicAccessPossible, "azure_no_nsg_ip_sku_unknown", "all"},
		{"no NSG on a private NIC", `[{"public":false,"nsg_ids":null}]`, nil, "", "", ""},
		{"confirmed NIC wins over a possible one", `[{"public":true,"nsg_ids":["nsg-missing"]},{"public":true,"nsg_ids":["nsg-nic"],"public_ip":"20.0.0.1","private_ip":"10.0.0.1","endpoint_known":true}]`,
			[]asset.Asset{sg("nsg-nic", allow22)}, asset.PublicAccessConfirmed, "azure_nsg_world_open", "tcp:22"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edges := InternetReachability{}.Correlate(NewGraph(append([]asset.Asset{azureVM("vm", tc.nics)}, tc.nsgs...)))
			if tc.tier == "" {
				require.Empty(t, edges)
				return
			}
			require.Len(t, edges, 1)
			require.Equal(t, tc.tier, edges[0].Properties[asset.EdgePropPublicAccess])
			require.Equal(t, tc.via, edges[0].Properties["via"])
			require.Equal(t, tc.ports, edges[0].Properties["ports"])
		})
	}
}
