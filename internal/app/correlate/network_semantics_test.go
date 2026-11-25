package correlate

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/vulngraph/vulngraph/internal/checks"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestNetworkSemanticsGCEExposure(t *testing.T) {
	inst := publicGCE()
	inst.PrivateIP = "10.23.1.10"
	allow := worldFW("allow", "200", "0.0.0.0/0", "tcp:22", "")
	for _, tc := range []struct {
		name  string
		rules []asset.Asset
		want  int
	}{
		{"irrelevant-deny", []asset.Asset{allow, worldFW("deny", "100", "0.0.0.0/0", "", "tcp:22", "destination_ranges", "10.23.2.0/24")}, 1},
		{"irrelevant-allow", []asset.Asset{worldFW("allow", "200", "0.0.0.0/0", "tcp:22", "", "destination_ranges", "10.23.2.0/24")}, 0},
		{"other-address-family", []asset.Asset{worldFW("allow6", "200", "::/0", "tcp:22", "")}, 0},
		{"numeric-tcp-deny", []asset.Asset{allow, worldFW("deny6", "100", "0.0.0.0/0", "", "6")}, 0},
		{"matching-destination-control", []asset.Asset{allow, worldFW("deny", "100", "0.0.0.0/0", "", "tcp:22", "destination_ranges", "10.23.1.0/24")}, 0},
		{"applicable-allow-control", []asset.Asset{allow}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es := InternetReachability{}.Correlate(NewGraph(append([]asset.Asset{inst}, tc.rules...)))
			t.Logf("edges=%+v", es)
			require.Len(t, es, tc.want)
		})
	}
}

func TestNetworkSemanticsAzureSameDestination(t *testing.T) {
	const begin = `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["Internet"],"destinations":[`
	const end = `],"access":"allow","priority":100}]`
	vm := azureVM("vm", `[{"public":true,"nsg_ids":["subnet-nsg","nic-nsg"]}]`)
	vm.PrivateIP = "10.0.0.10"
	for _, tc := range []struct {
		name, dst string
		want      int
	}{
		{"disjoint", `"10.0.0.11"`, 0}, {"matching-control", `"10.0.0.10"`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{vm, sg("subnet-nsg", begin+`"10.0.0.10"`+end), sg("nic-nsg", begin+tc.dst+end)}))
			t.Logf("edges=%+v", es)
			require.Len(t, es, tc.want)
		})
	}
}

func TestNetworkSemanticsAWSRouteUnknownTier(t *testing.T) {
	inst := publicEC2("i-review", "")
	es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{inst, sg("sg-open", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`)}))
	require.Len(t, es, 1)
	t.Logf("properties=%v", es[0].Properties)
	require.Equal(t, asset.PublicAccessPossible, es[0].Properties[asset.EdgePropPublicAccess])
}

func TestNetworkSemanticsGCEEvidenceAndInterfaces(t *testing.T) {
	allow := worldFW("allow", "200", "0.0.0.0/0", "tcp:22", "")
	allow6 := worldFW("allow6", "200", "::/0", "tcp:22", "")
	for _, tc := range []struct {
		name, nics, complete string
		rules                []asset.Asset
		tier                 string
	}{
		{"known empty rules", `[{"network":"default","private_ipv4":"10.0.0.1","public_ipv4":"34.1.2.3"}]`, "true", nil, ""},
		{"failed rule list", `[{"network":"default","private_ipv4":"10.0.0.1","public_ipv4":"34.1.2.3"}]`, "false", nil, asset.PublicAccessPossible},
		{"legacy rule list", `[{"network":"default","private_ipv4":"10.0.0.1","public_ipv4":"34.1.2.3"}]`, "", []asset.Asset{allow}, asset.PublicAccessPossible},
		{"public second NIC uses own network", `[{"network":"default","private_ipv4":"10.0.0.1"},{"network":"other","private_ipv4":"10.1.0.1","public_ipv4":"34.1.2.3"}]`, "true", []asset.Asset{allow}, ""},
		{"second public NIC allowed", `[{"network":"other","private_ipv4":"10.0.0.1"},{"network":"default","private_ipv4":"10.1.0.1","public_ipv4":"34.1.2.3"}]`, "true", []asset.Asset{allow}, asset.PublicAccessConfirmed},
		{"IPv6 only NIC", `[{"network":"default","external_ipv6":["2600:1234::/96"]}]`, "true", []asset.Asset{allow6}, asset.PublicAccessConfirmed},
		{"IPv6 narrower destination", `[{"network":"default","external_ipv6":["2600:1234::/96"]}]`, "true", []asset.Asset{worldFW("subset", "200", "::/0", "tcp:22", "", "destination_ranges", "2600:1234::100/128")}, asset.PublicAccessConfirmed},
		{"known no public addresses", `[{"network":"default","private_ipv4":"10.0.0.1"}]`, "true", []asset.Asset{allow}, ""},
		{"malformed NIC evidence", `{broken`, "true", []asset.Asset{allow}, asset.PublicAccessPossible},
		{"unknown destination denies cannot close", `[{"network":"default","public_ipv4":"34.1.2.3"}]`, "true", []asset.Asset{allow, worldFW("deny", "100", "0.0.0.0/0", "", "tcp:22", "destination_ranges", "10.0.0.0/8")}, asset.PublicAccessPossible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst := publicGCE("network_interfaces", tc.nics, "firewall_rules_complete", tc.complete)
			es := InternetReachability{}.Correlate(NewGraph(append([]asset.Asset{inst}, tc.rules...)))
			if tc.tier == "" {
				require.Empty(t, es)
				return
			}
			require.Len(t, es, 1)
			require.Equal(t, tc.tier, es[0].Properties[asset.EdgePropPublicAccess])
		})
	}
}

func TestNetworkSemanticsAzurePacketMatrix(t *testing.T) {
	const nic = `[{"public":true,"public_ip":"20.0.0.1","private_ip":"10.0.0.10","endpoint_known":true,"asgs":["asg-web"],"nsg_ids":["subnet","nic"]}]`
	rule := func(dst, source, ports, action string, priority int32) ingressRule {
		return ingressRule{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{source}, SourcePorts: []string{ports}, Access: action, Priority: priority, NSGDestination: checks.NSGDestination{Prefixes: []string{dst}}}
	}
	allow := rule("*", "Internet", "*", "allow", 200)
	for _, tc := range []struct {
		name    string
		a, b    []ingressRule
		private bool
		tier    string
	}{
		{"same private destination", []ingressRule{rule("10.0.0.10", "Internet", "*", "allow", 200)}, []ingressRule{allow}, true, asset.PublicAccessConfirmed},
		{"other destination deny ignored", []ingressRule{rule("10.0.0.11", "Internet", "*", "deny", 100), allow}, []ingressRule{allow}, true, asset.PublicAccessConfirmed},
		{"matching destination deny blocks", []ingressRule{rule("10.0.0.10", "Internet", "*", "deny", 100), allow}, []ingressRule{allow}, true, ""},
		{"disjoint source ports", []ingressRule{rule("*", "Internet", "1000-2000", "allow", 200)}, []ingressRule{rule("*", "Internet", "3000-4000", "allow", 200)}, true, ""},
		{"one shared source port", []ingressRule{rule("*", "Internet", "1000-2000", "allow", 200)}, []ingressRule{rule("*", "Internet", "2000-3000", "allow", 200)}, true, asset.PublicAccessConfirmed},
		{"unknown source ports on deny", []ingressRule{rule("*", "Internet", "", "deny", 100), allow}, []ingressRule{allow}, true, asset.PublicAccessPossible},
		{"unknown source ports on allow", []ingressRule{rule("*", "Internet", "", "allow", 200)}, []ingressRule{allow}, true, asset.PublicAccessPossible},
		{"unknown tag deny cannot close", []ingressRule{rule("AzureCloud", "Internet", "*", "deny", 100), allow}, []ingressRule{allow}, true, asset.PublicAccessPossible},
		{"IPv6 source cannot reach IPv4 public endpoint", []ingressRule{rule("*", "::/0", "*", "allow", 200)}, []ingressRule{allow}, true, ""},
		{"unknown private IP disjoint destination sets", []ingressRule{rule("10.0.0.10", "Internet", "*", "allow", 200)}, []ingressRule{rule("10.0.0.11", "Internet", "*", "allow", 200)}, false, ""},
		{"unknown private IP same candidate", []ingressRule{rule("10.0.0.10", "Internet", "*", "allow", 200)}, []ingressRule{rule("10.0.0.10", "Internet", "*", "allow", 200)}, false, asset.PublicAccessPossible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := azureVM("vm", nic)
			if !tc.private {
				vm.Metadata["nic_nsgs"] = strings.ReplaceAll(nic, `"private_ip":"10.0.0.10",`, "")
			}
			a, _ := json.Marshal(tc.a)
			b, _ := json.Marshal(tc.b)
			es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{vm, sg("subnet", string(a)), sg("nic", string(b))}))
			if tc.tier == "" {
				require.Empty(t, es)
				return
			}
			require.Len(t, es, 1)
			require.Equal(t, tc.tier, es[0].Properties[asset.EdgePropPublicAccess])
		})
	}
}

func TestNetworkSemanticsAzureIncompleteVersusEmpty(t *testing.T) {
	for _, tc := range []struct{ name, raw, complete, tier string }{
		{"known empty", "", "true", ""}, {"known empty JSON", "[]", "true", ""},
		{"unread", "", "", asset.PublicAccessPossible}, {"malformed", "{", "true", asset.PublicAccessPossible},
		{"partial", "[]", "false", asset.PublicAccessPossible}, {"null", "null", "true", asset.PublicAccessPossible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm := azureVM("vm", `[{"public":true,"nsg_ids":["nsg"]}]`)
			nsg := sg("nsg", tc.raw)
			nsg.Metadata["nsg_rules_complete"] = tc.complete
			es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{vm, nsg}))
			if tc.tier == "" {
				require.Empty(t, es)
				return
			}
			require.Len(t, es, 1)
			require.Equal(t, tc.tier, es[0].Properties[asset.EdgePropPublicAccess])
		})
	}
	for _, raw := range []string{"{", "null"} {
		es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{azureVM("vm", raw)}))
		require.Len(t, es, 1)
		require.Equal(t, asset.PublicAccessPossible, es[0].Properties[asset.EdgePropPublicAccess])
	}
}

func TestNetworkSemanticsAWSObservedRoutesAndSGs(t *testing.T) {
	for _, tc := range []struct{ name, raw, count, route, tier string }{
		{"observed empty", "", "0", "true", ""},
		{"missing rules", "", "", "true", asset.PublicAccessPossible},
		{"malformed rules", "{", "1", "true", asset.PublicAccessPossible},
		{"unread route", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`, "1", "", asset.PublicAccessPossible},
		{"observed public route", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`, "1", "true", asset.PublicAccessConfirmed},
		{"observed private route", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`, "1", "false", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nsg := sg("sg-open", tc.raw)
			nsg.Metadata["ingress_rules"] = tc.count
			es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{publicEC2("i", tc.route), nsg}))
			if tc.tier == "" {
				require.Empty(t, es)
				return
			}
			require.Len(t, es, 1)
			require.Equal(t, tc.tier, es[0].Properties[asset.EdgePropPublicAccess])
		})
	}
	inst := publicEC2("i", "true")
	es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{inst}))
	require.Len(t, es, 1)
	require.Equal(t, asset.PublicAccessPossible, es[0].Properties[asset.EdgePropPublicAccess])
}

func TestNetworkSemanticsAzureWorkLimitStaysPossible(t *testing.T) {
	var rules []ingressRule
	for i := int32(1); i < 600; i++ {
		rules = append(rules, ingressRule{Protocol: "tcp", FromPort: i, ToPort: i, CIDRs: []string{"Internet"}, SourcePorts: []string{fmt.Sprint(i)}, Access: "allow", Priority: 100, NSGDestination: checks.NSGDestination{Prefixes: []string{"*"}}})
	}
	ports := nsgPacketPorts([][]ingressRule{rules}, azureNIC{PublicIP: "20.0.0.1", PrivateIP: "10.0.0.1"})
	require.Equal(t, "all", ports.possible)
	require.Empty(t, ports.confirmed)
}

func TestNetworkSemanticsAzureASGMembership(t *testing.T) {
	rule := ingressRule{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"Internet"}, SourcePorts: []string{"*"}, Access: "allow", Priority: 200, NSGDestination: checks.NSGDestination{ASGs: []string{"asg-web"}}}
	for _, tc := range []struct {
		name   string
		groups []string
		known  bool
		want   networkMatch
	}{
		{"known member", []string{"ASG-WEB"}, true, networkYes},
		{"known nonmember", []string{"asg-db"}, true, networkNo},
		{"known empty", nil, true, networkNo},
		{"membership unread", nil, false, networkUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := 100
			got := nsgPacketDecision([]ingressRule{rule}, azureNIC{ASGs: tc.groups, EndpointKnown: tc.known}, netip.MustParseAddr("10.0.0.10"), false, "tcp", 443, 1024, &budget)
			require.Equal(t, tc.want, got)
		})
	}
	deny := rule
	deny.Access = "deny"
	deny.Priority = 100
	allow := rule
	allow.NSGDestination = anyDst
	for _, known := range []bool{true, false} {
		budget := 100
		got := nsgPacketDecision([]ingressRule{deny, allow}, azureNIC{EndpointKnown: known}, netip.MustParseAddr("10.0.0.10"), false, "tcp", 443, 1024, &budget)
		if known {
			require.Equal(t, networkYes, got)
		} else {
			require.Equal(t, networkUnknown, got)
		}
	}
}

func TestNetworkSemanticsGCPNarrowDenyPreservesUncertainty(t *testing.T) {
	es := InternetReachability{}.Correlate(NewGraph([]asset.Asset{publicGCE(),
		worldFW("allow", "200", "0.0.0.0/0", "tcp:22", ""),
		worldFW("deny-low", "100", "0.0.0.0/1", "", "tcp:22"),
		worldFW("deny-high", "100", "128.0.0.0/1", "", "tcp:22"),
	}))
	require.Len(t, es, 1)
	require.Equal(t, asset.PublicAccessPossible, es[0].Properties[asset.EdgePropPublicAccess], "separate narrow denies cannot be ignored and then called a confirmed world path")
}

func TestNetworkSemanticsGCPWorkLimitStaysPossible(t *testing.T) {
	rules := []worldFirewallRule{{id: "allow", v4: true, ranges: []fwPortRange{{proto: "tcp", from: 22, to: 22}}}}
	budget := 0
	ports, _ := gceInstanceExposure(prepareGCEFirewallRules(rules), netip.MustParseAddr("10.0.0.1"), false, &budget)
	require.Equal(t, "all", ports.possible)
	require.Empty(t, ports.confirmed)
}
