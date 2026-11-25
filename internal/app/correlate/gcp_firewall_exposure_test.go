package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func worldFW(name, priority, sources, allowed, denied string, extra ...string) asset.Asset {
	m := map[string]string{
		"network": "default", "direction": "INGRESS", "disabled": "false",
		"priority": priority, "source_ranges": sources, "allowed": allowed, "denied": denied,
	}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return asset.Asset{ID: "proj/firewall/" + name, Type: "gcp_firewall", AccountID: "proj", Metadata: m}
}

func publicGCE(meta ...string) asset.Asset {
	m := map[string]string{"network": "default", "network_tags": "web", "firewall_rules_complete": "true",
		"network_interfaces": `[{"network":"default","private_ipv4":"10.23.1.10","public_ipv4":"34.1.2.3"}]`}
	for i := 0; i+1 < len(meta); i += 2 {
		m[meta[i]] = meta[i+1]
	}
	return asset.Asset{ID: "proj/vm", Type: "gce_instance", AccountID: "proj", PublicIP: "34.1.2.3", Metadata: m}
}

func TestInternetReachability_GCPFirewallPerPortEvaluation(t *testing.T) {
	cases := []struct {
		name      string
		inst      asset.Asset
		fws       []asset.Asset
		wantPorts string
		wantFW    string
	}{
		{"higher-priority deny on another port does not block",
			publicGCE(),
			[]asset.Asset{
				worldFW("deny-ssh", "100", "0.0.0.0/0", "", "tcp:22"),
				worldFW("allow-web", "1000", "0.0.0.0/0", "tcp:443", ""),
			}, "tcp:443", "proj/firewall/allow-web"},
		{"higher-priority deny on the same port blocks",
			publicGCE(),
			[]asset.Asset{
				worldFW("deny-all", "100", "0.0.0.0/0", "", "all"),
				worldFW("allow-web", "1000", "0.0.0.0/0", "tcp:443", ""),
			}, "", ""},
		{"deny on another protocol does not block",
			publicGCE(),
			[]asset.Asset{
				worldFW("deny-udp", "100", "0.0.0.0/0", "", "udp"),
				worldFW("allow-web", "1000", "0.0.0.0/0", "tcp:443", ""),
			}, "tcp:443", "proj/firewall/allow-web"},
		{"IPv4 deny does not block an IPv6 allow",
			publicGCE("network_interfaces", `[{"network":"default","private_ipv4":"10.23.1.10","public_ipv4":"34.1.2.3","external_ipv6":["2600:1234::1/128"]}]`),
			[]asset.Asset{
				worldFW("deny-v4", "100", "0.0.0.0/0", "", "all"),
				worldFW("allow-v6", "1000", "::/0", "tcp:443", ""),
			}, "tcp:443", "proj/firewall/allow-v6"},
		{"deny wins a priority tie",
			publicGCE(),
			[]asset.Asset{
				worldFW("deny", "1000", "0.0.0.0/0", "", "tcp:443"),
				worldFW("allow", "1000", "0.0.0.0/0", "tcp:443", ""),
			}, "", ""},
		{"priority 0 is the highest precedence, not the default",
			publicGCE(),
			[]asset.Asset{
				worldFW("deny", "0", "0.0.0.0/0", "", "tcp:443"),
				worldFW("allow", "500", "0.0.0.0/0", "tcp:443", ""),
			}, "", ""},
		{"deny carves a range out of an allow",
			publicGCE(),
			[]asset.Asset{
				worldFW("deny-ssh", "100", "0.0.0.0/0", "", "tcp:22"),
				worldFW("allow-range", "1000", "0.0.0.0/0", "tcp:20-25", ""),
			}, "tcp:20-21,tcp:23-25", "proj/firewall/allow-range"},
		{"target service account matches the instance SA",
			publicGCE("exec_role", "serviceAccount:web@proj.iam.gserviceaccount.com"),
			[]asset.Asset{worldFW("allow-sa", "1000", "0.0.0.0/0", "tcp:443", "",
				"target_sas", "web@proj.iam.gserviceaccount.com")},
			"tcp:443", "proj/firewall/allow-sa"},
		{"target service account scoping excludes other instances",
			publicGCE("exec_role", "serviceAccount:db@proj.iam.gserviceaccount.com"),
			[]asset.Asset{worldFW("allow-sa", "1000", "0.0.0.0/0", "tcp:443", "",
				"target_sas", "web@proj.iam.gserviceaccount.com")},
			"", ""},
		{"SA-targeted deny does not block an instance with another SA",
			publicGCE("exec_role", "serviceAccount:web@proj.iam.gserviceaccount.com"),
			[]asset.Asset{
				worldFW("deny-sa", "100", "0.0.0.0/0", "", "all", "target_sas", "other@proj.iam.gserviceaccount.com"),
				worldFW("allow", "1000", "0.0.0.0/0", "tcp:443", ""),
			}, "tcp:443", "proj/firewall/allow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edges := InternetReachability{}.Correlate(NewGraph(append([]asset.Asset{tc.inst}, tc.fws...)))
			if tc.wantPorts == "" {
				require.Empty(t, edges)
				return
			}
			require.Len(t, edges, 1)
			require.Equal(t, tc.wantPorts, edges[0].Properties["ports"])
			require.Equal(t, tc.wantFW, edges[0].Properties["firewall"])
		})
	}
}

func TestParseFirewallPorts(t *testing.T) {
	require.Equal(t, []fwPortRange{
		{"tcp", 22, 22}, {"tcp", 8000, 8100}, {"udp", 0, 65535}, {"all", 0, 65535},
	}, parseFirewallPorts("tcp:22,8000-8100;udp;all"))
	require.Empty(t, parseFirewallPorts(""))
}

func TestGCPFirewallApplies_ServiceAccountTargets(t *testing.T) {
	g := NewGraph([]asset.Asset{
		worldFW("allow-sa", "1000", "0.0.0.0/0", "tcp:443", "", "target_sas", "web@p.iam.gserviceaccount.com"),
		publicGCE("exec_role", "serviceAccount:web@p.iam.gserviceaccount.com"),
		{ID: "proj/other", Type: "gce_instance", AccountID: "proj",
			Metadata: map[string]string{"network": "default", "exec_role": "serviceAccount:db@p.iam.gserviceaccount.com"}},
	})
	edges := GCPFirewallApplies{}.Correlate(g)
	require.Len(t, edges, 1, "an SA-targeted rule is not a whole-network rule")
	require.Equal(t, "proj/vm", edges[0].DstID)
	require.Equal(t, "service_account", edges[0].Properties["scope"])
}
