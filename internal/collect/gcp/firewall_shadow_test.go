package gcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	compute "google.golang.org/api/compute/v1"
)

func worldAllow(name, allowed string, prio int64) gcpFirewall {
	return gcpFirewall{Name: name, Network: "default", Direction: "INGRESS", Priority: prio,
		SourceRanges: []string{"0.0.0.0/0"}, Allowed: allowed, OpenToInternet: true}
}

func worldDeny(name, denied string, prio int64) gcpFirewall {
	return gcpFirewall{Name: name, Network: "default", Direction: "INGRESS", Priority: prio,
		SourceRanges: []string{"0.0.0.0/0"}, Denied: denied, DenyWorld: true}
}

// TestInternetExposure pins how a world-sourced deny is credited against an
// internet-open allow: only when it takes precedence, sits on the same network,
// covers every target, every destination and every internet family, and names
// the ports. Open is what remains reachable.
func TestInternetExposure(t *testing.T) {
	tagged := func(fw gcpFirewall, tags ...string) gcpFirewall { fw.TargetTags = tags; return fw }
	sas := func(fw gcpFirewall, emails ...string) gcpFirewall { fw.TargetSAs = emails; return fw }
	dest := func(fw gcpFirewall, cidrs ...string) gcpFirewall { fw.DestinationRanges = cidrs; return fw }
	v6 := func(fw gcpFirewall) gcpFirewall { fw.SourceRanges = append(fw.SourceRanges, "::/0"); return fw }
	tests := []struct {
		name  string
		rules []gcpFirewall
		want  fwExposure
	}{
		{"ssh open", []gcpFirewall{worldAllow("a", "tcp:22", 1000)}, fwExposure{SSH: true, Open: "tcp:22"}},
		{"rdp in a range", []gcpFirewall{worldAllow("a", "tcp:3000-4000", 1000)}, fwExposure{RDP: true, Open: "tcp:3000-4000"}},
		{"all protocols is one all-ports exposure, not per admin port", []gcpFirewall{worldAllow("a", "all", 1000)},
			fwExposure{AllPorts: true, Open: "all"}},
		{"every tcp port is all-ports", []gcpFirewall{worldAllow("a", "tcp", 1000)}, fwExposure{AllPorts: true, Open: "tcp"}},
		{"protocol number 6 is tcp", []gcpFirewall{worldAllow("a", "6:22", 1000)}, fwExposure{SSH: true, Open: "tcp:22"}},
		{"web only", []gcpFirewall{worldAllow("a", "tcp:80,443", 1000)}, fwExposure{Open: "tcp:80,443"}},
		{"udp 22 is not ssh", []gcpFirewall{worldAllow("a", "udp:22", 1000)}, fwExposure{Open: "udp:22"}},
		{"higher-precedence deny shadows ssh",
			[]gcpFirewall{worldAllow("a", "tcp:22", 1000), worldDeny("d", "tcp:22", 900)},
			fwExposure{Shadowed: true}},
		{"deny wins a priority tie",
			[]gcpFirewall{worldAllow("a", "tcp:22", 1000), worldDeny("d", "tcp", 1000)},
			fwExposure{Shadowed: true}},
		{"lower-precedence deny does not",
			[]gcpFirewall{worldAllow("a", "tcp:22", 1000), worldDeny("d", "tcp:22", 1100)},
			fwExposure{SSH: true, Open: "tcp:22"}},
		{"deny on another network does not",
			[]gcpFirewall{worldAllow("a", "tcp:22", 1000), func() gcpFirewall { d := worldDeny("d", "all", 1); d.Network = "other"; return d }()},
			fwExposure{SSH: true, Open: "tcp:22"}},
		{"partial deny leaves the rest open",
			[]gcpFirewall{worldAllow("a", "tcp:22,3389", 1000), worldDeny("d", "tcp:22", 10)},
			fwExposure{RDP: true, Open: "tcp:3389"}},
		{"what remains after a deny is what is graded",
			[]gcpFirewall{worldAllow("a", "tcp", 1000), worldDeny("d", "tcp:1-79,81-65535", 10)},
			fwExposure{Open: "tcp:0,80"}},
		{"a deny of one admin port turns all-ports into the other admin port",
			[]gcpFirewall{worldAllow("a", "tcp", 1000), worldDeny("d", "tcp:0-3388,3390-65535", 10)},
			fwExposure{RDP: true, Open: "tcp:3389"}},
		{"deny split across rules covers the range",
			[]gcpFirewall{worldAllow("a", "tcp:20-30", 1000), worldDeny("d1", "tcp:20-24", 10), worldDeny("d2", "tcp:25-30", 10)},
			fwExposure{Shadowed: true}},
		{"tcp-only deny does not shadow an all-protocol allow",
			[]gcpFirewall{worldAllow("a", "all", 1000), worldDeny("d", "tcp", 10)},
			fwExposure{AllPorts: true, Open: "all"}},
		{"deny targeting a subset of the allow's instances does not",
			[]gcpFirewall{worldAllow("a", "tcp:22", 1000), tagged(worldDeny("d", "tcp:22", 10), "web")},
			fwExposure{SSH: true, Open: "tcp:22"}},
		{"deny listing every tag of the allow does",
			[]gcpFirewall{tagged(worldAllow("a", "tcp:22", 1000), "web"), tagged(worldDeny("d", "tcp:22", 10), "web", "db")},
			fwExposure{Shadowed: true}},
		{"deny listing only some of the allow's tags does not",
			[]gcpFirewall{tagged(worldAllow("a", "tcp:22", 1000), "a", "b"), tagged(worldDeny("d", "tcp:22", 10), "a")},
			fwExposure{SSH: true, Open: "tcp:22"}},
		{"deny on every service account of the allow does",
			[]gcpFirewall{sas(worldAllow("a", "tcp:22", 1000), "x@p"), sas(worldDeny("d", "tcp:22", 10), "x@p", "y@p")},
			fwExposure{Shadowed: true}},
		{"deny on some of the allow's service accounts does not",
			[]gcpFirewall{sas(worldAllow("a", "tcp:22", 1000), "x@p", "y@p"), sas(worldDeny("d", "tcp:22", 10), "x@p")},
			fwExposure{SSH: true, Open: "tcp:22"}},
		{"deny limited to one subnet does not cover a network-wide allow",
			[]gcpFirewall{worldAllow("a", "tcp:22", 1000), dest(worldDeny("d", "all", 100), "10.0.2.0/24")},
			fwExposure{SSH: true, Open: "tcp:22"}},
		{"deny covering the allow's destinations does",
			[]gcpFirewall{dest(worldAllow("a", "tcp:22", 1000), "10.0.2.0/25"), dest(worldDeny("d", "all", 100), "10.0.0.0/16")},
			fwExposure{Shadowed: true}},
		{"deny narrower than the allow's destination does not",
			[]gcpFirewall{dest(worldAllow("a", "tcp:22", 1000), "10.0.0.0/8"), dest(worldDeny("d", "all", 100), "10.0.0.0/16")},
			fwExposure{SSH: true, Open: "tcp:22"}},
		{"deny covering only part of the allow's destinations does not",
			[]gcpFirewall{dest(worldAllow("a", "tcp:22", 1000), "10.0.2.0/24", "10.9.0.0/24"), dest(worldDeny("d", "all", 100), "10.0.0.0/16")},
			fwExposure{SSH: true, Open: "tcp:22"}},
		{"ipv4 deny leaves ipv6 open",
			[]gcpFirewall{v6(worldAllow("a", "tcp:22", 1000)), worldDeny("d", "tcp:22", 10)},
			fwExposure{SSH: true, Open: "tcp:22"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, internetExposure(tt.rules)["a"])
		})
	}
}

func TestToNeutralFirewall_KeepsDestinationRanges(t *testing.T) {
	g := toNeutralFirewall(&compute.Firewall{Name: "d", Direction: "INGRESS", DestinationRanges: []string{"10.0.2.0/24"}})
	require.Equal(t, []string{"10.0.2.0/24"}, g.DestinationRanges)
}

func TestCollectFirewalls_StampsEffectiveExposure(t *testing.T) {
	client := &fakeFirewall{rules: []gcpFirewall{
		worldAllow("ssh", "tcp:22", 1000),
		worldAllow("rdp-blocked", "tcp:3389", 1000),
		worldDeny("deny-rdp", "tcp:3389", 100),
	}}
	assets, err := collectFirewalls(context.Background(), client, "p", gcsNow)
	require.NoError(t, err)
	md := map[string]map[string]string{}
	for _, a := range assets {
		md[a.Name] = a.Metadata
	}
	require.Equal(t, "true", md["ssh"]["ssh_open_to_internet"])
	require.Equal(t, "false", md["ssh"]["shadowed_by_deny"])
	require.Equal(t, "false", md["rdp-blocked"]["rdp_open_to_internet"])
	require.Equal(t, "true", md["rdp-blocked"]["shadowed_by_deny"])
	for _, k := range []string{"ssh_open_to_internet", "rdp_open_to_internet", "shadowed_by_deny"} {
		require.Equal(t, "false", md["deny-rdp"][k], "a deny rule exposes nothing")
	}
}

func TestRangeCovered(t *testing.T) {
	r := []fwRange{{"tcp", 1, 10}, {"tcp", 11, 20}, {"udp", 0, 65535}}
	require.True(t, rangeCovered(r, fwRange{"tcp", 5, 20}))
	require.False(t, rangeCovered(r, fwRange{"tcp", 5, 21}))
	require.True(t, rangeCovered(r, fwRange{"udp", 53, 53}))
	require.False(t, rangeCovered(r, fwRange{"icmp", 0, 65535}))
	require.True(t, rangeCovered([]fwRange{{"all", 0, 65535}}, fwRange{"icmp", 0, 65535}))
	require.False(t, rangeCovered(nil, fwRange{"tcp", 22, 22}))
}
