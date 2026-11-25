package checks

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func sgWith(ingress, egress string) asset.Asset {
	md := map[string]string{}
	if ingress != "" {
		md["ingress"] = ingress
	}
	if egress != "" {
		md["egress"] = egress
	}
	return asset.Asset{ID: "sg-1", Name: "g", Type: "security_group", Provider: asset.ProviderAWS, Metadata: md}
}

func TestCIDRIsGlobal(t *testing.T) {
	tests := map[string]bool{
		"8.8.8.8/32": true, "52.0.0.0/8": true, "0.0.0.0/4": true, "128.0.0.0/1": true,
		"10.0.0.0/8": false, "10.1.0.0/16": false, "172.16.0.0/12": false, "172.32.0.0/16": true,
		"192.168.1.0/24": false, "100.64.0.0/10": false, "127.0.0.1/32": false, "169.254.0.0/16": false,
		"198.51.100.0/24": false, "2001:4860::/32": true, "fd00::/8": false, "fe80::/10": false,
		"2001:db8::/32": false, "2001:20::/28": true, "not-a-cidr": false,
	}
	for c, want := range tests {
		require.Equal(t, want, cidrIsGlobal(c), c)
	}
}

func TestSGSpecificPublicSource(t *testing.T) {
	tests := []struct {
		name    string
		ingress string
		want    bool
	}{
		{"single public address", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["203.1.2.3/32"]}]`, true},
		{"private only", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["10.0.0.0/8"]}]`, false},
		{"world only is another check", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`, false},
		{"world plus a private range", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0","10.0.0.0/8"]}]`, false},
		{"world plus a specific public address", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0","8.8.8.8/32"]}]`, true},
		{"all ports from world is skipped", `[{"protocol":"-1","cidrs":["0.0.0.0/0","203.1.2.3/32"]}]`, false},
		{"public ipv6 range", `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["2001:4860::/32"]}]`, true},
		{"security group source only", `[{"protocol":"tcp","from_port":22,"to_port":22,"sg_refs":["sg-2"]}]`, false},
		{"no rules observed", ``, false},
		{"unreadable rules", `not json`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, awsSGSpecificPublicSource.Violates(sgWith(tt.ingress, "")))
		})
	}
}

func TestSGWidePublicIPv4(t *testing.T) {
	rule := func(c string) string { return `[{"protocol":"tcp","from_port":1,"to_port":2,"cidrs":["` + c + `"]}]` }
	tests := []struct {
		name            string
		ingress, egress string
		want            bool
	}{
		{"ingress /16 public", rule("52.1.0.0/16"), "", true},
		{"egress /8 public", "", rule("52.0.0.0/8"), true},
		{"/23 is wide", rule("52.1.0.0/23"), "", true},
		{"/24 is not", rule("52.1.1.0/24"), "", false},
		{"world is not", rule("0.0.0.0/0"), "", false},
		{"private /8 is not", rule("10.0.0.0/8"), "", false},
		{"public ipv6 is out of scope", rule("2001:4860::/32"), "", false},
		{"nothing observed", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sgWith(tt.ingress, tt.egress)
			require.Equal(t, tt.want, awsSGWidePublicIPv4.Violates(a))
		})
	}
	ev := awsSGWidePublicIPv4.EvidenceFor(sgWith(rule("52.1.0.0/16"), rule("52.0.0.0/8")))
	require.Equal(t, "52.1.0.0/16", ev["ingress_ranges"])
	require.Equal(t, "52.0.0.0/8", ev["egress_ranges"])
}

func TestNACLAllowsAllTraffic(t *testing.T) {
	allow := func(n int, cidr string) string {
		return `{"rule_number":` + strconv.Itoa(n) + `,"protocol":"-1","action":"allow","cidr":"` + cidr + `","from_port":0,"to_port":65535}`
	}
	deny := func(n int, cidr string) string {
		return `{"rule_number":` + strconv.Itoa(n) + `,"protocol":"-1","action":"deny","cidr":"` + cidr + `","from_port":0,"to_port":65535}`
	}
	tcp := `{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22}`
	tests := []struct {
		name    string
		entries string
		want    bool
	}{
		{"default allow all", `[` + allow(100, "0.0.0.0/0") + `,` + deny(32767, "0.0.0.0/0") + `]`, true},
		{"ipv6 allow all", `[` + allow(100, "::/0") + `]`, true},
		{"lower deny closes ipv4", `[` + allow(100, "0.0.0.0/0") + `,` + deny(50, "0.0.0.0/0") + `]`, false},
		{"ipv6 deny does not close ipv4", `[` + deny(50, "::/0") + `,` + allow(100, "0.0.0.0/0") + `]`, true},
		{"ipv4 deny does not close ipv6", `[` + deny(50, "0.0.0.0/0") + `,` + allow(100, "::/0") + `]`, true},
		{"single port allow", `[` + tcp + `]`, false},
		{"narrow allow", `[` + allow(100, "10.0.0.0/8") + `]`, false},
		{"only catch-all", `[` + deny(32767, "0.0.0.0/0") + `]`, false},
		{"no entries", `[]`, false},
		{"unreadable entries", `not json`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := naclAsset(tt.entries, nil)
			require.Equal(t, tt.want, awsNACLAllowsAllTraffic.Violates(a))
		})
	}
	absent := asset.Asset{Type: "network_acl", Provider: asset.ProviderAWS, Metadata: map[string]string{}}
	require.False(t, awsNACLAllowsAllTraffic.Violates(absent))
	open := `[` + allow(100, "0.0.0.0/0") + `]`
	require.Equal(t, finding.SeverityInfo, awsNACLAllowsAllTraffic.SeverityFor(naclAsset(open, map[string]string{"is_default": "true"})))
	require.Equal(t, finding.SeverityMedium, awsNACLAllowsAllTraffic.SeverityFor(naclAsset(open, nil)))
}
