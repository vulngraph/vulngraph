package checks

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestNSGAllowsWorldPort(t *testing.T) {
	cases := []struct {
		name    string
		ingress string
		want    bool
	}{
		{"world allow on 22", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["*"],"access":"allow","priority":100}]`, true},
		{"Any source", `[{"protocol":"*","from_port":20,"to_port":25,"cidrs":["Any"],"access":"allow","priority":100}]`, true},
		{"private source", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["10.0.0.0/8"],"access":"allow","priority":100}]`, false},
		{"higher-priority deny wins", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["*"],"access":"allow","priority":200},` +
			`{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["Internet"],"destinations":["*"],"access":"deny","priority":100}]`, false},
		{"lower-priority deny is shadowed", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["*"],"access":"allow","priority":100},` +
			`{"protocol":"*","from_port":0,"to_port":65535,"cidrs":["Internet"],"destinations":["*"],"access":"deny","priority":200}]`, true},
		{"legacy allow-only rows", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := asset.Asset{Metadata: map[string]string{"ingress": tc.ingress}}
			require.Equal(t, tc.want, nsgAllowsWorldPort(a, 22))
		})
	}
}

// A Deny is credited against an Allow only where its destination covers the
// Allow's: "Deny Internet to db-subnet:22, Allow Internet to *:22" still
// exposes SSH everywhere but the db subnet.
func TestNSGAllowsWorldPort_DenyMustCoverTheAllowsDestination(t *testing.T) {
	const asg = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/"
	rule := func(access, dst string, priority int) string {
		return `{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["Internet"],` + dst +
			`,"access":"` + access + `","priority":` + strconv.Itoa(priority) + `}`
	}
	cases := []struct {
		name      string
		deny, dst string
		want      bool
	}{
		{"deny on one subnet above allow to everything", `"destinations":["10.0.2.0/24"]`, `"destinations":["*"]`, true},
		{"deny to everything above allow", `"destinations":["*"]`, `"destinations":["10.0.1.0/24"]`, false},
		{"Any deny above allow", `"destinations":["Any"]`, `"destinations":["VirtualNetwork"]`, false},
		{"deny on a wider range", `"destinations":["10.0.0.0/16"]`, `"destinations":["10.0.1.0/24","10.0.3.4"]`, false},
		{"deny ranges that add up to the allow's", `"destinations":["10.0.1.0/25","10.0.1.128/25"]`, `"destinations":["10.0.1.0/24"]`, false},
		{"deny on part of the allow's range", `"destinations":["10.0.1.0/25"]`, `"destinations":["10.0.1.0/24"]`, true},
		{"same service tag", `"destinations":["VirtualNetwork"]`, `"destinations":["virtualnetwork"]`, false},
		{"service tag versus address range", `"destinations":["VirtualNetwork"]`, `"destinations":["10.0.1.0/24"]`, true},
		{"same application security group", `"destination_asgs":["` + asg + `web"]`, `"destination_asgs":["` + asg + `WEB"]`, false},
		{"deny on one of two groups", `"destination_asgs":["` + asg + `web"]`, `"destination_asgs":["` + asg + `web","` + asg + `db"]`, true},
		{"group deny versus address allow", `"destination_asgs":["` + asg + `web"]`, `"destinations":["10.0.1.4"]`, true},
		{"deny with no recorded destination", `"cidrs_only":true`, `"destinations":["*"]`, true},
		{"allow with no recorded destination", `"destinations":["10.0.0.0/8"]`, `"cidrs_only":true`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ingress := "[" + rule("deny", tc.deny, 100) + "," + rule("allow", tc.dst, 200) + "]"
			a := asset.Asset{Metadata: map[string]string{"ingress": ingress}}
			require.Equal(t, tc.want, nsgAllowsWorldPort(a, 22))
		})
	}
}

// A later Allow is still reached when an earlier one is closed by a Deny on
// its own destination.
func TestNSGAllowsWorldPort_LaterAllowStillOpens(t *testing.T) {
	ingress := `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["Internet"],"destinations":["10.0.1.0/24"],"access":"deny","priority":100},` +
		`{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["Internet"],"destinations":["10.0.1.0/24"],"access":"allow","priority":200},` +
		`{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["Internet"],"destinations":["10.0.9.0/24"],"access":"allow","priority":300}]`
	require.True(t, nsgAllowsWorldPort(asset.Asset{Metadata: map[string]string{"ingress": ingress}}, 22))
}
