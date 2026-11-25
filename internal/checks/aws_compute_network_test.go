package checks

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func sgAsset(name, ingress string) asset.Asset {
	md := map[string]string{}
	if ingress != "" {
		md["ingress"] = ingress
	}
	return asset.Asset{ID: "sg-1", Name: name, Type: "security_group", Provider: asset.ProviderAWS, Metadata: md}
}

// The admin and database lists are subsets of the one high-risk list, so a
// port is "high risk" in exactly one place and the residual check cannot
// double-report a port a dedicated check owns.
func TestHighRiskPortsCoverSubsets(t *testing.T) {
	for _, p := range append(append([]int32{}, adminPorts...), databasePorts...) {
		require.True(t, slices.Contains(highRiskPorts, p), "port %d must be in highRiskPorts", p)
	}
	for _, p := range residualHighRiskPorts() {
		require.False(t, slices.Contains(adminPorts, p) || slices.Contains(databasePorts, p))
	}
	// FSBP EC2.19 critical ports plus CIS 6.1.2 CIFS and Redshift.
	for _, p := range []int32{20, 21, 22, 23, 25, 110, 135, 139, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333, 5000, 5432, 5439, 5500, 5601, 8080, 8088, 8888, 9200, 9300} {
		require.True(t, slices.Contains(highRiskPorts, p), "port %d", p)
	}
}

// Exactly one of the world-open port checks fires per group: the one naming
// the most specific exposure.
func TestSGWorldOpenChecksFireOncePerGroup(t *testing.T) {
	checks := []Check{awsSGOpenAllPorts, awsSGWorldOpenAdminPort, awsSGOpenDatabasePorts, awsSGOpenHighRiskPorts, awsSGOpenUnauthorizedPort}
	tests := []struct {
		name    string
		ingress string
		want    string // "" = nothing fires
	}{
		{"cifs 445 ipv4", `[{"protocol":"tcp","from_port":445,"to_port":445,"cidrs":["0.0.0.0/0"]}]`, "aws-sg-open-high-risk-ports"},
		{"netbios 139 ipv6", `[{"protocol":"tcp","from_port":139,"to_port":139,"cidrs":["::/0"]}]`, "aws-sg-open-high-risk-ports"},
		{"redshift", `[{"protocol":"tcp","from_port":5439,"to_port":5439,"cidrs":["0.0.0.0/0"]}]`, "aws-sg-open-high-risk-ports"},
		// Port-specific checks report their own ports independently, as the admin and
		// database checks always have: a range spanning SSH and Telnet is two services.
		{"range spanning telnet and ssh", `[{"protocol":"tcp","from_port":20,"to_port":23,"cidrs":["0.0.0.0/0"]}]`, "aws-security-group-world-open-admin-port,aws-sg-open-high-risk-ports"},
		{"ssh is the admin check", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`, "aws-security-group-world-open-admin-port"},
		{"mysql is the database check", `[{"protocol":"tcp","from_port":3306,"to_port":3306,"cidrs":["0.0.0.0/0"]}]`, "aws-sg-open-database-ports"},
		{"all traffic", `[{"protocol":"-1","from_port":0,"to_port":0,"cidrs":["0.0.0.0/0"]}]`, "aws-sg-open-all-ports"},
		{"8443 unauthorized", `[{"protocol":"tcp","from_port":8443,"to_port":8443,"cidrs":["0.0.0.0/0"]}]`, "aws-sg-open-unauthorized-port"},
		{"web only", `[{"protocol":"tcp","from_port":80,"to_port":80,"cidrs":["0.0.0.0/0"]},{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["::/0"]}]`, ""},
		{"445 from a private range", `[{"protocol":"tcp","from_port":445,"to_port":445,"cidrs":["10.0.0.0/8"]}]`, ""},
		// ICMP reuses the port fields for type/code: echo-request (type 8) is not port 8 and must not read as 0-65535.
		{"icmp is not a port range", `[{"protocol":"icmp","from_port":3,"to_port":4,"cidrs":["0.0.0.0/0"]}]`, ""},
		// ICMP type/code values that happen to span high-risk "ports" must not fire either check.
		{"icmp spanning high-risk numbers", `[{"protocol":"icmp","from_port":20,"to_port":445,"cidrs":["0.0.0.0/0"]}]`, ""},
		// Per-port step-aside: SSH goes to the admin check, 9000 still to the unauthorized one.
		{"ssh and 9000", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]},{"protocol":"tcp","from_port":9000,"to_port":9000,"cidrs":["0.0.0.0/0"]}]`, "aws-security-group-world-open-admin-port,aws-sg-open-unauthorized-port"},
		// No UDP port is authorized (FSBP EC2.18 default).
		{"udp dns", `[{"protocol":"udp","from_port":53,"to_port":53,"cidrs":["::/0"]}]`, "aws-sg-open-unauthorized-port"},
		{"udp openvpn numeric protocol", `[{"protocol":"17","from_port":1194,"to_port":1194,"cidrs":["0.0.0.0/0"]}]`, "aws-sg-open-unauthorized-port"},
		{"udp high-risk port", `[{"protocol":"udp","from_port":135,"to_port":135,"cidrs":["0.0.0.0/0"]}]`, "aws-sg-open-high-risk-ports"},
		{"no rules", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := sgAsset("app", tt.ingress)
			var fired []string
			for _, c := range checks {
				if c.Violates(a) {
					fired = append(fired, c.ID)
				}
			}
			if tt.want == "" {
				require.Empty(t, fired)
				return
			}
			require.Equal(t, strings.Split(tt.want, ","), fired)
		})
	}
}

func TestSGOpenHighRiskPortsEvidence(t *testing.T) {
	a := sgAsset("app", `[{"protocol":"tcp","from_port":20,"to_port":445,"cidrs":["0.0.0.0/0"]}]`)
	// 22 is the admin check's; the residual list excludes it.
	require.Equal(t, "20,21,23,25,110,135,139,143,445", awsSGOpenHighRiskPorts.EvidenceFor(a)["world_open_ports"])
}

func TestSGDefaultAllowsTraffic(t *testing.T) {
	build := func(name string, md map[string]string) asset.Asset {
		return asset.Asset{Name: name, Type: "security_group", Provider: asset.ProviderAWS, Metadata: md}
	}
	require.True(t, awsSGDefaultAllowsTraffic.Violates(build("default", map[string]string{"ingress_rules": "1", "egress_rules": "0"})))
	require.True(t, awsSGDefaultAllowsTraffic.Violates(build("default", map[string]string{"ingress_rules": "0", "egress_rules": "1"})))
	require.False(t, awsSGDefaultAllowsTraffic.Violates(build("default", map[string]string{"ingress_rules": "0", "egress_rules": "0"})))
	require.False(t, awsSGDefaultAllowsTraffic.Violates(build("web", map[string]string{"ingress_rules": "3", "egress_rules": "1"})))
	// Absent counts (a sweep before the collector wrote them) are unknown: silent,
	// and not evaluable, so an open finding is not closed as fixed.
	unread := build("default", map[string]string{})
	require.False(t, awsSGDefaultAllowsTraffic.Violates(unread))
	require.False(t, registered(t, awsSGDefaultAllowsTraffic.ID).Evaluable(unread))
}

func TestEC2StoppedLong(t *testing.T) {
	build := func(state, at string) asset.Asset {
		return asset.Asset{Type: "ec2_instance", Provider: asset.ProviderAWS, Metadata: map[string]string{"state": state, "stopped_at": at}}
	}
	old := time.Now().Add(-31 * 24 * time.Hour).UTC().Format(time.RFC3339)
	recent := time.Now().Add(-29 * 24 * time.Hour).UTC().Format(time.RFC3339)
	require.True(t, awsEC2StoppedLong.Violates(build("stopped", old)))
	require.False(t, awsEC2StoppedLong.Violates(build("stopped", recent)))
	require.False(t, awsEC2StoppedLong.Violates(build("running", old)), "only a currently stopped instance")
}

func TestEC2MultipleENIsExemptsKubernetesNodes(t *testing.T) {
	md := map[string]string{"eni_count": "3"}
	require.True(t, awsEC2MultipleENIs.Violates(asset.Asset{Metadata: md}))
	md["k8s_node"] = "true"
	require.False(t, awsEC2MultipleENIs.Violates(asset.Asset{Metadata: md}))
}

// A disabled metadata endpoint answers nothing, so optional tokens on it are
// not an IMDSv1 exposure (CIS 6.7 / FSBP EC2.8).
func TestIMDSChecksExemptDisabledEndpoint(t *testing.T) {
	plain := map[string]string{"http_tokens": "optional", "http_endpoint": "disabled"}
	require.False(t, awsEC2IMDSv2NotRequired.Violates(asset.Asset{Metadata: plain}))
	node := map[string]string{"http_tokens": "optional", "http_endpoint": "disabled", "k8s_node": "true", "iam_role_ecr_push": "true"}
	require.False(t, eksNodeIMDSv1RegistryWrite.Violates(asset.Asset{Metadata: node}))
	node["http_endpoint"] = "enabled"
	require.True(t, eksNodeIMDSv1RegistryWrite.Violates(asset.Asset{Metadata: node}))
	require.True(t, awsEC2IMDSv2NotRequired.Violates(asset.Asset{Metadata: map[string]string{"http_tokens": "optional", "http_endpoint": "enabled"}}))
}

// The description names every port the check fires on.
func TestSGOpenDatabasePortsDescriptionNamesEveryPort(t *testing.T) {
	for _, p := range databasePorts {
		require.Contains(t, awsSGOpenDatabasePorts.Description, " "+strconv.Itoa(int(p)))
	}
	require.Contains(t, awsSGOpenDatabasePorts.Description, "Elasticsearch 9200")
	require.Contains(t, awsSGOpenDatabasePorts.Description, "CouchDB 5984")
}
