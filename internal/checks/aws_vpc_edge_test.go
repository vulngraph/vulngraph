package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func naclAsset(entries string, md map[string]string) asset.Asset {
	m := map[string]string{"subnet_association_count": "1", "is_default": "false", "ingress_entries": entries}
	for k, v := range md {
		m[k] = v
	}
	return asset.Asset{ID: "acl-1", Type: "network_acl", Provider: asset.ProviderAWS, Metadata: m}
}

// Rule order is the whole of NACL evaluation: the lowest-numbered matching
// entry decides, so a world deny only shadows an allow it precedes.
func TestNACLWorldOpenAdminPort_RuleOrder(t *testing.T) {
	const star = `{"rule_number":32767,"protocol":"-1","action":"deny","cidr":"0.0.0.0/0","from_port":0,"to_port":65535}`
	tests := []struct {
		name    string
		entries string
		fires   bool
		ports   string
	}{
		{"stock default allow-all opens every admin port",
			`[{"rule_number":100,"protocol":"-1","action":"allow","cidr":"0.0.0.0/0","from_port":0,"to_port":65535},` + star + `]`, true, "22,3389,5985,5986"},
		{"a lower-numbered world deny shadows the allow",
			`[{"rule_number":200,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22},{"rule_number":100,"protocol":"6","action":"deny","cidr":"0.0.0.0/0","from_port":22,"to_port":22},` + star + `]`, false, ""},
		{"a higher-numbered deny does not",
			`[{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22},{"rule_number":200,"protocol":"6","action":"deny","cidr":"0.0.0.0/0","from_port":22,"to_port":22},` + star + `]`, true, "22"},
		{"a narrower deny still lets the rest of the internet in",
			`[{"rule_number":50,"protocol":"6","action":"deny","cidr":"198.51.100.0/24","from_port":22,"to_port":22},{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22},` + star + `]`, true, "22"},
		{"a narrow allow is not world-open",
			`[{"rule_number":100,"protocol":"6","action":"allow","cidr":"203.0.113.0/24","from_port":22,"to_port":22},` + star + `]`, false, ""},
		{"a port range spanning RDP opens it",
			`[{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":3000,"to_port":4000},` + star + `]`, true, "3389"},
		{"UDP on 22 is not SSH",
			`[{"rule_number":100,"protocol":"17","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22},` + star + `]`, false, ""},
		{"IPv6 world allow counts even when IPv4 is denied first",
			`[{"rule_number":90,"protocol":"-1","action":"deny","cidr":"0.0.0.0/0","from_port":0,"to_port":65535},{"rule_number":100,"protocol":"6","action":"allow","cidr":"::/0","from_port":22,"to_port":22}]`, true, "22"},
		{"a deny-all on one family does not close the other",
			`[{"rule_number":90,"protocol":"-1","action":"deny","cidr":"::/0","from_port":0,"to_port":65535},{"rule_number":100,"protocol":"-1","action":"allow","cidr":"::/0","from_port":0,"to_port":65535},{"rule_number":110,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":3389,"to_port":3389}]`, true, "3389"},
		{"only the catch-all is closed", `[` + star + `]`, false, ""},
		{"no entries at all is closed", `[]`, false, ""},
		{"entries out of order are evaluated by rule number",
			`[` + star + `,{"rule_number":200,"protocol":"-1","action":"allow","cidr":"0.0.0.0/0","from_port":0,"to_port":65535},{"rule_number":10,"protocol":"-1","action":"deny","cidr":"0.0.0.0/0","from_port":0,"to_port":65535}]`, false, ""},
		{"two half-internet allows are the world",
			`[{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/1","from_port":22,"to_port":22},{"rule_number":110,"protocol":"6","action":"allow","cidr":"128.0.0.0/1","from_port":22,"to_port":22},` + star + `]`, true, "22"},
		{"a split IPv6 allow is the world too",
			`[{"rule_number":100,"protocol":"-1","action":"allow","cidr":"::/1","from_port":0,"to_port":65535},{"rule_number":110,"protocol":"-1","action":"allow","cidr":"8000::/1","from_port":0,"to_port":65535}]`, true, "22,3389,5985,5986"},
		{"a split deny ahead of the allow closes the port",
			`[{"rule_number":10,"protocol":"6","action":"deny","cidr":"0.0.0.0/1","from_port":22,"to_port":22},{"rule_number":20,"protocol":"6","action":"deny","cidr":"128.0.0.0/1","from_port":22,"to_port":22},{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22},` + star + `]`, false, ""},
		{"half the internet denied first still leaves the other half open",
			`[{"rule_number":10,"protocol":"6","action":"deny","cidr":"0.0.0.0/1","from_port":22,"to_port":22},{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":22,"to_port":22},` + star + `]`, true, "22"},
		{"one half allowed and the rest closed by the catch-all is not world-open",
			`[{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/1","from_port":22,"to_port":22},` + star + `]`, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := naclAsset(tt.entries, nil)
			require.Equal(t, tt.fires, awsNACLWorldOpenAdminPort.Violates(a))
			if tt.fires {
				require.Equal(t, tt.ports, awsNACLWorldOpenAdminPort.EvidenceFor(a)["world_open_ports"])
			}
		})
	}
}

func TestNACLWorldOpenAdminPort_SeverityAndScope(t *testing.T) {
	open := `[{"rule_number":100,"protocol":"-1","action":"allow","cidr":"0.0.0.0/0","from_port":0,"to_port":65535}]`
	grade := func(md map[string]string) finding.Severity {
		return awsNACLWorldOpenAdminPort.SeverityFor(naclAsset(open, md))
	}
	require.Equal(t, finding.SeverityMedium, grade(map[string]string{"filters_public_subnet": "true"}))
	require.Equal(t, finding.SeverityLow, grade(map[string]string{"filters_public_subnet": "false"}))
	require.Equal(t, finding.SeverityMedium, grade(nil), "unknown subnet routing is graded as the worst case, not down")
	require.Equal(t, finding.SeverityInfo, grade(map[string]string{"is_default": "true", "filters_public_subnet": "true"}),
		"the stock default ACL is CIS 6.2's condition but not a choice anyone made")
	require.Equal(t, "22@100,3389@100,5985@100,5986@100", awsNACLWorldOpenAdminPort.EvidenceFor(naclAsset(open, nil))["allowing_rules"])

	require.False(t, awsNACLWorldOpenAdminPort.Violates(naclAsset(open, map[string]string{"subnet_association_count": "0"})),
		"an ACL filtering no subnet is aws-nacl-unused's")
	require.False(t, awsNACLWorldOpenAdminPort.Violates(naclAsset("not json", nil)), "malformed entries are unread, not open")
	require.False(t, awsNACLUnused.Violates(naclAsset(open, map[string]string{"subnet_association_count": "0", "is_default": "true"})),
		"a default ACL cannot be deleted")
}

func TestVPCMissingServiceEndpoints(t *testing.T) {
	a := asset.Asset{Type: "vpc", Provider: asset.ProviderAWS, Metadata: map[string]string{"endpoint_services": ""}}
	require.True(t, awsVPCMissingServiceEndpoints.Violates(a))
	require.Equal(t, "ec2,ecr.api,ecr.dkr,ssm,ssm-contacts,ssm-incidents", awsVPCMissingServiceEndpoints.EvidenceFor(a)["missing_endpoint_services"])
	a.Metadata["endpoint_services"] = "ecr.api,ssm"
	require.Equal(t, "ec2,ecr.dkr,ssm-contacts,ssm-incidents", awsVPCMissingServiceEndpoints.EvidenceFor(a)["missing_endpoint_services"])
}

func TestLaunchPathSeverity(t *testing.T) {
	lt := func(md map[string]string) asset.Asset {
		return asset.Asset{Type: "launch_template", Provider: asset.ProviderAWS, Metadata: md}
	}
	require.Equal(t, finding.SeverityMedium, awsEC2LaunchTemplatePublicIP.SeverityFor(lt(map[string]string{"public_ip_interfaces": "1", "auto_scaling_group_count": "2"})))
	require.Equal(t, finding.SeverityLow, awsEC2LaunchTemplatePublicIP.SeverityFor(lt(map[string]string{"public_ip_interfaces": "1", "auto_scaling_group_count": "0"})))
	require.Equal(t, finding.SeverityLow, awsEC2LaunchTemplatePublicIP.SeverityFor(lt(map[string]string{"public_ip_interfaces": "1"})),
		"an unread usage count never raises the grade")
	require.False(t, awsEC2LaunchTemplateIMDSv1.Violates(lt(map[string]string{"http_tokens": "optional", "http_endpoint": "disabled"})),
		"a disabled metadata endpoint answers nothing")
	lc := asset.Asset{Type: "autoscaling_launch_configuration", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"http_tokens": "optional", "http_endpoint": "disabled"}}
	require.False(t, awsASGLaunchConfigIMDSv1.Violates(lc))
	require.False(t, awsASGNoELBHealthCheck.Violates(asset.Asset{Metadata: map[string]string{"load_balanced": "false", "health_check_type": "EC2"}}),
		"a group behind no load balancer has no ELB check to use")
	require.False(t, awsASGNoELBHealthCheck.Violates(asset.Asset{Metadata: map[string]string{"load_balanced": "true", "health_check_type": "EC2,ELB"}}))
}

// A NACL check that cannot see its entries must hold an open finding rather
// than close it as fixed.
func TestNACLCheckNotEvaluableWithoutEntries(t *testing.T) {
	c, ok := Default().ByID("aws-nacl-world-open-admin-port")
	require.True(t, ok)
	require.False(t, c.Evaluable(asset.Asset{Type: "network_acl", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"subnet_association_count": "1"}}))
}

// The security-group world-open checks share ruleWorldOpen, so a rule whose
// ranges add up to the internet is world-open there too.
func TestSGSplitWorldRangeIsWorldOpen(t *testing.T) {
	sg := asset.Asset{Type: "security_group", Provider: asset.ProviderAWS, Metadata: map[string]string{
		"ingress": `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/1","128.0.0.0/1"]}]`}}
	require.True(t, awsSGWorldOpenAdminPort.Violates(sg))
	sg.Metadata["ingress"] = `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/1"]}]`
	require.False(t, awsSGWorldOpenAdminPort.Violates(sg))
}
