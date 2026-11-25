package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func eolVM(eco, publicIP string) asset.Asset {
	md := map[string]string{}
	if eco != "" {
		md[asset.MetaPackageEcosystem] = eco
	}
	return asset.Asset{ID: "i-1", Type: "ec2_instance", Provider: asset.ProviderAWS, PublicIP: publicIP, Metadata: md}
}

func TestVMOSEndOfLife(t *testing.T) {
	tests := []struct {
		eco   string
		fires bool
	}{
		{"CentOS:7", true},
		{"CentOS:8", true},
		{"Amazon Linux:1", true},
		{"Amazon Linux:2", true}, // ended 2026-06-30
		{"Red Hat:7", true},
		{"Ubuntu:18.04:LTS", true},
		{"Ubuntu:20.04:LTS", true},
		{"Debian:10", true},
		{"Amazon Linux:2023", false},
		{"Red Hat:9", false},
		{"Ubuntu:24.04:LTS", false},
		{"SUSE:15.5", true}, // general support ended 2024-12-31; LTSS is paid
		{"SUSE:15.7", false},
		// Unlisted is unknown, never a finding.
		{"openSUSE:Tumbleweed", false},
		{"", false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.fires, awsEC2OSEndOfLife.Violates(eolVM(tt.eco, "")), tt.eco)
	}
}

func TestVMOSEndOfLife_SeverityFollowsExposure(t *testing.T) {
	require.Equal(t, finding.SeverityHigh, awsEC2OSEndOfLife.SeverityFor(eolVM("CentOS:7", "203.0.113.7")))
	require.Equal(t, finding.SeverityMedium, awsEC2OSEndOfLife.SeverityFor(eolVM("CentOS:7", "")))
}

func TestVMOSEndOfLife_Evidence(t *testing.T) {
	ev := awsEC2OSEndOfLife.EvidenceFor(eolVM("Red Hat:7", ""))
	require.Equal(t, "Red Hat:7", ev["os_release"])
	require.Equal(t, "2024-06-30", ev["end_of_life"])
	require.Equal(t, "false", ev["final"], "RHEL 7 has a paid extended tier")
	require.NotEmpty(t, ev["support_note"])
}

// A VM whose inventory disappeared carries no package_ecosystem. The check's
// silence then proves nothing: the lifecycle table's coordinates are probed, so
// an open end-of-life finding is not closed as fixed for want of data.
func TestVMOSEndOfLife_AbsentEcosystemIsNotEvaluable(t *testing.T) {
	c, ok := Default().ByID("aws-ec2-os-end-of-life")
	require.True(t, ok)
	require.Equal(t, []string{asset.MetaPackageEcosystem}, c.RequiredKeys)
	require.False(t, c.Evaluable(eolVM("", "")), "no inventory: not evaluated")
	require.True(t, c.Evaluable(eolVM("Amazon Linux:2023", "")), "observed and supported: evaluated clean")

	g, ok := Default().ByID("gcp-gce-os-end-of-life")
	require.True(t, ok)
	require.False(t, g.Evaluable(asset.Asset{Type: "gce_instance", Provider: asset.ProviderGCP}))
}
