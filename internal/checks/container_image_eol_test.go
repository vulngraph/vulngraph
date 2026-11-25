package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func eolImage(baseOS, exposed string) asset.Asset {
	md := map[string]string{asset.MetaBaseImageSource: "os_release"}
	if baseOS != "" {
		md[asset.MetaBaseOS] = baseOS
	}
	if exposed != "" {
		md[asset.MetaWorkloadExposed] = exposed
	}
	return asset.Asset{ID: "image/sha256:abc", Name: "registry.example/app", Type: "container_image",
		Provider: asset.ProviderKubernetes, Metadata: md}
}

func TestContainerImageOSEndOfLife(t *testing.T) {
	tests := []struct {
		baseOS string
		fires  bool
	}{
		{"Debian:10", true},
		{"Debian:11", true}, // LTS ended 2026-08-31
		{"Alpine:v3.18", true},
		{"Ubuntu:20.04:LTS", true},
		{"CentOS:7", true},
		{"Amazon Linux:2", true},
		{"openSUSE:Leap 15.5", true},
		{"Debian:13", false},
		{"Alpine:v3.22", false},
		{"Ubuntu:24.04:LTS", false},
		{"Red Hat:9", false},
		// Unknown is never a finding.
		{"openSUSE:Tumbleweed", false},
		{"Alpine", false},
		{"", false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.fires, containerImageOSEndOfLife.Violates(eolImage(tt.baseOS, "false")), tt.baseOS)
	}
}

func TestContainerImageOSEndOfLife_SeverityFollowsWorkloadExposure(t *testing.T) {
	require.Equal(t, finding.SeverityHigh, containerImageOSEndOfLife.SeverityFor(eolImage("Debian:10", "true")))
	require.Equal(t, finding.SeverityMedium, containerImageOSEndOfLife.SeverityFor(eolImage("Debian:10", "false")))
}

func TestContainerImageOSEndOfLife_EvaluateIgnoresProvider(t *testing.T) {
	img := eolImage("Debian:10", "true")
	img.Provider = asset.ProviderAWS // an ECS task's image
	f, ok := containerImageOSEndOfLife.Evaluate(img, time.Now())
	require.True(t, ok)
	require.Equal(t, "container-image-os-end-of-life", f.CheckID)
	require.Equal(t, "image/sha256:abc", f.ResourceID)
	require.Equal(t, "container_image", f.ResourceType)
	require.Equal(t, finding.SeverityHigh, f.Severity)
	require.Equal(t, "Debian:10", f.Metadata["os_release"])
	require.Equal(t, "2024-06-30", f.Metadata["end_of_life"])
	require.Equal(t, "true", f.Metadata["final"])
	require.Equal(t, "os_release", f.Metadata[asset.MetaBaseImageSource])
}

// The registry the base-image job evaluates carries the derived evidence key,
// and an image whose base was never identified is not evaluable: its silence
// is not a remediation.
func TestContainerImageChecks_AbsentBaseIsNotEvaluable(t *testing.T) {
	c, ok := ContainerImageChecks().ByID("container-image-os-end-of-life")
	require.True(t, ok)
	require.Equal(t, []string{asset.MetaBaseOS}, c.RequiredKeys)
	require.False(t, c.Evaluable(eolImage("", "false")), "no base_os: not evaluated")
	require.True(t, c.Evaluable(eolImage("Debian:13", "false")), "known and supported: evaluated clean")

	_, inDefault := Default().ByID("container-image-os-end-of-life")
	require.False(t, inDefault, "the sync-time run never sees base_os; registering it there makes a permanently blind check")
}
