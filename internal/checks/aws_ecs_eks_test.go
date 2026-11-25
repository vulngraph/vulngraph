package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsAsset(typ string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "x", Type: typ, Provider: asset.ProviderAWS, Metadata: md}
}

func TestECSContainerRunsAsRootTiers(t *testing.T) {
	tests := []struct {
		user  string
		fires bool
		sev   finding.Severity
	}{
		{"root", true, finding.SeverityMedium},
		{"0:0", true, finding.SeverityMedium},
		{"root:wheel", true, finding.SeverityMedium},
		{"ContainerAdministrator", true, finding.SeverityMedium},
		{"", true, finding.SeverityLow},
		{"1000", false, ""},
		{"app:app", false, ""},
		{"ContainerUser", false, ""},
	}
	for _, tt := range tests {
		a := awsAsset("container", map[string]string{"user": tt.user})
		require.Equal(t, tt.fires, awsECSContainerRunsAsRoot.Violates(a), tt.user)
		if tt.fires {
			require.Equal(t, tt.sev, awsECSContainerRunsAsRoot.SeverityFor(a), tt.user)
		}
	}
}

func TestECSPlaintextSecretEnvSeverity(t *testing.T) {
	aws := awsAsset("container", map[string]string{"plaintext_secret_env": "AWS_SECRET_ACCESS_KEY,DB_PASSWORD"})
	require.True(t, awsECSContainerPlaintextSecretEnv.Violates(aws))
	require.Equal(t, finding.SeverityHigh, awsECSContainerPlaintextSecretEnv.SeverityFor(aws))
	other := awsAsset("container", map[string]string{"plaintext_secret_env": "DB_PASSWORD"})
	require.Equal(t, finding.SeverityMedium, awsECSContainerPlaintextSecretEnv.SeverityFor(other))
	require.False(t, awsECSContainerPlaintextSecretEnv.Violates(awsAsset("container", map[string]string{"plaintext_secret_env": ""})))
}

func TestECSTaskSharesHostNamespace(t *testing.T) {
	require.True(t, awsECSTaskSharesHostNamespace.Violates(awsAsset("ecs_service", map[string]string{"pid_mode": "host", "network_mode": "awsvpc"})))
	require.True(t, awsECSTaskSharesHostNamespace.Violates(awsAsset("ecs_service", map[string]string{"pid_mode": "", "network_mode": "host"})))
	require.False(t, awsECSTaskSharesHostNamespace.Violates(awsAsset("ecs_service", map[string]string{"pid_mode": "task", "network_mode": "bridge"})))
}

func TestECSFargateOldPlatform(t *testing.T) {
	tests := []struct {
		launch, pv, os string
		fires          bool
	}{
		{"FARGATE", "1.3.0", "LINUX", true},
		{"FARGATE", "1.4.0", "", false},
		{"FARGATE", "LATEST", "", false},
		{"FARGATE", "1.0.0", "WINDOWS_SERVER_2022_CORE", false},
		{"FARGATE", "1.4.0", "WINDOWS_SERVER_2019_FULL", true},
		{"EC2", "1.3.0", "", false},
		{"FARGATE", "", "", false},
	}
	for _, tt := range tests {
		a := awsAsset("ecs_service", map[string]string{"launch_type": tt.launch, "platform_version": tt.pv, "os_family": tt.os})
		require.Equal(t, tt.fires, awsECSFargateOldPlatform.Violates(a), "%+v", tt)
	}
}

func TestLambdaDeprecatedRuntimeTable(t *testing.T) {
	now := time.Now()
	for rt, d := range lambdaRuntimeDeprecation {
		a := awsAsset("lambda_function", map[string]string{"runtime": rt})
		require.Equal(t, !now.Before(d), awsLambdaDeprecatedRuntime.Violates(a), rt)
	}
	// Runtimes the old hard-coded list missed are now graded by date.
	for _, rt := range []string{"nodejs16.x", "nodejs18.x", "python3.8", "python3.9", "ruby2.7", "dotnet6", "provided"} {
		require.True(t, awsLambdaDeprecatedRuntime.Violates(awsAsset("lambda_function", map[string]string{"runtime": rt})), rt)
	}
	for _, rt := range []string{"python3.13", "nodejs24.x", "java21", "", "nodejs26.x"} {
		require.False(t, awsLambdaDeprecatedRuntime.Violates(awsAsset("lambda_function", map[string]string{"runtime": rt})), rt)
	}
	pub := awsAsset("lambda_function", map[string]string{"runtime": "python3.8", "public": "true"})
	require.Equal(t, finding.SeverityHigh, awsLambdaDeprecatedRuntime.SeverityFor(pub))
	priv := awsAsset("lambda_function", map[string]string{"runtime": "python3.8", "public": "false"})
	require.Equal(t, finding.SeverityMedium, awsLambdaDeprecatedRuntime.SeverityFor(priv))
	require.Equal(t, "2024-10-14", awsLambdaDeprecatedRuntime.EvidenceFor(priv)["deprecation_date"])
	require.False(t, registered(t, awsLambdaDeprecatedRuntime.ID).Evaluable(awsAsset("lambda_function", map[string]string{})),
		"an unread runtime could be a deprecated one")
}

func TestEKSSupportPhase(t *testing.T) {
	at := func(s string) time.Time { return day(s) }
	tests := []struct {
		version, now, want string
	}{
		{"1.31", "2025-11-25", "standard"},
		{"1.31", "2025-11-26", "extended"},
		{"1.31", "2026-11-26", "ended"},
		{"1.37", "2026-10-09", "standard"},
		{"1.30", "2026-10-09", "ended"}, // older than the calendar
		{"1.24", "2026-10-09", "ended"},
		{"1.38", "2026-10-09", ""}, // newer than the calendar: unknown
		{"1.33.4", "2026-10-09", "extended"},
		{"", "2026-10-09", ""},
		{"2.0", "2026-10-09", ""},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, eksSupportPhase(tt.version, at(tt.now)), "%s @ %s", tt.version, tt.now)
	}
}

func TestEKSUnsupportedVersionSeverity(t *testing.T) {
	ended := awsAsset("eks_cluster", map[string]string{"version": "1.25"})
	require.True(t, awsEKSUnsupportedVersion.Violates(ended))
	require.Equal(t, finding.SeverityHigh, awsEKSUnsupportedVersion.SeverityFor(ended))
	require.False(t, awsEKSUnsupportedVersion.Violates(awsAsset("eks_cluster", map[string]string{"version": "1.37"})))
	require.False(t, registered(t, awsEKSUnsupportedVersion.ID).Evaluable(awsAsset("eks_cluster", map[string]string{})))
}

// A malformed date literal panics at package init (day), so reaching this test
// already proves the tables parse; this pins the calendar's shape.
func TestLifecycleTablesParse(t *testing.T) {
	for k, v := range eksVersionCalendar {
		_, ok := eksMinor(k)
		require.True(t, ok, k)
		require.True(t, v.standardEnd.Before(v.extendedEnd), k)
	}
}

// FSBP ECS.5 does not apply to Windows containers, which cannot run with a
// read-only root file system.
func TestECSWritableRootFSSkipsWindows(t *testing.T) {
	require.True(t, awsECSContainerWritableRootFS.Violates(awsAsset("container", map[string]string{"readonly_root_fs": "false", "os_family": "LINUX"})))
	require.True(t, awsECSContainerWritableRootFS.Violates(awsAsset("container", map[string]string{"readonly_root_fs": "false"})))
	require.False(t, awsECSContainerWritableRootFS.Violates(awsAsset("container", map[string]string{"readonly_root_fs": "false", "os_family": "WINDOWS_SERVER_2022_CORE"})))
}

func TestECSPlaintextSecretEnvIsNotAnExposure(t *testing.T) {
	require.NotEqual(t, "exposure", awsECSContainerPlaintextSecretEnv.Type, "enrichment reads exposure as an internet-facing asset")
}
