package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestECSTaskDefinitionRunsAsRootTiers(t *testing.T) {
	root := awsAsset("ecs_task_definition", map[string]string{"root_user_containers": "job", "unset_user_containers": "noop"})
	require.True(t, awsECSTaskDefRunsAsRoot.Violates(root))
	require.Equal(t, finding.SeverityMedium, awsECSTaskDefRunsAsRoot.SeverityFor(root))
	unset := awsAsset("ecs_task_definition", map[string]string{"root_user_containers": "", "unset_user_containers": "noop"})
	require.True(t, awsECSTaskDefRunsAsRoot.Violates(unset))
	require.Equal(t, finding.SeverityLow, awsECSTaskDefRunsAsRoot.SeverityFor(unset))
}

func TestECSTaskDefinitionMirrorsContainerChecks(t *testing.T) {
	// Windows task definitions cannot use a read-only root file system.
	win := awsAsset("ecs_task_definition", map[string]string{"writable_root_fs_containers": "iis", "os_family": "WINDOWS_SERVER_2022_CORE"})
	require.False(t, awsECSTaskDefWritableRootFS.Violates(win))
	// A static AWS credential is High, as on the container check.
	aws := awsAsset("ecs_task_definition", map[string]string{"plaintext_secret_env": "AWS_ACCESS_KEY_ID"})
	require.Equal(t, finding.SeverityHigh, awsECSTaskDefPlaintextSecretEnv.SeverityFor(aws))
	other := awsAsset("ecs_task_definition", map[string]string{"plaintext_secret_env": "DB_PASSWORD"})
	require.Equal(t, finding.SeverityMedium, awsECSTaskDefPlaintextSecretEnv.SeverityFor(other))
	require.True(t, awsECSTaskDefSharesHostNamespace.Violates(awsAsset("ecs_task_definition", map[string]string{"network_mode": "host"})))
}

// One public exposure, one finding: a service whose own configuration assigns
// public IPs is the service check's finding, not the task-set check's too.
func TestECSTaskSetPublicIPStepsAsideForService(t *testing.T) {
	both := awsAsset("ecs_service", map[string]string{"task_sets_public_ip": "ecs-svc/1", "assign_public_ip": "ENABLED"})
	require.True(t, awsECSServicePublicIP.Violates(both))
	require.False(t, awsECSTaskSetPublicIP.Violates(both))
	external := awsAsset("ecs_service", map[string]string{"task_sets_public_ip": "ecs-svc/1", "assign_public_ip": ""})
	require.True(t, awsECSTaskSetPublicIP.Violates(external))
}

func TestECSFargateCapacityProviderStrategy(t *testing.T) {
	a := awsAsset("ecs_service", map[string]string{"launch_type": "", "capacity_provider_fargate": "true", "platform_version": "1.3.0"})
	require.True(t, awsECSFargateOldPlatform.Violates(a))
	a.Metadata["capacity_provider_fargate"] = "false"
	require.False(t, awsECSFargateOldPlatform.Violates(a), "an EC2 capacity provider has no Fargate platform")
}

// The restricted-endpoint check and the world-open one split EKS.1 between
// them: never both on one cluster.
func TestEKSPublicEndpointPairFiresOnce(t *testing.T) {
	tests := []struct {
		public, cidrs     string
		world, restricted bool
	}{
		{"true", "0.0.0.0/0", true, false},
		{"true", "10.0.0.0/8,::/0", true, false},
		{"true", "203.0.113.0/24", false, true},
		{"false", "0.0.0.0/0", false, false},
		{"false", "203.0.113.0/24", false, false},
	}
	for _, tt := range tests {
		a := awsAsset("eks_cluster", map[string]string{"endpoint_public_access": tt.public, "public_access_cidrs": tt.cidrs})
		require.Equal(t, tt.world, awsEKSPublicEndpoint.Violates(a), "%+v", tt)
		require.Equal(t, tt.restricted, awsEKSPublicEndpointRestricted.Violates(a), "%+v", tt)
	}
}

func TestEKSNodegroupUnsupportedVersionStepsAsideForCluster(t *testing.T) {
	now := time.Now()
	var current, past string
	for _, k := range eksCalendarKeys() {
		switch eksSupportPhase(k, now) {
		case "standard":
			if current == "" {
				current = k
			}
		case "extended", "ended":
			past = k
		}
	}
	// The check grades against the wall clock too, so a calendar with nothing in
	// standard support today is stale data for the check itself, not a reason
	// to skip.
	require.NotEmpty(t, current, "eksVersionCalendar (aws_lifecycle.go) has no version in standard support today: add the current EKS releases")
	tests := []struct {
		node, cluster string
		fires         bool
	}{
		{"1.20", current, true},   // lagging node group on a supported control plane
		{"1.20", "1.20", false},   // the cluster's own finding covers the upgrade
		{"1.20", "", true},        // cluster version unknown/unlisted: graded on its own
		{current, current, false}, // supported
		{"", current, false},      // node version unknown
	}
	if past != "" {
		tests = append(tests, struct {
			node, cluster string
			fires         bool
		}{past, past, false})
	}
	for _, tt := range tests {
		md := map[string]string{"version": tt.node, "cluster_version": tt.cluster}
		a := awsAsset("eks_nodegroup", md)
		require.Equal(t, tt.fires, awsEKSNodegroupUnsupportedVersion.Violates(a), "%+v", tt)
		if tt.fires {
			require.Equal(t, finding.SeverityHigh, awsEKSNodegroupUnsupportedVersion.SeverityFor(a), "1.20 is past all support")
		}
	}
}

func TestSecretRotationOverdueByNextRotationDate(t *testing.T) {
	ago := func(d int) string {
		return time.Now().Add(-time.Duration(d) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}
	ahead := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	tests := []struct {
		name  string
		md    map[string]string
		fires bool
	}{
		{"cron schedule, next date long passed", map[string]string{"rotation_enabled": "true", "next_rotation": ago(10), "last_rotated": ago(40)}, true},
		{"cron schedule, inside the grace day", map[string]string{"rotation_enabled": "true", "next_rotation": ago(1), "last_rotated": ago(8)}, false},
		{"cron schedule, next date ahead", map[string]string{"rotation_enabled": "true", "next_rotation": ahead, "last_rotated": ago(5)}, false},
		{"no rotation scheduled, interval unknown", map[string]string{"rotation_enabled": "true", "next_rotation": "", "last_rotated": ago(400)}, false},
		{"rotation off", map[string]string{"rotation_enabled": "false", "next_rotation": ago(10)}, false},
		{"interval leg still fires", map[string]string{"rotation_enabled": "true", "next_rotation": ahead, "rotation_interval_days": "30", "last_rotated": ago(45)}, true},
	}
	for _, tt := range tests {
		require.Equal(t, tt.fires, awsSecretRotationOverdue.Violates(awsAsset("secretsmanager_secret", tt.md)), tt.name)
	}
	// The 90-day check steps aside for an overdue secret, whichever leg fired.
	overdue := awsAsset("secretsmanager_secret", map[string]string{"rotation_enabled": "true", "next_rotation": ago(10), "last_rotated": ago(120)})
	require.False(t, awsSecretNotRotated90d.Violates(overdue))
}

func TestECSCapacityProviderAndECRLifecycle(t *testing.T) {
	require.True(t, awsECSCapacityProviderNoTerminationProtection.Violates(awsAsset("ecs_capacity_provider", map[string]string{"managed_termination_protection": "DISABLED"})))
	require.False(t, awsECSCapacityProviderNoTerminationProtection.Violates(awsAsset("ecs_capacity_provider", map[string]string{"managed_termination_protection": "ENABLED"})))
	require.True(t, awsECRNoLifecyclePolicy.Violates(awsAsset("ecr_repository", map[string]string{"lifecycle_policy": "false"})))
}
