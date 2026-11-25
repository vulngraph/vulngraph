package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestCollectECSResources_TaskDefinitionPosture(t *testing.T) {
	f := ecsTestFake()
	f.clusters[0].Settings = []ecstypes.ClusterSetting{{Name: ecstypes.ClusterSettingNameContainerInsights, Value: awssdk.String("disabled")}}
	f.services[0].PlatformVersion = awssdk.String("1.3.0")
	f.taskDef.PidMode = ecstypes.PidModeHost
	f.taskDef.RuntimePlatform = &ecstypes.RuntimePlatform{OperatingSystemFamily: ecstypes.OSFamilyLinux}
	f.taskDef.Volumes = []ecstypes.Volume{
		{Name: awssdk.String("shared"), EfsVolumeConfiguration: &ecstypes.EFSVolumeConfiguration{FileSystemId: awssdk.String("fs-1")}},
		{Name: awssdk.String("tls"), EfsVolumeConfiguration: &ecstypes.EFSVolumeConfiguration{
			FileSystemId: awssdk.String("fs-2"), TransitEncryption: ecstypes.EFSTransitEncryptionEnabled}},
		{Name: awssdk.String("scratch")},
	}
	f.taskDef.ContainerDefinitions[0].Privileged = awssdk.Bool(true)
	f.taskDef.ContainerDefinitions[0].User = awssdk.String("root")
	f.taskDef.ContainerDefinitions[0].Environment = []ecstypes.KeyValuePair{
		{Name: awssdk.String("AWS_SECRET_ACCESS_KEY"), Value: awssdk.String("abc")},
		{Name: awssdk.String("DB_PASSWORD"), Value: awssdk.String("hunter2hunter2")},
		{Name: awssdk.String("DB_PASSWORD_ARN"), Value: awssdk.String("arn:aws:secretsmanager:eu-west-1:1:secret:db")},
		{Name: awssdk.String("API_TOKEN"), Value: awssdk.String("${TOKEN}")},
		{Name: awssdk.String("LOG_LEVEL"), Value: awssdk.String("debug-verbose")},
	}
	f.taskDef.ContainerDefinitions[1].ReadonlyRootFilesystem = awssdk.Bool(true)
	f.taskDef.ContainerDefinitions[1].LogConfiguration = &ecstypes.LogConfiguration{LogDriver: ecstypes.LogDriverAwslogs}

	assets, _, _, err := collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	byType := byTypeOf(assets)

	require.Equal(t, "disabled", byType["ecs_cluster"][0].Metadata["container_insights"])
	svc := byType["ecs_service"][0].Metadata
	require.Equal(t, "host", svc["pid_mode"])
	require.Equal(t, "shared", svc["efs_volumes_plaintext"])
	require.Equal(t, "1.3.0", svc["platform_version"])
	require.Equal(t, "LINUX", svc["os_family"])

	byID := map[string]asset.Asset{}
	for _, c := range byType["container"] {
		byID[c.Name] = c
	}
	web := byID["web"].Metadata
	require.Equal(t, "true", web["privileged"])
	require.Equal(t, "false", web["readonly_root_fs"])
	require.Equal(t, "root", web["user"])
	require.Equal(t, "", web["log_driver"])
	require.Equal(t, "AWS_SECRET_ACCESS_KEY,DB_PASSWORD", web["plaintext_secret_env"],
		"names only; references and placeholders are not plaintext secrets")
	require.Equal(t, "LINUX", web["os_family"])
	require.NotContains(t, web["plaintext_secret_env"], "hunter2", "values never leave the collector")

	sidecar := byID["sidecar"].Metadata
	require.Equal(t, "false", sidecar["privileged"])
	require.Equal(t, "true", sidecar["readonly_root_fs"])
	require.Equal(t, "", sidecar["user"])
	require.Equal(t, "awslogs", sidecar["log_driver"])
	require.Equal(t, "", sidecar["plaintext_secret_env"])
}

// Without a task definition the posture keys are absent, not defaulted.
func TestCollectECSResources_TaskDefinitionUnreadOmitsPosture(t *testing.T) {
	f := ecsTestFake()
	f.taskDef = nil
	assets, _, _, err := collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	svc := byTypeOf(assets)["ecs_service"][0].Metadata
	require.NotContains(t, svc, "pid_mode")
	require.NotContains(t, svc, "efs_volumes_plaintext")
}

func TestEnvValueIsReference(t *testing.T) {
	for v, want := range map[string]bool{
		"arn:aws:secretsmanager:eu-west-1:1:secret:db": true,
		"${DB_PASSWORD}":                      true,
		"{{ resolve:secretsmanager:db }}":     true,
		"/run/secrets/db_password":            true,
		"https://vault.internal/v1/secret/db": true,
		"http://config:8080/token":            true,
		"https://admin:hunter2@db.internal/":  false,
		"hunter2hunter2":                      false,
		"CHANGEME":                            true,
	} {
		require.Equal(t, want, envValueIsReference(v), v)
	}
}
