package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/require"
)

func TestCollectECSResources_LatestTaskDefinitions(t *testing.T) {
	f := ecsTestFake()
	f.families = [][]string{{"web", "batch"}, {"cron", "broken"}}
	f.latest = map[string]*ecstypes.TaskDefinition{
		// The service already runs web:3 — graded through the service.
		"web": {TaskDefinitionArn: awssdk.String("arn:aws:ecs:eu-west-1:1:task-definition/web:3"), Revision: 3},
		"batch": {
			TaskDefinitionArn: awssdk.String("arn:aws:ecs:eu-west-1:1:task-definition/batch:7"), Revision: 7,
			NetworkMode: ecstypes.NetworkModeHost, PidMode: ecstypes.PidModeHost,
			ContainerDefinitions: []ecstypes.ContainerDefinition{
				{Name: awssdk.String("job"), Privileged: awssdk.Bool(true), User: awssdk.String("0:0"),
					Environment: []ecstypes.KeyValuePair{{Name: awssdk.String("AWS_ACCESS_KEY_ID"), Value: awssdk.String("AKIA")}}},
				{Name: awssdk.String("helper"), User: awssdk.String("1000"), ReadonlyRootFilesystem: awssdk.Bool(true),
					LogConfiguration: &ecstypes.LogConfiguration{LogDriver: ecstypes.LogDriverAwslogs}},
				{Name: awssdk.String("noop")},
			},
		},
		// Every field omitted: the AWS defaults are observations.
		"cron":   {TaskDefinitionArn: awssdk.String("arn:aws:ecs:eu-west-1:1:task-definition/cron:1"), Revision: 1},
		"broken": nil,
	}
	assets, _, partial, err := collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.False(t, partial, "one failed describe is that family's unknown posture, not a failed listing")

	byID := map[string]map[string]string{}
	for _, a := range byTypeOf(assets)["ecs_task_definition"] {
		byID[a.Name] = a.Metadata
		require.Equal(t, "arn:aws:ecs:eu-west-1:1:task-definition/"+a.Name, a.ID, "family-level id: stable across revisions")
	}
	require.NotContains(t, byID, "web", "a revision a service runs is graded through the service")
	require.Len(t, byID, 3)

	batch := byID["batch"]
	require.Equal(t, "job", batch["privileged_containers"])
	require.Equal(t, "job,noop", batch["writable_root_fs_containers"])
	require.Equal(t, "job,noop", batch["no_log_containers"])
	require.Equal(t, "job", batch["root_user_containers"])
	require.Equal(t, "noop", batch["unset_user_containers"])
	require.Equal(t, "AWS_ACCESS_KEY_ID", batch["plaintext_secret_env"])
	require.Equal(t, "host", batch["pid_mode"])
	require.Equal(t, "host", batch["network_mode"])
	require.Equal(t, "7", batch["revision"])

	cron := byID["cron"]
	for _, k := range []string{"privileged_containers", "root_user_containers", "plaintext_secret_env", "pid_mode", "efs_volumes_plaintext"} {
		v, ok := cron[k]
		require.True(t, ok, k)
		require.Empty(t, v, k)
	}

	broken := byID["broken"]
	require.Equal(t, map[string]string{"family": "broken"}, broken, "a failed describe leaves every posture key absent")
}

func TestCollectECSResources_TaskDefinitionFamiliesFail(t *testing.T) {
	f := ecsTestFake()
	f.familiesErr = errors.New("throttled")
	assets, _, partial, err := collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.True(t, partial, "an unread family listing must not read as no task definitions")
	require.Empty(t, byTypeOf(assets)["ecs_task_definition"])
	require.Len(t, byTypeOf(assets)["ecs_service"], 1)
}

// A registered task definition is graded even in a region with no cluster;
// capacity providers are not, and a region with neither emits nothing.
func TestCollectECSResources_NoClustersStillGradesTaskDefinitions(t *testing.T) {
	f := &fakeECS{families: [][]string{{"web"}}, capProviders: [][]ecstypes.CapacityProvider{{{Name: awssdk.String("x")}}}}
	assets, _, partial, err := collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.False(t, partial)
	require.Len(t, byTypeOf(assets)["ecs_task_definition"], 1)
	require.Empty(t, byTypeOf(assets)["ecs_capacity_provider"])

	none, _, _, err := collectECSResources(context.Background(), &fakeECS{}, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Empty(t, none, "ECS that is not used produces no assets")

	failed := &fakeECS{familiesErr: errors.New("throttled")}
	_, _, partial, err = collectECSResources(context.Background(), failed, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.True(t, partial, "an unread family listing in a cluster-less region still flags the sweep")
}

func TestCollectECSResources_CapacityProviders(t *testing.T) {
	f := ecsTestFake()
	asg := func(mtp ecstypes.ManagedTerminationProtection) *ecstypes.AutoScalingGroupProvider {
		return &ecstypes.AutoScalingGroupProvider{AutoScalingGroupArn: awssdk.String("arn:asg"), ManagedTerminationProtection: mtp}
	}
	f.capProviders = [][]ecstypes.CapacityProvider{
		{
			{Name: awssdk.String("FARGATE"), Status: ecstypes.CapacityProviderStatusActive},
			{Name: awssdk.String("on"), CapacityProviderArn: awssdk.String("arn:cp/on"), Status: ecstypes.CapacityProviderStatusActive,
				AutoScalingGroupProvider: asg(ecstypes.ManagedTerminationProtectionEnabled)},
		},
		{
			{Name: awssdk.String("default"), CapacityProviderArn: awssdk.String("arn:cp/default"), Status: ecstypes.CapacityProviderStatusActive,
				AutoScalingGroupProvider: asg("")},
			{Name: awssdk.String("gone"), CapacityProviderArn: awssdk.String("arn:cp/gone"), Status: ecstypes.CapacityProviderStatusInactive,
				AutoScalingGroupProvider: asg("")},
		},
	}
	assets, _, partial, err := collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.False(t, partial)
	got := map[string]string{}
	for _, a := range byTypeOf(assets)["ecs_capacity_provider"] {
		got[a.Name] = a.Metadata["managed_termination_protection"]
	}
	require.Equal(t, map[string]string{"on": "ENABLED", "default": "DISABLED"}, got,
		"Fargate built-ins and inactive providers are not graded; an omitted setting is the documented default (off)")

	f.capErr = errors.New("denied")
	assets, _, partial, err = collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.True(t, partial)
	require.Empty(t, byTypeOf(assets)["ecs_capacity_provider"])
}

func TestCollectECSResources_FargateStrategyAndTaskSets(t *testing.T) {
	f := ecsTestFake()
	f.services[0].LaunchType = ""
	f.services[0].NetworkConfiguration = nil
	f.services[0].CapacityProviderStrategy = []ecstypes.CapacityProviderStrategyItem{{CapacityProvider: awssdk.String("FARGATE_SPOT")}}
	public := &ecstypes.NetworkConfiguration{AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{AssignPublicIp: ecstypes.AssignPublicIpEnabled}}
	private := &ecstypes.NetworkConfiguration{AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{AssignPublicIp: ecstypes.AssignPublicIpDisabled}}
	f.services[0].TaskSets = []ecstypes.TaskSet{
		{Id: awssdk.String("ecs-svc/2"), NetworkConfiguration: public},
		{Id: awssdk.String("ecs-svc/1"), NetworkConfiguration: private},
		{Id: awssdk.String("ecs-svc/3")},
	}
	assets, _, _, err := collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	svc := byTypeOf(assets)["ecs_service"][0].Metadata
	require.Equal(t, "true", svc["capacity_provider_fargate"])
	require.Equal(t, "ecs-svc/2", svc["task_sets_public_ip"])

	f = ecsTestFake()
	assets, _, _, err = collectECSResources(context.Background(), f, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	svc = byTypeOf(assets)["ecs_service"][0].Metadata
	require.Equal(t, "false", svc["capacity_provider_fargate"])
	v, ok := svc["task_sets_public_ip"]
	require.True(t, ok)
	require.Empty(t, v, "a service with no task sets has none that are public — observed")
}
