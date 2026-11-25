package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeECS struct {
	clusters    []ecstypes.Cluster
	services    []ecstypes.Service
	taskDef     *ecstypes.TaskDefinition
	taskDefErr  error
	tasks       []ecstypes.Task
	listTaskErr error
	// families pages ListTaskDefinitionFamilies; latest maps a family to the
	// revision DescribeTaskDefinition(family) returns (nil → describe error).
	families     [][]string
	familiesErr  error
	latest       map[string]*ecstypes.TaskDefinition
	capProviders [][]ecstypes.CapacityProvider
	capErr       error
}

func (f *fakeECS) ListTaskDefinitionFamilies(_ context.Context, in *ecs.ListTaskDefinitionFamiliesInput, _ ...func(*ecs.Options)) (*ecs.ListTaskDefinitionFamiliesOutput, error) {
	if f.familiesErr != nil {
		return nil, f.familiesErr
	}
	page := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &page)
	}
	if page >= len(f.families) {
		return &ecs.ListTaskDefinitionFamiliesOutput{}, nil
	}
	out := &ecs.ListTaskDefinitionFamiliesOutput{Families: f.families[page]}
	if page+1 < len(f.families) {
		out.NextToken = awssdk.String(fmt.Sprint(page + 1))
	}
	return out, nil
}

func (f *fakeECS) DescribeCapacityProviders(_ context.Context, in *ecs.DescribeCapacityProvidersInput, _ ...func(*ecs.Options)) (*ecs.DescribeCapacityProvidersOutput, error) {
	if f.capErr != nil {
		return nil, f.capErr
	}
	page := 0
	if in.NextToken != nil {
		fmt.Sscanf(*in.NextToken, "%d", &page)
	}
	if page >= len(f.capProviders) {
		return &ecs.DescribeCapacityProvidersOutput{}, nil
	}
	out := &ecs.DescribeCapacityProvidersOutput{CapacityProviders: f.capProviders[page]}
	if page+1 < len(f.capProviders) {
		out.NextToken = awssdk.String(fmt.Sprint(page + 1))
	}
	return out, nil
}

func (f *fakeECS) ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	arns := make([]string, len(f.clusters))
	for i, c := range f.clusters {
		arns[i] = awssdk.ToString(c.ClusterArn)
	}
	return &ecs.ListClustersOutput{ClusterArns: arns}, nil
}

func (f *fakeECS) DescribeClusters(context.Context, *ecs.DescribeClustersInput, ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error) {
	return &ecs.DescribeClustersOutput{Clusters: f.clusters}, nil
}

func (f *fakeECS) ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	arns := make([]string, len(f.services))
	for i, s := range f.services {
		arns[i] = awssdk.ToString(s.ServiceArn)
	}
	return &ecs.ListServicesOutput{ServiceArns: arns}, nil
}

func (f *fakeECS) DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return &ecs.DescribeServicesOutput{Services: f.services}, nil
}

func (f *fakeECS) DescribeTaskDefinition(_ context.Context, in *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	if td, ok := f.latest[awssdk.ToString(in.TaskDefinition)]; ok {
		if td == nil {
			return nil, errors.New("throttled")
		}
		return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: td}, nil
	}
	if f.taskDefErr != nil {
		return nil, f.taskDefErr
	}
	if f.taskDef == nil {
		return &ecs.DescribeTaskDefinitionOutput{}, nil
	}
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: f.taskDef}, nil
}

func (f *fakeECS) ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	if f.listTaskErr != nil {
		return nil, f.listTaskErr
	}
	arns := make([]string, len(f.tasks))
	for i, t := range f.tasks {
		arns[i] = awssdk.ToString(t.TaskArn)
	}
	return &ecs.ListTasksOutput{TaskArns: arns}, nil
}

func (f *fakeECS) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	want := map[string]bool{}
	for _, a := range in.Tasks {
		want[a] = true
	}
	var out []ecstypes.Task
	for _, t := range f.tasks {
		if want[awssdk.ToString(t.TaskArn)] {
			out = append(out, t)
		}
	}
	return &ecs.DescribeTasksOutput{Tasks: out}, nil
}

type fakeTargetGroups struct {
	lbsByTG map[string][]string
	err     error
	// missing target groups fail the WHOLE call they appear in with
	// TargetGroupNotFound, exactly as ELBv2 does.
	missing map[string]bool
	calls   int
}

func (f *fakeTargetGroups) DescribeTargetGroups(_ context.Context, in *elasticloadbalancingv2.DescribeTargetGroupsInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeTargetGroupsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	for _, arn := range in.TargetGroupArns {
		if f.missing[arn] {
			return nil, &elbv2types.TargetGroupNotFoundException{Message: awssdk.String("One or more target groups not found")}
		}
	}
	var tgs []elbv2types.TargetGroup
	for _, arn := range in.TargetGroupArns {
		tgs = append(tgs, elbv2types.TargetGroup{TargetGroupArn: awssdk.String(arn), LoadBalancerArns: f.lbsByTG[arn]})
	}
	return &elasticloadbalancingv2.DescribeTargetGroupsOutput{TargetGroups: tgs}, nil
}

const (
	ecsTestCluster = "arn:aws:ecs:eu-west-1:1:cluster/prod"
	ecsTestService = "arn:aws:ecs:eu-west-1:1:service/prod/web"
	ecsTestDigest  = "sha256:aaaa000000000000000000000000000000000000000000000000000000000000"
	ecsTestTG      = "arn:aws:elasticloadbalancing:eu-west-1:1:targetgroup/web/abc"
	ecsTestLB      = "arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/web/def"
)

func ecsTestFake() *fakeECS {
	return &fakeECS{
		clusters: []ecstypes.Cluster{
			{ClusterArn: awssdk.String(ecsTestCluster), ClusterName: awssdk.String("prod"), Status: awssdk.String("ACTIVE")},
		},
		services: []ecstypes.Service{
			{
				ServiceArn:  awssdk.String(ecsTestService),
				ServiceName: awssdk.String("web"),
				LaunchType:  ecstypes.LaunchTypeFargate,
				NetworkConfiguration: &ecstypes.NetworkConfiguration{
					AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{AssignPublicIp: ecstypes.AssignPublicIpEnabled},
				},
				TaskDefinition: awssdk.String("arn:aws:ecs:eu-west-1:1:task-definition/web:3"),
				LoadBalancers:  []ecstypes.LoadBalancer{{TargetGroupArn: awssdk.String(ecsTestTG)}},
			},
		},
		taskDef: &ecstypes.TaskDefinition{
			NetworkMode: ecstypes.NetworkModeAwsvpc,
			TaskRoleArn: awssdk.String("arn:aws:iam::1:role/web-task-role"),
			ContainerDefinitions: []ecstypes.ContainerDefinition{
				{Name: awssdk.String("web"), Image: awssdk.String("web:1.2.3")},
				{Name: awssdk.String("sidecar"), Image: awssdk.String("envoy:1.0")},
			},
		},
		tasks: []ecstypes.Task{
			{
				TaskArn: awssdk.String("arn:aws:ecs:eu-west-1:1:task/prod/t1"),
				Group:   awssdk.String("service:web"),
				Containers: []ecstypes.Container{
					{Name: awssdk.String("web"), Image: awssdk.String("1.dkr.ecr.eu-west-1.amazonaws.com/web:1.2.3"), ImageDigest: awssdk.String(ecsTestDigest)},
					// Digest not resolved yet (task still PENDING) — skipped.
					{Name: awssdk.String("sidecar"), Image: awssdk.String("envoy:1.0")},
				},
			},
			// A second replica of the same service running the same digest: one image.
			{
				TaskArn: awssdk.String("arn:aws:ecs:eu-west-1:1:task/prod/t2"),
				Group:   awssdk.String("service:web"),
				Containers: []ecstypes.Container{
					{Name: awssdk.String("web"), Image: awssdk.String("1.dkr.ecr.eu-west-1.amazonaws.com/web:1.2.3"), ImageDigest: awssdk.String(ecsTestDigest)},
				},
			},
			// A standalone task (not launched by a service) is not attributed to one.
			{
				TaskArn: awssdk.String("arn:aws:ecs:eu-west-1:1:task/prod/t3"),
				Group:   awssdk.String("family:batch"),
				Containers: []ecstypes.Container{
					{Name: awssdk.String("batch"), Image: awssdk.String("batch:1"), ImageDigest: awssdk.String("sha256:bbbb")},
				},
			},
		},
	}
}

func byTypeOf(assets []asset.Asset) map[string][]asset.Asset {
	out := map[string][]asset.Asset{}
	for _, a := range assets {
		out[a.Type] = append(out[a.Type], a)
	}
	return out
}

func edgesOfType(edges []asset.Edge, edgeType string) []asset.Edge {
	var out []asset.Edge
	for _, e := range edges {
		if e.EdgeType == edgeType {
			out = append(out, e)
		}
	}
	return out
}

func TestCollectECSResources(t *testing.T) {
	tgs := &fakeTargetGroups{lbsByTG: map[string][]string{ecsTestTG: {ecsTestLB}}}
	assets, edges, partial, err := collectECSResources(context.Background(), ecsTestFake(), tgs, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.False(t, partial)

	byType := byTypeOf(assets)
	require.Contains(t, byType, "ecs_cluster")
	require.Contains(t, byType, "ecs_service")
	require.Equal(t, "ENABLED", byType["ecs_service"][0].Metadata["assign_public_ip"])
	require.Equal(t, "awsvpc", byType["ecs_service"][0].Metadata["network_mode"])
	require.Equal(t, "true", byType["ecs_service"][0].Metadata["public"])
	require.Equal(t, "FARGATE", byType["ecs_service"][0].Metadata["launch_type"])
	require.Equal(t, "arn:aws:iam::1:role/web-task-role", byType["ecs_service"][0].Metadata["exec_role"])

	require.Len(t, byType["container"], 2, "one container asset per task-def container definition")
	byID := map[string]asset.Asset{}
	for _, c := range byType["container"] {
		byID[c.ID] = c
	}
	web := byID[ecsTestService+"/container/web"]
	require.Equal(t, "web", web.Name)
	require.Equal(t, "web:1.2.3", web.Metadata["image"])
	require.Equal(t, asset.ProviderAWS, web.Provider)

	containerEdges := edgesOfType(edges, "runs_container")
	require.Len(t, containerEdges, 2, "ecs_service->container edge per container")
	for _, e := range containerEdges {
		require.Equal(t, ecsTestService, e.SrcID)
		require.Equal(t, "ecs_service", e.SrcType)
		require.Equal(t, "container", e.DstType)
	}

	// Running-task digests: one image (two replicas, same digest), keyed exactly
	// like the k8s path so a digest run on both is one node.
	require.Len(t, byType["container_image"], 1)
	img := byType["container_image"][0]
	require.Equal(t, "image/"+ecsTestDigest, img.ID)
	require.Equal(t, ecsTestDigest, img.Metadata["image_id"])
	require.Equal(t, "1.dkr.ecr.eu-west-1.amazonaws.com/web:1.2.3", img.Metadata["image_ref"])
	require.Equal(t, "1", img.AccountID)

	imageEdges := edgesOfType(edges, "runs_image")
	require.Len(t, imageEdges, 1)
	require.Equal(t, asset.Edge{
		SrcID: ecsTestService, SrcType: "ecs_service",
		DstID: "image/" + ecsTestDigest, DstType: "container_image",
		EdgeType:   "runs_image",
		Properties: map[string]string{"image_ref": "1.dkr.ecr.eu-west-1.amazonaws.com/web:1.2.3"},
	}, imageEdges[0])

	routes := edgesOfType(edges, "routes_to")
	require.Len(t, routes, 1)
	require.Equal(t, ecsTestLB, routes[0].SrcID)
	require.Equal(t, "load_balancer", routes[0].SrcType)
	require.Equal(t, ecsTestService, routes[0].DstID)
	require.Equal(t, "ecs_service", routes[0].DstType)
}

// A failed sub-listing keeps the services but marks the sweep partial — an
// image or LB link that is missing because a call failed must not read as gone.
func TestCollectECSResources_DegradedSubListingsArePartial(t *testing.T) {
	boom := errors.New("throttled")
	tests := []struct {
		name       string
		mutate     func(*fakeECS)
		tgErr      error
		wantImages int
		wantRoutes int
		wantRole   bool
	}{
		{name: "task listing fails", mutate: func(f *fakeECS) { f.listTaskErr = boom }, wantImages: 0, wantRoutes: 1, wantRole: true},
		{name: "task definition fails", mutate: func(f *fakeECS) { f.taskDefErr = boom }, wantImages: 1, wantRoutes: 1, wantRole: false},
		{name: "target groups fail", mutate: func(*fakeECS) {}, tgErr: boom, wantImages: 1, wantRoutes: 0, wantRole: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := ecsTestFake()
			tt.mutate(fake)
			tgs := &fakeTargetGroups{lbsByTG: map[string][]string{ecsTestTG: {ecsTestLB}}, err: tt.tgErr}
			assets, edges, partial, err := collectECSResources(context.Background(), fake, tgs, "eu-west-1", "1", time.Now())
			require.NoError(t, err)
			require.True(t, partial)
			byType := byTypeOf(assets)
			require.Len(t, byType["ecs_service"], 1, "the service itself is always emitted")
			require.Len(t, byType["container_image"], tt.wantImages)
			require.Len(t, edgesOfType(edges, "routes_to"), tt.wantRoutes)
			_, hasRole := byType["ecs_service"][0].Metadata["exec_role"]
			require.Equal(t, tt.wantRole, hasRole)
		})
	}
}

func TestCollectECSResources_NoClusters(t *testing.T) {
	assets, edges, partial, err := collectECSResources(context.Background(), &fakeECS{}, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.False(t, partial)
	require.Empty(t, assets)
	require.Empty(t, edges)
}

// One deleted target group must cost only its own link: ELBv2 fails the whole
// DescribeTargetGroups call on any unknown ARN, which used to drop every
// LB -> service edge in the region and mark the connector Partial forever.
func TestCollectECSResources_StaleTargetGroupDropsOnlyItself(t *testing.T) {
	const staleTG = "arn:aws:elasticloadbalancing:eu-west-1:1:targetgroup/old/zzz"
	fake := ecsTestFake()
	fake.services[0].LoadBalancers = append(fake.services[0].LoadBalancers, ecstypes.LoadBalancer{TargetGroupArn: awssdk.String(staleTG)})
	tgs := &fakeTargetGroups{
		lbsByTG: map[string][]string{ecsTestTG: {ecsTestLB}},
		missing: map[string]bool{staleTG: true},
	}
	_, edges, partial, err := collectECSResources(context.Background(), fake, tgs, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.False(t, partial, "a target group that no longer exists is an observation, not a failed read")
	routes := edgesOfType(edges, "routes_to")
	require.Len(t, routes, 1)
	require.Equal(t, ecsTestLB, routes[0].SrcID)
	require.Equal(t, ecsTestTG, routes[0].Properties["target_group"])
}

func TestTargetGroupLoadBalancers_SplitsAroundMissing(t *testing.T) {
	var arns []string
	lbs := map[string][]string{}
	for i := range 20 {
		arn := fmt.Sprintf("arn:aws:elasticloadbalancing:eu-west-1:1:targetgroup/tg%02d/x", i)
		arns = append(arns, arn)
		lbs[arn] = []string{fmt.Sprintf("lb-%02d", i)}
	}
	tgs := &fakeTargetGroups{lbsByTG: lbs, missing: map[string]bool{arns[3]: true, arns[17]: true}}
	got, err := targetGroupLoadBalancers(context.Background(), tgs, arns)
	require.NoError(t, err)
	require.Len(t, got, 18)
	require.NotContains(t, got, arns[3])
	require.NotContains(t, got, arns[17])
	require.Equal(t, []string{"lb-00"}, got[arns[0]])
	require.Less(t, tgs.calls, len(arns), "bisects rather than retrying every ARN alone")
}

// Bridge/host networking (EC2 launch type) puts the task on the HOST's
// interfaces, so the service's own exposure is not measured here: "public"
// must be absent, never "false".
func TestCollectECSResources_HostNetworkedExposureUnknown(t *testing.T) {
	fake := ecsTestFake()
	fake.services[0].LaunchType = ecstypes.LaunchTypeEc2
	fake.services[0].NetworkConfiguration = nil
	fake.taskDef.NetworkMode = ecstypes.NetworkModeBridge
	assets, _, _, err := collectECSResources(context.Background(), fake, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	svc := byTypeOf(assets)["ecs_service"][0]
	require.NotContains(t, svc.Metadata, "public")
	require.Equal(t, "bridge", svc.Metadata["network_mode"])
	require.Empty(t, svc.Metadata["assign_public_ip"])
}

// Running images that cannot be attributed are recorded, not silently dropped:
// standalone tasks (Group "family:...") on the cluster, unresolved digests on
// the service.
func TestCollectECSResources_UnattributedImagesRecorded(t *testing.T) {
	assets, _, _, err := collectECSResources(context.Background(), ecsTestFake(), &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	byType := byTypeOf(assets)
	require.Equal(t, "1", byType["ecs_cluster"][0].Metadata["standalone_tasks"])
	require.Equal(t, "1", byType["ecs_service"][0].Metadata["running_images_unresolved"])

	// Task listing failed: nothing is known, so neither key is written.
	fake := ecsTestFake()
	fake.listTaskErr = errors.New("throttled")
	assets, _, _, err = collectECSResources(context.Background(), fake, &fakeTargetGroups{}, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	byType = byTypeOf(assets)
	require.NotContains(t, byType["ecs_cluster"][0].Metadata, "standalone_tasks")
	require.NotContains(t, byType["ecs_service"][0].Metadata, "running_images_unresolved")
}
