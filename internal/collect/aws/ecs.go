package aws

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ecsAPI is the slice of the ECS SDK the collector needs — small enough to fake.
type ecsAPI interface {
	ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	DescribeClusters(context.Context, *ecs.DescribeClustersInput, ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error)
	ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
	ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	// Task-definition families and capacity providers (ecs_registry.go).
	ListTaskDefinitionFamilies(context.Context, *ecs.ListTaskDefinitionFamiliesInput, ...func(*ecs.Options)) (*ecs.ListTaskDefinitionFamiliesOutput, error)
	DescribeCapacityProviders(context.Context, *ecs.DescribeCapacityProvidersInput, ...func(*ecs.Options)) (*ecs.DescribeCapacityProvidersOutput, error)
}

// collectECS builds the ECS (and ELBv2, for target groups) clients and pulls
// clusters + services (+ their containers and running images) for a region.
// Returns edges too, so it is called explicitly alongside Lambda/RDS/EKS in
// aws.go rather than through the generic list-and-emit loop those asset-only
// collectors share. partial reports a best-effort sub-listing (running tasks,
// a task definition, target groups) that failed: the services are still
// emitted, but what hangs off them is incomplete this sweep.
func collectECS(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, bool, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, nil, false, fmt.Errorf("collectECS: %w", err)
	}
	return collectECSResources(ctx, ecs.NewFromConfig(awsCfg), elasticloadbalancingv2.NewFromConfig(awsCfg), region, accountID, now)
}

// ecsSweep accumulates one region's ECS output. Images are deduplicated by
// digest across clusters: the same image run by many services is one node.
type ecsSweep struct {
	region, accountID string
	now               time.Time
	assets            []asset.Asset
	edges             []asset.Edge
	seenImages        map[string]bool
	tgByService       map[string][]string // service ARN → target group ARNs
	// serviceTaskDefs are the task-definition revisions a service runs: they
	// are graded through the service and its containers, so the latest-revision
	// sweep (ecs_registry.go) does not emit them again.
	serviceTaskDefs map[string]bool
	partial         bool
}

// collectECSResources lists clusters and their services. A service whose tasks
// get a public IP (assignPublicIp ENABLED) is a real internet entry point, so
// the flag is stamped for the exposure check; a service behind a load balancer
// is linked to it (load_balancer -routes_to-> ecs_service) so the LB's
// exposure reaches it.
func collectECSResources(ctx context.Context, client ecsAPI, tgClient targetGroupAPI, region, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, bool, error) {
	var clusterARNs []string
	var token *string
	for {
		out, err := client.ListClusters(ctx, &ecs.ListClustersInput{NextToken: token})
		if err != nil {
			return nil, nil, false, fmt.Errorf("collectECSResources: list clusters: %w", err)
		}
		clusterARNs = append(clusterARNs, out.ClusterArns...)
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	sw := &ecsSweep{
		region: region, accountID: accountID, now: now,
		seenImages:      map[string]bool{},
		tgByService:     map[string][]string{},
		serviceTaskDefs: map[string]bool{},
	}
	if len(clusterARNs) == 0 {
		// A registered task definition is ECS in use even with no cluster
		// (it can be run later, or by a scheduled task elsewhere), so it is
		// graded in every region; an unused region lists no family.
		sw.collectLatestTaskDefinitions(ctx, client)
		return sw.assets, nil, sw.partial, nil
	}

	// DescribeClusters takes at most 100 clusters per call.
	var clusters []ecstypes.Cluster
	for _, batch := range chunk(clusterARNs, 100) {
		desc, err := client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: batch,
			// SETTINGS adds the containerInsights setting to the same call.
			Include: []ecstypes.ClusterField{ecstypes.ClusterFieldSettings},
		})
		if err != nil {
			return nil, nil, false, fmt.Errorf("collectECSResources: describe clusters: %w", err)
		}
		clusters = append(clusters, desc.Clusters...)
	}

	for _, c := range clusters {
		arn := awssdk.ToString(c.ClusterArn)
		meta := map[string]string{
			"status":                awssdk.ToString(c.Status),
			"active_services_count": fmt.Sprintf("%d", c.ActiveServicesCount),
		}
		for _, st := range c.Settings {
			if st.Name == ecstypes.ClusterSettingNameContainerInsights {
				meta["container_insights"] = awssdk.ToString(st.Value)
			}
		}
		tasks, err := runningServiceImages(ctx, client, arn)
		if err != nil {
			// The services are still real; only their running images are unknown
			// this sweep. Partial, so an image that dropped out is not read as gone.
			log.FromContext(ctx).Warn().Err(err).Str("cluster", arn).
				Msg("ecs: running task images unavailable; services collected without images")
			sw.partial = true
		} else {
			// Written only when the listing succeeded: these tasks' images are
			// scanned by nothing, and an unknown count must not read as zero.
			meta["standalone_tasks"] = strconv.Itoa(tasks.standalone)
		}
		sw.assets = append(sw.assets, asset.Asset{
			ID:           arn,
			Name:         awssdk.ToString(c.ClusterName),
			Type:         "ecs_cluster",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
		if err := collectECSServices(ctx, client, sw, arn, tasks); err != nil {
			return nil, nil, false, err
		}
	}
	sw.linkLoadBalancers(ctx, tgClient)
	sw.collectLatestTaskDefinitions(ctx, client)
	sw.collectCapacityProviders(ctx, client)
	return sw.assets, sw.edges, sw.partial, nil
}

// linkLoadBalancers emits load_balancer -routes_to-> ecs_service for every
// target group a service registers with. A failed lookup flags the sweep
// partial: a missing link would silently understate the service's exposure.
func (sw *ecsSweep) linkLoadBalancers(ctx context.Context, tgClient targetGroupAPI) {
	var tgARNs []string
	for _, arns := range sw.tgByService {
		tgARNs = append(tgARNs, arns...)
	}
	if len(tgARNs) == 0 {
		return
	}
	slices.Sort(tgARNs)
	tgARNs = slices.Compact(tgARNs)
	lbsByTG, err := targetGroupLoadBalancers(ctx, tgClient, tgARNs)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).
			Msg("ecs: target group lookup failed; load balancer → service links missing this sweep")
		sw.partial = true
		return
	}
	for _, serviceARN := range slices.Sorted(maps.Keys(sw.tgByService)) {
		linked := map[string]bool{}
		for _, tg := range sw.tgByService[serviceARN] {
			for _, lb := range lbsByTG[tg] {
				if linked[lb] {
					continue
				}
				linked[lb] = true
				sw.edges = append(sw.edges, asset.Edge{
					SrcID: lb, SrcType: "load_balancer",
					DstID: serviceARN, DstType: "ecs_service",
					EdgeType:   "routes_to",
					Properties: map[string]string{"target_group": tg},
				})
			}
		}
	}
}

// collectECSServices appends one cluster's services, their task-definition
// containers and their running images to sw. tasks is nil when the task
// listing failed.
func collectECSServices(ctx context.Context, client ecsAPI, sw *ecsSweep, clusterARN string, tasks *clusterTasks) error {
	var serviceARNs []string
	var token *string
	for {
		out, err := client.ListServices(ctx, &ecs.ListServicesInput{Cluster: &clusterARN, NextToken: token})
		if err != nil {
			return fmt.Errorf("collectECSServices: list: %w", err)
		}
		serviceARNs = append(serviceARNs, out.ServiceArns...)
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	if len(serviceARNs) == 0 {
		return nil
	}

	// Cache the described task definition by ARN — avoids N API calls when many
	// services share the same task definition family revision. It carries both
	// the task role (already used for the executes_as edge) AND the container
	// definitions list, so promoting containers to assets costs zero extra
	// AWS API round-trips: DescribeTaskDefinition is fetched for the task role anyway.
	taskDefCache := map[string]*ecstypes.TaskDefinition{}
	taskDefFor := func(taskDefARN string) *ecstypes.TaskDefinition {
		if taskDefARN == "" {
			return nil
		}
		if td, ok := taskDefCache[taskDefARN]; ok {
			return td
		}
		out, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &taskDefARN})
		if err != nil || out.TaskDefinition == nil {
			// No task role and no containers for this service this sweep: an
			// absent executes_as edge must not read as "runs as nothing".
			log.FromContext(ctx).Warn().Err(err).Str("task_definition", taskDefARN).
				Msg("ecs: task definition unavailable; service collected without role or containers")
			sw.partial = true
			taskDefCache[taskDefARN] = nil
			return nil
		}
		taskDefCache[taskDefARN] = out.TaskDefinition
		return out.TaskDefinition
	}

	// DescribeServices takes at most 10 services per call.
	for _, batch := range chunk(serviceARNs, 10) {
		desc, err := client.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: &clusterARN, Services: batch})
		if err != nil {
			return fmt.Errorf("collectECSServices: describe: %w", err)
		}
		for _, s := range desc.Services {
			sw.addService(s, clusterARN, taskDefFor(awssdk.ToString(s.TaskDefinition)), tasks)
		}
	}
	return nil
}

// addService emits the ecs_service asset, its task-definition containers
// (runs_container) and the image digests its running tasks resolved
// (runs_image) — the same container_image node and edge the k8s pod path
// emits, so the imagevuln sweep scans it and the must-fix supply-chain chain
// reaches the service's exposure.
func (sw *ecsSweep) addService(s ecstypes.Service, clusterARN string, taskDef *ecstypes.TaskDefinition, tasks *clusterTasks) {
	pubIP := assignPublicIP(s.NetworkConfiguration)
	serviceARN := awssdk.ToString(s.ServiceArn)
	serviceName := awssdk.ToString(s.ServiceName)
	meta := map[string]string{
		"cluster":          clusterARN,
		"launch_type":      string(s.LaunchType),
		"desired_count":    fmt.Sprintf("%d", s.DesiredCount),
		"assign_public_ip": pubIP,
		// A capacity-provider strategy on FARGATE / FARGATE_SPOT runs the
		// tasks on Fargate with no launch type set (FSBP ECS.10).
		"capacity_provider_fargate": strconv.FormatBool(usesFargateCapacity(s.CapacityProviderStrategy)),
		// Task sets (EXTERNAL / CODE_DEPLOY deployments) carry their own
		// network configuration (FSBP ECS.16).
		"task_sets_public_ip": strings.Join(publicTaskSets(s.TaskSets), ","),
	}
	if td := awssdk.ToString(s.TaskDefinition); td != "" {
		sw.serviceTaskDefs[td] = true
	}
	// public=true makes InternetReachability emit an exposed_to_internet edge.
	// Only awsvpc tasks own an interface whose public IP this setting decides;
	// bridge/host-networked tasks (EC2 launch type) answer on the HOST
	// instance's interfaces, so their exposure is not measured here and the key
	// stays absent rather than reading as a confirmed "not public".
	if pubIP != "" {
		meta["public"] = fmt.Sprintf("%t", pubIP == "ENABLED")
	}
	var images []collect.RunningImage
	if tasks != nil {
		images = tasks.images[serviceName]
		if n := tasks.unresolved[serviceName]; n > 0 {
			meta["running_images_unresolved"] = strconv.Itoa(n)
		}
	}
	if taskDef != nil {
		// The task role is the role the containers run as — the executes_as edge.
		if role := awssdk.ToString(taskDef.TaskRoleArn); role != "" {
			meta["exec_role"] = role
		}
		if mode := string(taskDef.NetworkMode); mode != "" {
			meta["network_mode"] = mode
		}
		maps.Copy(meta, taskPostureMeta(taskDef))
	}
	if pv := awssdk.ToString(s.PlatformVersion); pv != "" {
		meta["platform_version"] = pv
	}
	if tgs := serviceTargetGroups(s); len(tgs) > 0 {
		sw.tgByService[serviceARN] = tgs
	}
	sw.assets = append(sw.assets, asset.Asset{
		ID:           serviceARN,
		Name:         serviceName,
		Type:         "ecs_service",
		Provider:     asset.ProviderAWS,
		Region:       sw.region,
		AccountID:    sw.accountID,
		Metadata:     meta,
		DiscoveredAt: sw.now,
		LastSeen:     sw.now,
	})

	for _, img := range images {
		sw.edges = append(sw.edges, collect.RunsImageEdge(serviceARN, "ecs_service", img))
		if sw.seenImages[img.Digest] {
			continue
		}
		sw.seenImages[img.Digest] = true
		sw.assets = append(sw.assets, collect.ImageAsset(img, asset.ProviderAWS, sw.region, sw.accountID, sw.now))
	}

	// Container assets come from the task DEFINITION (the static container
	// list): same names every task launched from this service runs, and free
	// since taskDefFor already fetched it for the task role above.
	if taskDef == nil {
		return
	}
	for _, cd := range taskDef.ContainerDefinitions {
		name := awssdk.ToString(cd.Name)
		if name == "" {
			continue
		}
		containerID := fmt.Sprintf("%s/container/%s", serviceARN, name)
		cmeta := containerPostureMeta(cd)
		cmeta["service"] = serviceARN
		cmeta["cluster"] = clusterARN
		cmeta["image"] = awssdk.ToString(cd.Image)
		if fam, ok := meta["os_family"]; ok {
			cmeta["os_family"] = fam
		}
		sw.assets = append(sw.assets, asset.Asset{
			ID:           containerID,
			Name:         name,
			Type:         "container",
			Provider:     asset.ProviderAWS,
			Region:       sw.region,
			AccountID:    sw.accountID,
			Metadata:     cmeta,
			DiscoveredAt: sw.now,
			LastSeen:     sw.now,
		})
		sw.edges = append(sw.edges, asset.Edge{
			SrcID: serviceARN, SrcType: "ecs_service",
			DstID:    containerID,
			DstType:  "container",
			EdgeType: "runs_container",
		})
	}
}

// assignPublicIP reports the service's awsvpc public-IP setting ("ENABLED" /
// "DISABLED" / "" when not awsvpc).
func assignPublicIP(nc *ecstypes.NetworkConfiguration) string {
	if nc == nil || nc.AwsvpcConfiguration == nil {
		return ""
	}
	return string(nc.AwsvpcConfiguration.AssignPublicIp)
}

// usesFargateCapacity reports a strategy that places tasks on Fargate.
func usesFargateCapacity(strategy []ecstypes.CapacityProviderStrategyItem) bool {
	for _, item := range strategy {
		switch awssdk.ToString(item.CapacityProvider) {
		case "FARGATE", "FARGATE_SPOT":
			return true
		}
	}
	return false
}

// publicTaskSets returns the ids of task sets that assign public IPs.
func publicTaskSets(sets []ecstypes.TaskSet) []string {
	var out []string
	for _, ts := range sets {
		if assignPublicIP(ts.NetworkConfiguration) == string(ecstypes.AssignPublicIpEnabled) {
			out = append(out, awssdk.ToString(ts.Id))
		}
	}
	slices.Sort(out)
	return out
}

// chunk splits s into consecutive slices of at most n elements.
func chunk(s []string, n int) [][]string {
	var out [][]string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return out
}
