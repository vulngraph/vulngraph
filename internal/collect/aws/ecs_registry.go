package aws

import (
	"context"
	"fmt"
	"maps"
	"strconv"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ECS resources graded outside the services that run them: the latest active
// revision of every task-definition family (FSBP ECS.3/4/5/8/9/18/20/21
// evaluate task definitions, not services) and Auto Scaling group capacity
// providers (FSBP ECS.19). Task definitions are read in every region (a
// region with none lists no family); capacity providers only where a cluster
// exists to use them.

// taskDefDescribeConcurrency bounds the per-family DescribeTaskDefinition
// fan-out; ECS throttles that call at a low steady rate.
const taskDefDescribeConcurrency = 4

// collectLatestTaskDefinitions emits an ecs_task_definition asset for each
// family's latest ACTIVE revision that no collected service runs: a revision
// a service runs is already graded through the service and its containers,
// and grading it twice would be two findings for one root cause. A failed
// family listing emits none and flags the sweep partial; a failed describe
// emits the family with its posture keys absent.
func (sw *ecsSweep) collectLatestTaskDefinitions(ctx context.Context, client ecsAPI) {
	var families []string
	var token *string
	for {
		out, err := client.ListTaskDefinitionFamilies(ctx, &ecs.ListTaskDefinitionFamiliesInput{
			Status: ecstypes.TaskDefinitionFamilyStatusActive, NextToken: token,
		})
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("region", sw.region).
				Msg("ecs: task definition families unavailable (check ecs:ListTaskDefinitionFamilies); standalone task definitions not graded this sweep")
			sw.partial = true
			return
		}
		families = append(families, out.Families...)
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}

	results := make([]*asset.Asset, len(families))
	var wg sync.WaitGroup
	sem := make(chan struct{}, taskDefDescribeConcurrency)
	for i, family := range families {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("family", family).
						Msg("ecs: task definition describe panicked")
				}
			}()
			results[i] = sw.latestTaskDefinition(ctx, client, family)
		}()
	}
	wg.Wait()
	for _, a := range results {
		if a != nil {
			sw.assets = append(sw.assets, *a)
		}
	}
}

// latestTaskDefinition describes a family by name, which returns its latest
// ACTIVE revision. nil when a service already runs that revision.
func (sw *ecsSweep) latestTaskDefinition(ctx context.Context, client ecsAPI, family string) *asset.Asset {
	a := asset.Asset{
		ID:           fmt.Sprintf("arn:%s:ecs:%s:%s:task-definition/%s", partitionFor(sw.region), sw.region, sw.accountID, family),
		Name:         family,
		Type:         "ecs_task_definition",
		Provider:     asset.ProviderAWS,
		Region:       sw.region,
		AccountID:    sw.accountID,
		Metadata:     map[string]string{"family": family},
		DiscoveredAt: sw.now,
		LastSeen:     sw.now,
	}
	out, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: awssdk.String(family)})
	if err != nil || out == nil || out.TaskDefinition == nil {
		log.FromContext(ctx).Warn().Err(err).Str("family", family).
			Msg("ecs: task definition unavailable (check ecs:DescribeTaskDefinition); family emitted without posture")
		return &a
	}
	td := out.TaskDefinition
	arn := awssdk.ToString(td.TaskDefinitionArn)
	if sw.serviceTaskDefs[arn] {
		return nil
	}
	a.Metadata["task_definition_arn"] = arn
	a.Metadata["revision"] = strconv.Itoa(int(td.Revision))
	if mode := string(td.NetworkMode); mode != "" {
		a.Metadata["network_mode"] = mode
	}
	maps.Copy(a.Metadata, taskPostureMeta(td))
	maps.Copy(a.Metadata, taskDefinitionContainersMeta(td.ContainerDefinitions))
	return &a
}

// collectCapacityProviders emits the region's Auto Scaling group capacity
// providers. The built-in FARGATE / FARGATE_SPOT providers have no Auto Scaling
// group and nothing to protect. A failed listing emits none and flags partial.
func (sw *ecsSweep) collectCapacityProviders(ctx context.Context, client ecsAPI) {
	var out []asset.Asset
	var token *string
	for {
		page, err := client.DescribeCapacityProviders(ctx, &ecs.DescribeCapacityProvidersInput{NextToken: token})
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("region", sw.region).
				Msg("ecs: capacity providers unavailable (check ecs:DescribeCapacityProviders); not graded this sweep")
			sw.partial = true
			return
		}
		for _, cp := range page.CapacityProviders {
			asg := cp.AutoScalingGroupProvider
			arn := awssdk.ToString(cp.CapacityProviderArn)
			if asg == nil || arn == "" || cp.Status != ecstypes.CapacityProviderStatusActive {
				continue
			}
			// The API documents managed termination protection as off by
			// default, so an omitted value is the observed default.
			mtp := string(asg.ManagedTerminationProtection)
			if mtp == "" {
				mtp = string(ecstypes.ManagedTerminationProtectionDisabled)
			}
			meta := map[string]string{
				"auto_scaling_group":             awssdk.ToString(asg.AutoScalingGroupArn),
				"managed_termination_protection": mtp,
			}
			if ms := asg.ManagedScaling; ms != nil && ms.Status != "" {
				meta["managed_scaling"] = string(ms.Status)
			}
			out = append(out, asset.Asset{
				ID:           arn,
				Name:         awssdk.ToString(cp.Name),
				Type:         "ecs_capacity_provider",
				Provider:     asset.ProviderAWS,
				Region:       sw.region,
				AccountID:    sw.accountID,
				Metadata:     meta,
				DiscoveredAt: sw.now,
				LastSeen:     sw.now,
			})
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	sw.assets = append(sw.assets, out...)
}
