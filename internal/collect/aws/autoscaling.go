package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type autoScalingAPI interface {
	DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
	DescribeLaunchConfigurations(context.Context, *autoscaling.DescribeLaunchConfigurationsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error)
}

// Values of the autoscaling_group `launch_source` key.
const (
	launchSourceTemplate      = "launch_template"
	launchSourceMixedPolicy   = "mixed_instances_policy"
	launchSourceConfiguration = "launch_configuration"
)

func collectAutoScaling(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectAutoScaling: %w", err)
	}
	return readAutoScaling(ctx, autoscaling.NewFromConfig(awsCfg), region, accountID, now)
}

// readAutoScaling emits the region's Auto Scaling groups and launch
// configurations. A launch configuration's `auto_scaling_group_count` comes
// from the group listing in the same call, so both listings must succeed:
// either failing fails the collector rather than emitting configurations
// whose usage reads as zero.
func readAutoScaling(ctx context.Context, client autoScalingAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	groups, err := listAutoScalingGroups(ctx, client, region)
	if err != nil {
		return nil, fmt.Errorf("readAutoScaling: %w", err)
	}
	lcUse := map[string]int{}
	assets := make([]asset.Asset, 0, len(groups))
	for _, g := range groups {
		a := autoScalingGroupAsset(g, region, accountID, now)
		if n := awssdk.ToString(g.LaunchConfigurationName); n != "" {
			lcUse[n]++
		}
		assets = append(assets, a)
	}
	var token *string
	for {
		out, err := client.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("readAutoScaling: DescribeLaunchConfigurations: %w", err)
		}
		for _, lc := range out.LaunchConfigurations {
			name := awssdk.ToString(lc.LaunchConfigurationName)
			if name == "" {
				continue
			}
			id := awssdk.ToString(lc.LaunchConfigurationARN)
			if id == "" {
				id = "arn:" + partitionFor(region) + ":autoscaling:" + region + ":" + accountID + ":launchConfiguration:" + name
			}
			assets = append(assets, asset.Asset{
				ID:           id,
				Name:         name,
				Type:         "autoscaling_launch_configuration",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     launchConfigMeta(lc, lcUse[name]),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}

// listAutoScalingGroups reads the region's groups once per sweep: the group
// collector and the launch-template collector (usage counts) share it.
func listAutoScalingGroups(ctx context.Context, client autoScalingAPI, region string) ([]astypes.AutoScalingGroup, error) {
	return memoized(ctx, "autoscaling:groups:"+region, func() ([]astypes.AutoScalingGroup, error) {
		return pageAutoScalingGroups(ctx, client)
	})
}

func pageAutoScalingGroups(ctx context.Context, client autoScalingAPI) ([]astypes.AutoScalingGroup, error) {
	var (
		groups []astypes.AutoScalingGroup
		token  *string
	)
	for {
		out, err := client.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("DescribeAutoScalingGroups: %w", err)
		}
		groups = append(groups, out.AutoScalingGroups...)
		if out.NextToken == nil {
			return groups, nil
		}
		token = out.NextToken
	}
}

func autoScalingGroupAsset(g astypes.AutoScalingGroup, region, accountID string, now time.Time) asset.Asset {
	name := awssdk.ToString(g.AutoScalingGroupName)
	id := awssdk.ToString(g.AutoScalingGroupARN)
	if id == "" {
		id = "arn:" + partitionFor(region) + ":autoscaling:" + region + ":" + accountID + ":autoScalingGroup:" + name
	}
	meta := map[string]string{
		"health_check_type":       awssdk.ToString(g.HealthCheckType),
		"load_balanced":           strconv.FormatBool(len(g.LoadBalancerNames) > 0 || len(g.TargetGroupARNs) > 0 || hasELBTrafficSource(g.TrafficSources)),
		"availability_zone_count": strconv.Itoa(len(g.AvailabilityZones)),
		"launch_source":           launchSource(g),
	}
	if n := awssdk.ToString(g.LaunchConfigurationName); n != "" {
		meta["launch_configuration_name"] = n
	}
	meta["multiple_instance_types"] = strconv.FormatBool(multipleInstanceTypes(g.MixedInstancesPolicy))
	tags := map[string]string{}
	for _, t := range g.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	if len(tags) == 0 {
		tags = nil
	}
	return asset.Asset{
		ID:           id,
		Name:         name,
		Type:         "autoscaling_group",
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Tags:         tags,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// hasELBTrafficSource reports a load balancer attached through the newer
// traffic-sources API, which a group can use instead of TargetGroupARNs.
func hasELBTrafficSource(sources []astypes.TrafficSourceIdentifier) bool {
	for _, s := range sources {
		switch awssdk.ToString(s.Type) {
		case "elb", "elbv2":
			if awssdk.ToString(s.Identifier) != "" {
				return true
			}
		}
	}
	return false
}

func launchSource(g astypes.AutoScalingGroup) string {
	switch {
	case g.LaunchTemplate != nil:
		return launchSourceTemplate
	case g.MixedInstancesPolicy != nil && g.MixedInstancesPolicy.LaunchTemplate != nil:
		return launchSourceMixedPolicy
	case awssdk.ToString(g.LaunchConfigurationName) != "":
		return launchSourceConfiguration
	}
	return ""
}

// multipleInstanceTypes reports whether the group can launch more than one
// instance type: a mixed instances policy with two or more distinct override
// types, or attribute-based selection (InstanceRequirements), which matches a
// family of types by design. A single launch template or configuration names
// one type.
func multipleInstanceTypes(p *astypes.MixedInstancesPolicy) bool {
	if p == nil || p.LaunchTemplate == nil {
		return false
	}
	types := map[string]bool{}
	for _, o := range p.LaunchTemplate.Overrides {
		if o.InstanceRequirements != nil {
			return true
		}
		if t := awssdk.ToString(o.InstanceType); t != "" {
			types[t] = true
		}
	}
	return len(types) > 1
}

// launchConfigMeta records the instance settings a launch configuration
// imposes. http_tokens is "" when the configuration sets no metadata options:
// FSBP AutoScaling.3 fails that case too, since instances then launch with
// IMDSv1 allowed unless an account default says otherwise.
func launchConfigMeta(lc astypes.LaunchConfiguration, groups int) map[string]string {
	meta := map[string]string{
		"auto_scaling_group_count": strconv.Itoa(groups),
		"http_tokens":              "",
		"associate_public_ip":      strconv.FormatBool(awssdk.ToBool(lc.AssociatePublicIpAddress)),
	}
	if mo := lc.MetadataOptions; mo != nil {
		meta["http_tokens"] = string(mo.HttpTokens)
		if mo.HttpEndpoint != "" {
			meta["http_endpoint"] = string(mo.HttpEndpoint)
		}
	}
	return meta
}

// groupLaunchTemplate returns the launch template a group launches from,
// directly or through its mixed instances policy; nil for a launch
// configuration. The reference may carry the template id, its name or both.
func groupLaunchTemplate(g astypes.AutoScalingGroup) *astypes.LaunchTemplateSpecification {
	if g.LaunchTemplate != nil {
		return g.LaunchTemplate
	}
	if p := g.MixedInstancesPolicy; p != nil && p.LaunchTemplate != nil {
		return p.LaunchTemplate.LaunchTemplateSpecification
	}
	return nil
}
