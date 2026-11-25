package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	astypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

type fakeAutoScaling struct {
	groupPages [][]astypes.AutoScalingGroup
	groupCall  int
	groupsErr  error
	lcs        []astypes.LaunchConfiguration
	lcErr      error
}

func (f *fakeAutoScaling) DescribeAutoScalingGroups(context.Context, *autoscaling.DescribeAutoScalingGroupsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error) {
	if f.groupsErr != nil {
		return nil, f.groupsErr
	}
	f.groupCall++
	out := &autoscaling.DescribeAutoScalingGroupsOutput{}
	if f.groupCall <= len(f.groupPages) {
		out.AutoScalingGroups = f.groupPages[f.groupCall-1]
	}
	if f.groupCall < len(f.groupPages) {
		out.NextToken = awssdk.String("next")
	}
	return out, nil
}

func (f *fakeAutoScaling) DescribeLaunchConfigurations(context.Context, *autoscaling.DescribeLaunchConfigurationsInput, ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error) {
	if f.lcErr != nil {
		return nil, f.lcErr
	}
	return &autoscaling.DescribeLaunchConfigurationsOutput{LaunchConfigurations: f.lcs}, nil
}

func TestReadAutoScaling(t *testing.T) {
	f := &fakeAutoScaling{
		groupPages: [][]astypes.AutoScalingGroup{
			{{AutoScalingGroupName: awssdk.String("web"), AutoScalingGroupARN: awssdk.String("arn:asg:web"),
				HealthCheckType: awssdk.String("EC2"), TargetGroupARNs: []string{"arn:tg"},
				AvailabilityZones: []string{"r-1a"}, LaunchConfigurationName: awssdk.String("lc-old")}},
			{{AutoScalingGroupName: awssdk.String("batch"), HealthCheckType: awssdk.String("EC2"),
				AvailabilityZones: []string{"r-1a", "r-1b"},
				MixedInstancesPolicy: &astypes.MixedInstancesPolicy{LaunchTemplate: &astypes.LaunchTemplate{
					LaunchTemplateSpecification: &astypes.LaunchTemplateSpecification{LaunchTemplateId: awssdk.String("lt-1")},
					Overrides:                   []astypes.LaunchTemplateOverrides{{InstanceType: awssdk.String("m5.large")}, {InstanceType: awssdk.String("m6i.large")}},
				}}}},
		},
		lcs: []astypes.LaunchConfiguration{
			{LaunchConfigurationName: awssdk.String("lc-old"), LaunchConfigurationARN: awssdk.String("arn:lc:old"),
				AssociatePublicIpAddress: awssdk.Bool(true)},
			{LaunchConfigurationName: awssdk.String("lc-v2"), LaunchConfigurationARN: awssdk.String("arn:lc:v2"),
				MetadataOptions: &astypes.InstanceMetadataOptions{HttpTokens: astypes.InstanceMetadataHttpTokensStateRequired}},
		},
	}
	got, err := readAutoScaling(context.Background(), f, "r", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 4)

	web := got[0]
	require.Equal(t, "autoscaling_group", web.Type)
	require.Equal(t, "arn:asg:web", web.ID)
	require.Equal(t, "true", web.Metadata["load_balanced"])
	require.Equal(t, "EC2", web.Metadata["health_check_type"])
	require.Equal(t, "1", web.Metadata["availability_zone_count"])
	require.Equal(t, launchSourceConfiguration, web.Metadata["launch_source"])
	require.Equal(t, "false", web.Metadata["multiple_instance_types"])

	batch := got[1]
	require.Contains(t, batch.ID, ":autoScalingGroup:batch", "an ARN is synthesised when the response omits it")
	require.Equal(t, "false", batch.Metadata["load_balanced"])
	require.Equal(t, launchSourceMixedPolicy, batch.Metadata["launch_source"])
	require.Equal(t, "true", batch.Metadata["multiple_instance_types"])

	old, v2 := got[2], got[3]
	require.Equal(t, "autoscaling_launch_configuration", old.Type)
	require.Equal(t, "1", old.Metadata["auto_scaling_group_count"])
	require.Equal(t, "", old.Metadata["http_tokens"], "no metadata options is an observed unset, which AutoScaling.3 fails")
	require.Equal(t, "true", old.Metadata["associate_public_ip"])
	require.Equal(t, "0", v2.Metadata["auto_scaling_group_count"])
	require.Equal(t, "required", v2.Metadata["http_tokens"])
	require.Equal(t, "false", v2.Metadata["associate_public_ip"])
}

func TestReadAutoScaling_EitherListingFailingFailsTheRead(t *testing.T) {
	_, err := readAutoScaling(context.Background(), &fakeAutoScaling{groupsErr: errors.New("denied")}, "r", "1", time.Now())
	require.Error(t, err)
	_, err = readAutoScaling(context.Background(), &fakeAutoScaling{lcErr: errors.New("denied")}, "r", "1", time.Now())
	require.Error(t, err, "configurations whose usage could not be counted are not emitted as unused")
}

func TestMultipleInstanceTypes(t *testing.T) {
	lt := func(o ...astypes.LaunchTemplateOverrides) *astypes.MixedInstancesPolicy {
		return &astypes.MixedInstancesPolicy{LaunchTemplate: &astypes.LaunchTemplate{Overrides: o}}
	}
	require.False(t, multipleInstanceTypes(nil))
	require.False(t, multipleInstanceTypes(lt()))
	require.False(t, multipleInstanceTypes(lt(astypes.LaunchTemplateOverrides{InstanceType: awssdk.String("m5.large")},
		astypes.LaunchTemplateOverrides{InstanceType: awssdk.String("m5.large")})), "one distinct type")
	require.True(t, multipleInstanceTypes(lt(astypes.LaunchTemplateOverrides{InstanceRequirements: &astypes.InstanceRequirements{}})),
		"attribute-based selection matches a family of types")
}

type fakeLaunchTemplates struct {
	versions  []ec2types.LaunchTemplateVersion
	err       error
	fleets    []ec2types.SpotFleetRequestConfig
	versionIn *ec2.DescribeLaunchTemplateVersionsInput
}

func (f *fakeLaunchTemplates) DescribeLaunchTemplateVersions(_ context.Context, in *ec2.DescribeLaunchTemplateVersionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeLaunchTemplateVersionsOutput, error) {
	f.versionIn = in
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeLaunchTemplateVersionsOutput{LaunchTemplateVersions: f.versions}, nil
}

func (f *fakeLaunchTemplates) DescribeSpotFleetRequests(context.Context, *ec2.DescribeSpotFleetRequestsInput, ...func(*ec2.Options)) (*ec2.DescribeSpotFleetRequestsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeSpotFleetRequestsOutput{SpotFleetRequestConfigs: f.fleets}, nil
}

func TestReadLaunchTemplates(t *testing.T) {
	f := &fakeLaunchTemplates{versions: []ec2types.LaunchTemplateVersion{
		{LaunchTemplateId: awssdk.String("lt-1"), LaunchTemplateName: awssdk.String("web"), VersionNumber: awssdk.Int64(3),
			LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{
				NetworkInterfaces: []ec2types.LaunchTemplateInstanceNetworkInterfaceSpecification{
					{AssociatePublicIpAddress: awssdk.Bool(true)}, {AssociatePublicIpAddress: awssdk.Bool(false)}, {}},
				MetadataOptions: &ec2types.LaunchTemplateInstanceMetadataOptions{HttpTokens: ec2types.LaunchTemplateHttpTokensStateOptional},
				BlockDeviceMappings: []ec2types.LaunchTemplateBlockDeviceMapping{
					{Ebs: &ec2types.LaunchTemplateEbsBlockDevice{Encrypted: awssdk.Bool(false)}},
					{Ebs: &ec2types.LaunchTemplateEbsBlockDevice{}}, // omitted: inherits the default
					{VirtualName: awssdk.String("ephemeral0")},
				},
			}},
		{LaunchTemplateId: awssdk.String("lt-2"), LaunchTemplateName: awssdk.String("batch"), VersionNumber: awssdk.Int64(1),
			LaunchTemplateData: &ec2types.ResponseLaunchTemplateData{}},
	}}
	asg := &fakeAutoScaling{groupPages: [][]astypes.AutoScalingGroup{{
		{LaunchTemplate: &astypes.LaunchTemplateSpecification{LaunchTemplateName: awssdk.String("batch")}},
		{LaunchTemplate: &astypes.LaunchTemplateSpecification{LaunchTemplateId: awssdk.String("lt-2")}},
	}}}
	got, err := readLaunchTemplates(context.Background(), f, asg, "r", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, []string{"$Default"}, f.versionIn.Versions, "the default version is the one graded")
	require.Len(t, got, 2)
	require.Equal(t, map[string]string{"public_ip_interfaces": "1", "unencrypted_ebs_volumes": "1", "http_tokens": "optional",
		"default_version": "3", "auto_scaling_group_count": "0"}, got[0].Metadata)
	require.Equal(t, "", got[1].Metadata["http_tokens"], "unset metadata options is observed")
	require.Equal(t, "2", got[1].Metadata["auto_scaling_group_count"], "groups reference a template by name or id")

	asg = &fakeAutoScaling{groupsErr: errors.New("denied")}
	got, err = readLaunchTemplates(context.Background(), f, asg, "r", "1", time.Now())
	require.NoError(t, err, "the templates are real even when their usage is unread")
	require.NotContains(t, got[0].Metadata, "auto_scaling_group_count")

	_, err = readLaunchTemplates(context.Background(), &fakeLaunchTemplates{err: errors.New("denied")}, asg, "r", "1", time.Now())
	require.Error(t, err)
}

func TestReadSpotFleetRequests(t *testing.T) {
	spec := func(enc *bool) ec2types.SpotFleetLaunchSpecification {
		return ec2types.SpotFleetLaunchSpecification{BlockDeviceMappings: []ec2types.BlockDeviceMapping{{Ebs: &ec2types.EbsBlockDevice{Encrypted: enc}}}}
	}
	f := &fakeLaunchTemplates{fleets: []ec2types.SpotFleetRequestConfig{
		{SpotFleetRequestId: awssdk.String("sfr-bad"), SpotFleetRequestState: ec2types.BatchStateActive,
			SpotFleetRequestConfig: &ec2types.SpotFleetRequestConfigData{LaunchSpecifications: []ec2types.SpotFleetLaunchSpecification{
				spec(awssdk.Bool(false)), spec(nil), spec(awssdk.Bool(true))}}},
		{SpotFleetRequestId: awssdk.String("sfr-lt"), SpotFleetRequestState: ec2types.BatchStateActive,
			SpotFleetRequestConfig: &ec2types.SpotFleetRequestConfigData{}},
		{SpotFleetRequestId: awssdk.String("sfr-old"), SpotFleetRequestState: ec2types.BatchStateCancelled,
			SpotFleetRequestConfig: &ec2types.SpotFleetRequestConfigData{LaunchSpecifications: []ec2types.SpotFleetLaunchSpecification{spec(awssdk.Bool(false))}}},
	}}
	got, err := readSpotFleetRequests(context.Background(), f, "r", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2, "a cancelled request launches nothing")
	require.Equal(t, "1", got[0].Metadata["unencrypted_ebs_volumes"], "only an explicit Encrypted=false counts")
	require.Equal(t, "3", got[0].Metadata["launch_specification_count"])
	require.Equal(t, "0", got[1].Metadata["launch_specification_count"])
}
