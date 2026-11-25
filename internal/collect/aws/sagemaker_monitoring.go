package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	smtypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// SageMaker Model Monitor job definitions and schedules, and Feature Store
// feature groups (AWS FSBP SageMaker.9-15, .17).

// Values of the sagemaker_monitoring_job_definition `job_type` key.
const (
	smJobDataQuality         = "data_quality"
	smJobModelBias           = "model_bias"
	smJobModelQuality        = "model_quality"
	smJobModelExplainability = "model_explainability"
)

type sageMakerMonitoringAPI interface {
	ListDataQualityJobDefinitions(context.Context, *sagemaker.ListDataQualityJobDefinitionsInput, ...func(*sagemaker.Options)) (*sagemaker.ListDataQualityJobDefinitionsOutput, error)
	DescribeDataQualityJobDefinition(context.Context, *sagemaker.DescribeDataQualityJobDefinitionInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeDataQualityJobDefinitionOutput, error)
	ListModelBiasJobDefinitions(context.Context, *sagemaker.ListModelBiasJobDefinitionsInput, ...func(*sagemaker.Options)) (*sagemaker.ListModelBiasJobDefinitionsOutput, error)
	DescribeModelBiasJobDefinition(context.Context, *sagemaker.DescribeModelBiasJobDefinitionInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeModelBiasJobDefinitionOutput, error)
	ListModelQualityJobDefinitions(context.Context, *sagemaker.ListModelQualityJobDefinitionsInput, ...func(*sagemaker.Options)) (*sagemaker.ListModelQualityJobDefinitionsOutput, error)
	DescribeModelQualityJobDefinition(context.Context, *sagemaker.DescribeModelQualityJobDefinitionInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeModelQualityJobDefinitionOutput, error)
	ListModelExplainabilityJobDefinitions(context.Context, *sagemaker.ListModelExplainabilityJobDefinitionsInput, ...func(*sagemaker.Options)) (*sagemaker.ListModelExplainabilityJobDefinitionsOutput, error)
	DescribeModelExplainabilityJobDefinition(context.Context, *sagemaker.DescribeModelExplainabilityJobDefinitionInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeModelExplainabilityJobDefinitionOutput, error)
	ListMonitoringSchedules(context.Context, *sagemaker.ListMonitoringSchedulesInput, ...func(*sagemaker.Options)) (*sagemaker.ListMonitoringSchedulesOutput, error)
	DescribeMonitoringSchedule(context.Context, *sagemaker.DescribeMonitoringScheduleInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeMonitoringScheduleOutput, error)
	ListFeatureGroups(context.Context, *sagemaker.ListFeatureGroupsInput, ...func(*sagemaker.Options)) (*sagemaker.ListFeatureGroupsOutput, error)
	DescribeFeatureGroup(context.Context, *sagemaker.DescribeFeatureGroupInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeFeatureGroupOutput, error)
}

func collectSageMakerMonitoring(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSageMakerMonitoring: %w", err)
	}
	return readSageMakerMonitoring(ctx, sagemaker.NewFromConfig(awsCfg), region, accountID, now)
}

// monitoringJobType is one Model Monitor job-definition family: how to list
// it and how to read one definition's network settings.
type monitoringJobType struct {
	jobType  string
	action   string
	list     func(ctx context.Context, next *string) ([]smtypes.MonitoringJobDefinitionSummary, *string, error)
	describe func(ctx context.Context, name string) (*smtypes.MonitoringNetworkConfig, *smtypes.MonitoringResources, error)
}

func monitoringJobTypes(client sageMakerMonitoringAPI) []monitoringJobType {
	return []monitoringJobType{
		{smJobDataQuality, "sagemaker:DescribeDataQualityJobDefinition",
			func(ctx context.Context, next *string) ([]smtypes.MonitoringJobDefinitionSummary, *string, error) {
				p, err := client.ListDataQualityJobDefinitions(ctx, &sagemaker.ListDataQualityJobDefinitionsInput{NextToken: next})
				if err != nil {
					return nil, nil, err
				}
				return p.JobDefinitionSummaries, p.NextToken, nil
			},
			func(ctx context.Context, name string) (*smtypes.MonitoringNetworkConfig, *smtypes.MonitoringResources, error) {
				d, err := client.DescribeDataQualityJobDefinition(ctx, &sagemaker.DescribeDataQualityJobDefinitionInput{JobDefinitionName: &name})
				if err != nil {
					return nil, nil, err
				}
				return d.NetworkConfig, d.JobResources, nil
			}},
		{smJobModelBias, "sagemaker:DescribeModelBiasJobDefinition",
			func(ctx context.Context, next *string) ([]smtypes.MonitoringJobDefinitionSummary, *string, error) {
				p, err := client.ListModelBiasJobDefinitions(ctx, &sagemaker.ListModelBiasJobDefinitionsInput{NextToken: next})
				if err != nil {
					return nil, nil, err
				}
				return p.JobDefinitionSummaries, p.NextToken, nil
			},
			func(ctx context.Context, name string) (*smtypes.MonitoringNetworkConfig, *smtypes.MonitoringResources, error) {
				d, err := client.DescribeModelBiasJobDefinition(ctx, &sagemaker.DescribeModelBiasJobDefinitionInput{JobDefinitionName: &name})
				if err != nil {
					return nil, nil, err
				}
				return d.NetworkConfig, d.JobResources, nil
			}},
		{smJobModelQuality, "sagemaker:DescribeModelQualityJobDefinition",
			func(ctx context.Context, next *string) ([]smtypes.MonitoringJobDefinitionSummary, *string, error) {
				p, err := client.ListModelQualityJobDefinitions(ctx, &sagemaker.ListModelQualityJobDefinitionsInput{NextToken: next})
				if err != nil {
					return nil, nil, err
				}
				return p.JobDefinitionSummaries, p.NextToken, nil
			},
			func(ctx context.Context, name string) (*smtypes.MonitoringNetworkConfig, *smtypes.MonitoringResources, error) {
				d, err := client.DescribeModelQualityJobDefinition(ctx, &sagemaker.DescribeModelQualityJobDefinitionInput{JobDefinitionName: &name})
				if err != nil {
					return nil, nil, err
				}
				return d.NetworkConfig, d.JobResources, nil
			}},
		{smJobModelExplainability, "sagemaker:DescribeModelExplainabilityJobDefinition",
			func(ctx context.Context, next *string) ([]smtypes.MonitoringJobDefinitionSummary, *string, error) {
				p, err := client.ListModelExplainabilityJobDefinitions(ctx, &sagemaker.ListModelExplainabilityJobDefinitionsInput{NextToken: next})
				if err != nil {
					return nil, nil, err
				}
				return p.JobDefinitionSummaries, p.NextToken, nil
			},
			func(ctx context.Context, name string) (*smtypes.MonitoringNetworkConfig, *smtypes.MonitoringResources, error) {
				d, err := client.DescribeModelExplainabilityJobDefinition(ctx, &sagemaker.DescribeModelExplainabilityJobDefinitionInput{JobDefinitionName: &name})
				if err != nil {
					return nil, nil, err
				}
				return d.NetworkConfig, d.JobResources, nil
			}},
	}
}

func readSageMakerMonitoring(ctx context.Context, client sageMakerMonitoringAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var out []asset.Asset
	for _, jt := range monitoringJobTypes(client) {
		defs, err := listJobDefinitions(ctx, jt)
		if err != nil {
			return nil, fmt.Errorf("readSageMakerMonitoring: %s: %w", jt.jobType, err)
		}
		mds := describeAll(ctx, region, jt.action, defs, func(r listedResource) (map[string]string, error) {
			nc, res, err := jt.describe(ctx, r.name)
			if err != nil {
				return nil, err
			}
			return jobDefinitionMetadata(jt.jobType, nc, res), nil
		})
		for i := range mds {
			if mds[i] == nil {
				mds[i] = map[string]string{"job_type": jt.jobType}
			}
		}
		out = append(out, listedAssets(mds, defs, "sagemaker_monitoring_job_definition", region, accountID, now)...)
	}

	schedules, err := listMonitoringSchedules(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readSageMakerMonitoring: %w", err)
	}
	mds := describeAll(ctx, region, "sagemaker:DescribeMonitoringSchedule", schedules, func(r listedResource) (map[string]string, error) {
		d, err := client.DescribeMonitoringSchedule(ctx, &sagemaker.DescribeMonitoringScheduleInput{MonitoringScheduleName: &r.name})
		if err != nil {
			return nil, err
		}
		return monitoringScheduleMetadata(d), nil
	})
	out = append(out, listedAssets(mds, schedules, "sagemaker_monitoring_schedule", region, accountID, now)...)

	groups, err := listFeatureGroups(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readSageMakerMonitoring: %w", err)
	}
	mds = describeAll(ctx, region, "sagemaker:DescribeFeatureGroup", groups, func(r listedResource) (map[string]string, error) {
		d, err := client.DescribeFeatureGroup(ctx, &sagemaker.DescribeFeatureGroupInput{FeatureGroupName: &r.name})
		if err != nil {
			return nil, err
		}
		return featureGroupMetadata(d), nil
	})
	return append(out, listedAssets(mds, groups, "sagemaker_feature_group", region, accountID, now)...), nil
}

func listJobDefinitions(ctx context.Context, jt monitoringJobType) ([]listedResource, error) {
	var (
		out  []listedResource
		next *string
	)
	for {
		page, token, err := jt.list(ctx, next)
		if err != nil {
			return nil, fmt.Errorf("listJobDefinitions: %w", err)
		}
		for _, s := range page {
			out = append(out, listedResource{arn: awssdk.ToString(s.MonitoringJobDefinitionArn), name: awssdk.ToString(s.MonitoringJobDefinitionName)})
		}
		if token == nil {
			return out, nil
		}
		next = token
	}
}

func listMonitoringSchedules(ctx context.Context, client sageMakerMonitoringAPI) ([]listedResource, error) {
	var (
		out  []listedResource
		next *string
	)
	for {
		page, err := client.ListMonitoringSchedules(ctx, &sagemaker.ListMonitoringSchedulesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listMonitoringSchedules: %w", err)
		}
		for _, s := range page.MonitoringScheduleSummaries {
			out = append(out, listedResource{arn: awssdk.ToString(s.MonitoringScheduleArn), name: awssdk.ToString(s.MonitoringScheduleName)})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

func listFeatureGroups(ctx context.Context, client sageMakerMonitoringAPI) ([]listedResource, error) {
	var (
		out  []listedResource
		next *string
	)
	for {
		page, err := client.ListFeatureGroups(ctx, &sagemaker.ListFeatureGroupsInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listFeatureGroups: %w", err)
		}
		for _, g := range page.FeatureGroupSummaries {
			out = append(out, listedResource{arn: awssdk.ToString(g.FeatureGroupArn), name: awssdk.ToString(g.FeatureGroupName)})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

// jobDefinitionMetadata reads a described job definition's network settings.
// The API omits NetworkConfig, and each flag inside it, when the definition
// was created without them; both flags default to false, so a successful
// describe with the field absent is an observed "false", not unknown.
func jobDefinitionMetadata(jobType string, nc *smtypes.MonitoringNetworkConfig, res *smtypes.MonitoringResources) map[string]string {
	md := map[string]string{"job_type": jobType}
	var isolation, encryption bool
	if nc != nil {
		isolation = awssdk.ToBool(nc.EnableNetworkIsolation)
		encryption = awssdk.ToBool(nc.EnableInterContainerTrafficEncryption)
	}
	md["network_isolation"] = strconv.FormatBool(isolation)
	md["inter_container_encryption"] = strconv.FormatBool(encryption)
	if res != nil && res.ClusterConfig != nil && res.ClusterConfig.InstanceCount != nil {
		md["instance_count"] = strconv.Itoa(int(*res.ClusterConfig.InstanceCount))
	}
	return md
}

// monitoringScheduleMetadata records whether the schedule carries its own
// (inline) job definition and, if so, that definition's network isolation
// (unset defaults to false, as for job definitions). A schedule that names a
// separately created job definition is graded through that definition.
func monitoringScheduleMetadata(d *sagemaker.DescribeMonitoringScheduleOutput) map[string]string {
	md := map[string]string{}
	if d.MonitoringScheduleConfig == nil {
		return md
	}
	def := d.MonitoringScheduleConfig.MonitoringJobDefinition
	md["job_definition_inline"] = strconv.FormatBool(def != nil)
	if def != nil {
		isolation := def.NetworkConfig != nil && awssdk.ToBool(def.NetworkConfig.EnableNetworkIsolation)
		md["network_isolation"] = strconv.FormatBool(isolation)
		encryption := def.NetworkConfig != nil && awssdk.ToBool(def.NetworkConfig.EnableInterContainerTrafficEncryption)
		md["inter_container_encryption"] = strconv.FormatBool(encryption)
	}
	return md
}

// featureGroupMetadata records whether the group has an offline store and the
// KMS key its S3 storage is encrypted with ("" when none is set, which means
// the bucket's default encryption rather than a KMS key).
func featureGroupMetadata(d *sagemaker.DescribeFeatureGroupOutput) map[string]string {
	md := map[string]string{"offline_store": strconv.FormatBool(d.OfflineStoreConfig != nil)}
	if d.OfflineStoreConfig != nil {
		key := ""
		if s3 := d.OfflineStoreConfig.S3StorageConfig; s3 != nil {
			key = awssdk.ToString(s3.KmsKeyId)
		}
		md["offline_store_kms_key"] = key
	}
	return md
}
