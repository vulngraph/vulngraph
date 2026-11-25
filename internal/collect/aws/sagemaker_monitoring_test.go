package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	smtypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/stretchr/testify/require"
)

type fakeSageMakerMonitoring struct {
	dq          []smtypes.MonitoringJobDefinitionSummary
	dqDesc      map[string]*sagemaker.DescribeDataQualityJobDefinitionOutput
	biasPages   [][]smtypes.MonitoringJobDefinitionSummary
	biasDesc    map[string]*sagemaker.DescribeModelBiasJobDefinitionOutput
	qualityErr  error
	schedules   []smtypes.MonitoringScheduleSummary
	schedDesc   map[string]*sagemaker.DescribeMonitoringScheduleOutput
	groups      []smtypes.FeatureGroupSummary
	groupDesc   map[string]*sagemaker.DescribeFeatureGroupOutput
	explainList []smtypes.MonitoringJobDefinitionSummary
}

func (f *fakeSageMakerMonitoring) ListDataQualityJobDefinitions(context.Context, *sagemaker.ListDataQualityJobDefinitionsInput, ...func(*sagemaker.Options)) (*sagemaker.ListDataQualityJobDefinitionsOutput, error) {
	return &sagemaker.ListDataQualityJobDefinitionsOutput{JobDefinitionSummaries: f.dq}, nil
}

func (f *fakeSageMakerMonitoring) DescribeDataQualityJobDefinition(_ context.Context, in *sagemaker.DescribeDataQualityJobDefinitionInput, _ ...func(*sagemaker.Options)) (*sagemaker.DescribeDataQualityJobDefinitionOutput, error) {
	if d, ok := f.dqDesc[*in.JobDefinitionName]; ok {
		return d, nil
	}
	return nil, errors.New("AccessDeniedException")
}

func (f *fakeSageMakerMonitoring) ListModelBiasJobDefinitions(_ context.Context, in *sagemaker.ListModelBiasJobDefinitionsInput, _ ...func(*sagemaker.Options)) (*sagemaker.ListModelBiasJobDefinitionsOutput, error) {
	i := 0
	if in.NextToken != nil {
		i = 1
	}
	out := &sagemaker.ListModelBiasJobDefinitionsOutput{}
	if i < len(f.biasPages) {
		out.JobDefinitionSummaries = f.biasPages[i]
	}
	if i == 0 && len(f.biasPages) > 1 {
		out.NextToken = awssdk.String("p2")
	}
	return out, nil
}

func (f *fakeSageMakerMonitoring) DescribeModelBiasJobDefinition(_ context.Context, in *sagemaker.DescribeModelBiasJobDefinitionInput, _ ...func(*sagemaker.Options)) (*sagemaker.DescribeModelBiasJobDefinitionOutput, error) {
	return f.biasDesc[*in.JobDefinitionName], nil
}

func (f *fakeSageMakerMonitoring) ListModelQualityJobDefinitions(context.Context, *sagemaker.ListModelQualityJobDefinitionsInput, ...func(*sagemaker.Options)) (*sagemaker.ListModelQualityJobDefinitionsOutput, error) {
	if f.qualityErr != nil {
		return nil, f.qualityErr
	}
	return &sagemaker.ListModelQualityJobDefinitionsOutput{}, nil
}

func (f *fakeSageMakerMonitoring) DescribeModelQualityJobDefinition(context.Context, *sagemaker.DescribeModelQualityJobDefinitionInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeModelQualityJobDefinitionOutput, error) {
	return &sagemaker.DescribeModelQualityJobDefinitionOutput{}, nil
}

func (f *fakeSageMakerMonitoring) ListModelExplainabilityJobDefinitions(context.Context, *sagemaker.ListModelExplainabilityJobDefinitionsInput, ...func(*sagemaker.Options)) (*sagemaker.ListModelExplainabilityJobDefinitionsOutput, error) {
	return &sagemaker.ListModelExplainabilityJobDefinitionsOutput{JobDefinitionSummaries: f.explainList}, nil
}

func (f *fakeSageMakerMonitoring) DescribeModelExplainabilityJobDefinition(context.Context, *sagemaker.DescribeModelExplainabilityJobDefinitionInput, ...func(*sagemaker.Options)) (*sagemaker.DescribeModelExplainabilityJobDefinitionOutput, error) {
	// Created with no NetworkConfig at all.
	return &sagemaker.DescribeModelExplainabilityJobDefinitionOutput{}, nil
}

func (f *fakeSageMakerMonitoring) ListMonitoringSchedules(context.Context, *sagemaker.ListMonitoringSchedulesInput, ...func(*sagemaker.Options)) (*sagemaker.ListMonitoringSchedulesOutput, error) {
	return &sagemaker.ListMonitoringSchedulesOutput{MonitoringScheduleSummaries: f.schedules}, nil
}

func (f *fakeSageMakerMonitoring) DescribeMonitoringSchedule(_ context.Context, in *sagemaker.DescribeMonitoringScheduleInput, _ ...func(*sagemaker.Options)) (*sagemaker.DescribeMonitoringScheduleOutput, error) {
	return f.schedDesc[*in.MonitoringScheduleName], nil
}

func (f *fakeSageMakerMonitoring) ListFeatureGroups(context.Context, *sagemaker.ListFeatureGroupsInput, ...func(*sagemaker.Options)) (*sagemaker.ListFeatureGroupsOutput, error) {
	return &sagemaker.ListFeatureGroupsOutput{FeatureGroupSummaries: f.groups}, nil
}

func (f *fakeSageMakerMonitoring) DescribeFeatureGroup(_ context.Context, in *sagemaker.DescribeFeatureGroupInput, _ ...func(*sagemaker.Options)) (*sagemaker.DescribeFeatureGroupOutput, error) {
	return f.groupDesc[*in.FeatureGroupName], nil
}

func jobSummary(name string) smtypes.MonitoringJobDefinitionSummary {
	return smtypes.MonitoringJobDefinitionSummary{MonitoringJobDefinitionArn: awssdk.String("arn:" + name), MonitoringJobDefinitionName: awssdk.String(name)}
}

func TestReadSageMakerMonitoring(t *testing.T) {
	f := &fakeSageMakerMonitoring{
		dq: []smtypes.MonitoringJobDefinitionSummary{jobSummary("dq-ok"), jobSummary("dq-denied")},
		dqDesc: map[string]*sagemaker.DescribeDataQualityJobDefinitionOutput{
			"dq-ok": {NetworkConfig: &smtypes.MonitoringNetworkConfig{EnableNetworkIsolation: awssdk.Bool(true), EnableInterContainerTrafficEncryption: awssdk.Bool(true)}},
		},
		biasPages: [][]smtypes.MonitoringJobDefinitionSummary{{jobSummary("bias-1")}, {jobSummary("bias-2")}},
		biasDesc: map[string]*sagemaker.DescribeModelBiasJobDefinitionOutput{
			"bias-1": {JobResources: &smtypes.MonitoringResources{ClusterConfig: &smtypes.MonitoringClusterConfig{InstanceCount: awssdk.Int32(2)}},
				NetworkConfig: &smtypes.MonitoringNetworkConfig{EnableNetworkIsolation: awssdk.Bool(false)}},
			"bias-2": {},
		},
		explainList: []smtypes.MonitoringJobDefinitionSummary{jobSummary("ex-1")},
		schedules: []smtypes.MonitoringScheduleSummary{
			{MonitoringScheduleArn: awssdk.String("arn:s-inline"), MonitoringScheduleName: awssdk.String("s-inline")},
			{MonitoringScheduleArn: awssdk.String("arn:s-ref"), MonitoringScheduleName: awssdk.String("s-ref")},
		},
		schedDesc: map[string]*sagemaker.DescribeMonitoringScheduleOutput{
			"s-inline": {MonitoringScheduleConfig: &smtypes.MonitoringScheduleConfig{MonitoringJobDefinition: &smtypes.MonitoringJobDefinition{}}},
			"s-ref":    {MonitoringScheduleConfig: &smtypes.MonitoringScheduleConfig{MonitoringJobDefinitionName: awssdk.String("dq-ok")}},
		},
		groups: []smtypes.FeatureGroupSummary{
			{FeatureGroupArn: awssdk.String("arn:fg-online"), FeatureGroupName: awssdk.String("fg-online")},
			{FeatureGroupArn: awssdk.String("arn:fg-sse"), FeatureGroupName: awssdk.String("fg-sse")},
			{FeatureGroupArn: awssdk.String("arn:fg-kms"), FeatureGroupName: awssdk.String("fg-kms")},
		},
		groupDesc: map[string]*sagemaker.DescribeFeatureGroupOutput{
			"fg-online": {},
			"fg-sse":    {OfflineStoreConfig: &smtypes.OfflineStoreConfig{S3StorageConfig: &smtypes.S3StorageConfig{S3Uri: awssdk.String("s3://b")}}},
			"fg-kms":    {OfflineStoreConfig: &smtypes.OfflineStoreConfig{S3StorageConfig: &smtypes.S3StorageConfig{KmsKeyId: awssdk.String("arn:kms")}}},
		},
	}
	got, err := readSageMakerMonitoring(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	m := smByID(got)
	require.Len(t, got, 10)

	require.Equal(t, map[string]string{"job_type": "data_quality", "network_isolation": "true", "inter_container_encryption": "true"}, m["arn:dq-ok"].Metadata)
	require.Equal(t, map[string]string{"job_type": "data_quality"}, m["arn:dq-denied"].Metadata, "a failed describe keeps only the job type")
	require.Equal(t, map[string]string{"job_type": "model_bias", "network_isolation": "false", "inter_container_encryption": "false", "instance_count": "2"}, m["arn:bias-1"].Metadata)
	require.Equal(t, "false", m["arn:bias-2"].Metadata["network_isolation"], "a definition created without NetworkConfig has both flags off")
	require.Equal(t, "model_explainability", m["arn:ex-1"].Metadata["job_type"])
	require.Equal(t, "sagemaker_monitoring_job_definition", m["arn:ex-1"].Type)

	require.Equal(t, map[string]string{"job_definition_inline": "true", "network_isolation": "false", "inter_container_encryption": "false"}, m["arn:s-inline"].Metadata)
	require.Equal(t, map[string]string{"job_definition_inline": "false"}, m["arn:s-ref"].Metadata)

	require.Equal(t, map[string]string{"offline_store": "false"}, m["arn:fg-online"].Metadata)
	require.Equal(t, map[string]string{"offline_store": "true", "offline_store_kms_key": ""}, m["arn:fg-sse"].Metadata)
	require.Equal(t, "arn:kms", m["arn:fg-kms"].Metadata["offline_store_kms_key"])
}

func TestReadSageMakerMonitoringListingFailure(t *testing.T) {
	got, err := readSageMakerMonitoring(context.Background(), &fakeSageMakerMonitoring{qualityErr: errors.New("ThrottlingException")}, "eu-west-1", "111", time.Now())
	require.Error(t, err)
	require.Nil(t, got)
}
