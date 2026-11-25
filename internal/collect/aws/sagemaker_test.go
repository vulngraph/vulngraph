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

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeSageMaker struct {
	notebookPages [][]smtypes.NotebookInstanceSummary
	notebooks     map[string]*sagemaker.DescribeNotebookInstanceOutput
	models        []smtypes.ModelSummary
	modelDescs    map[string]*sagemaker.DescribeModelOutput
	configs       []smtypes.EndpointConfigSummary
	configDescs   map[string]*sagemaker.DescribeEndpointConfigOutput
	listModelsErr error
}

func (f *fakeSageMaker) ListNotebookInstances(_ context.Context, in *sagemaker.ListNotebookInstancesInput, _ ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error) {
	i := 0
	if in.NextToken != nil {
		i = int((*in.NextToken)[0] - '0')
	}
	out := &sagemaker.ListNotebookInstancesOutput{}
	if i < len(f.notebookPages) {
		out.NotebookInstances = f.notebookPages[i]
	}
	if i+1 < len(f.notebookPages) {
		out.NextToken = awssdk.String(string(rune('0' + i + 1)))
	}
	return out, nil
}

func (f *fakeSageMaker) DescribeNotebookInstance(_ context.Context, in *sagemaker.DescribeNotebookInstanceInput, _ ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error) {
	if d, ok := f.notebooks[*in.NotebookInstanceName]; ok {
		return d, nil
	}
	return nil, errors.New("AccessDeniedException")
}

func (f *fakeSageMaker) ListModels(context.Context, *sagemaker.ListModelsInput, ...func(*sagemaker.Options)) (*sagemaker.ListModelsOutput, error) {
	if f.listModelsErr != nil {
		return nil, f.listModelsErr
	}
	return &sagemaker.ListModelsOutput{Models: f.models}, nil
}

func (f *fakeSageMaker) DescribeModel(_ context.Context, in *sagemaker.DescribeModelInput, _ ...func(*sagemaker.Options)) (*sagemaker.DescribeModelOutput, error) {
	if d, ok := f.modelDescs[*in.ModelName]; ok {
		return d, nil
	}
	return nil, errors.New("ThrottlingException")
}

func (f *fakeSageMaker) ListEndpointConfigs(context.Context, *sagemaker.ListEndpointConfigsInput, ...func(*sagemaker.Options)) (*sagemaker.ListEndpointConfigsOutput, error) {
	return &sagemaker.ListEndpointConfigsOutput{EndpointConfigs: f.configs}, nil
}

func (f *fakeSageMaker) DescribeEndpointConfig(_ context.Context, in *sagemaker.DescribeEndpointConfigInput, _ ...func(*sagemaker.Options)) (*sagemaker.DescribeEndpointConfigOutput, error) {
	return f.configDescs[*in.EndpointConfigName], nil
}

func smByID(as []asset.Asset) map[string]asset.Asset {
	m := map[string]asset.Asset{}
	for _, a := range as {
		m[a.ID] = a
	}
	return m
}

func TestReadSageMaker(t *testing.T) {
	f := &fakeSageMaker{
		notebookPages: [][]smtypes.NotebookInstanceSummary{
			{{NotebookInstanceArn: awssdk.String("arn:nb1"), NotebookInstanceName: awssdk.String("nb1")}},
			{{NotebookInstanceArn: awssdk.String("arn:nb2"), NotebookInstanceName: awssdk.String("nb2")},
				{NotebookInstanceArn: awssdk.String("arn:nb3"), NotebookInstanceName: awssdk.String("nb3")}},
		},
		notebooks: map[string]*sagemaker.DescribeNotebookInstanceOutput{
			// No VPC: SubnetId omitted, direct internet on, root on, old platform.
			"nb1": {DirectInternetAccess: smtypes.DirectInternetAccessEnabled, RootAccess: smtypes.RootAccessEnabled,
				PlatformIdentifier: awssdk.String("notebook-al2-v2"), NotebookInstanceStatus: smtypes.NotebookInstanceStatusInService},
			"nb2": {DirectInternetAccess: smtypes.DirectInternetAccessDisabled, RootAccess: smtypes.RootAccessDisabled, KmsKeyId: awssdk.String("arn:kms:nb"),
				SubnetId: awssdk.String("subnet-1"), PlatformIdentifier: awssdk.String("notebook-al2023-v1")},
			// nb3: describe denied → asset emitted with no settings.
		},
		models: []smtypes.ModelSummary{
			{ModelArn: awssdk.String("arn:m1"), ModelName: awssdk.String("m1")},
			{ModelArn: awssdk.String("arn:m2"), ModelName: awssdk.String("m2")},
			{ModelArn: awssdk.String("arn:m3"), ModelName: awssdk.String("m3")},
			{ModelArn: awssdk.String("arn:m4"), ModelName: awssdk.String("m4")},
		},
		modelDescs: map[string]*sagemaker.DescribeModelOutput{
			"m1": {EnableNetworkIsolation: awssdk.Bool(false), PrimaryContainer: &smtypes.ContainerDefinition{Image: awssdk.String("img")}},
			"m2": {EnableNetworkIsolation: awssdk.Bool(true), PrimaryContainer: &smtypes.ContainerDefinition{
				ImageConfig: &smtypes.ImageConfig{RepositoryAccessMode: smtypes.RepositoryAccessModeVpc}}},
			"m3": {EnableNetworkIsolation: awssdk.Bool(true), Containers: []smtypes.ContainerDefinition{
				{ContainerHostname: awssdk.String("pre"), ImageConfig: &smtypes.ImageConfig{RepositoryAccessMode: smtypes.RepositoryAccessModeVpc}},
				{ImageConfig: &smtypes.ImageConfig{RepositoryAccessMode: smtypes.RepositoryAccessModePlatform}},
				{ContainerHostname: awssdk.String("post")},
			}},
			// m4: describe throttled.
		},
		configs: []smtypes.EndpointConfigSummary{
			{EndpointConfigArn: awssdk.String("arn:c1"), EndpointConfigName: awssdk.String("c1")},
			{EndpointConfigArn: awssdk.String("arn:c2"), EndpointConfigName: awssdk.String("c2")},
		},
		configDescs: map[string]*sagemaker.DescribeEndpointConfigOutput{
			"c1": {ProductionVariants: []smtypes.ProductionVariant{
				{VariantName: awssdk.String("a"), InitialInstanceCount: awssdk.Int32(1)},
				{VariantName: awssdk.String("b"), InitialInstanceCount: awssdk.Int32(2)},
				{VariantName: awssdk.String("srv"), ServerlessConfig: &smtypes.ProductionVariantServerlessConfig{}},
				{VariantName: awssdk.String("ic")},
			}},
			"c2": {ProductionVariants: []smtypes.ProductionVariant{{VariantName: awssdk.String("x"), InitialInstanceCount: awssdk.Int32(3)}}},
		},
	}
	got, err := readSageMaker(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 9, "every listed resource, across pages, is emitted — a failed describe included")
	m := smByID(got)

	nb1 := m["arn:nb1"].Metadata
	require.Equal(t, "sagemaker_notebook", m["arn:nb1"].Type)
	require.Equal(t, map[string]string{"subnet_id": "", "kms_key_id": "", "status": "InService", "direct_internet_access": "true",
		"root_access": "true", "platform_identifier": "notebook-al2-v2"}, nb1)
	require.Equal(t, "false", m["arn:nb2"].Metadata["direct_internet_access"])
	require.Equal(t, "subnet-1", m["arn:nb2"].Metadata["subnet_id"])
	require.Equal(t, "arn:kms:nb", m["arn:nb2"].Metadata["kms_key_id"])
	require.Empty(t, m["arn:nb3"].Metadata, "a denied describe leaves every setting unknown")

	require.Equal(t, map[string]string{"network_isolation": "false", "primary_image_access_mode": ""}, m["arn:m1"].Metadata,
		"a primary container with no ImageConfig is observed as not VPC-pulled")
	require.Equal(t, "Vpc", m["arn:m2"].Metadata["primary_image_access_mode"])
	require.Equal(t, "container-2,post", m["arn:m3"].Metadata["pipeline_containers_not_vpc_registry"])
	_, hasPrimary := m["arn:m3"].Metadata["primary_image_access_mode"]
	require.False(t, hasPrimary, "a pipeline has no primary container")
	require.Empty(t, m["arn:m4"].Metadata)

	require.Equal(t, "a", m["arn:c1"].Metadata["single_instance_variants"], "serverless and inference-component variants are not instance-based")
	require.Equal(t, "", m["arn:c2"].Metadata["single_instance_variants"])
}

func TestReadSageMakerListingFailureFailsTheCall(t *testing.T) {
	f := &fakeSageMaker{listModelsErr: errors.New("ThrottlingException")}
	got, err := readSageMaker(context.Background(), f, "eu-west-1", "111", time.Now())
	require.Error(t, err, "a failed listing must never read as an account with no models")
	require.Nil(t, got)
}

func TestReadSageMakerUnusedServiceEmitsNothing(t *testing.T) {
	got, err := readSageMaker(context.Background(), &fakeSageMaker{}, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestModelMetadataSingleContainerListIsPrimary(t *testing.T) {
	md := modelMetadata(&sagemaker.DescribeModelOutput{Containers: []smtypes.ContainerDefinition{
		{ImageConfig: &smtypes.ImageConfig{RepositoryAccessMode: smtypes.RepositoryAccessModePlatform}}}})
	require.Equal(t, map[string]string{"primary_image_access_mode": "Platform"}, md,
		"nil EnableNetworkIsolation stays unknown; one Containers entry is the primary container, not a pipeline")
}

func TestStampSageMakerNotebookVPC(t *testing.T) {
	as := []asset.Asset{
		{ID: "subnet-d", Type: "subnet", Provider: asset.ProviderAWS, Metadata: map[string]string{"vpc_id": "vpc-d"}},
		{ID: "subnet-c", Type: "subnet", Provider: asset.ProviderAWS, Metadata: map[string]string{"vpc_id": "vpc-c"}},
		{ID: "vpc-d", Type: "vpc", Provider: asset.ProviderAWS, Metadata: map[string]string{"is_default": "true"}},
		{ID: "vpc-c", Type: "vpc", Provider: asset.ProviderAWS, Metadata: map[string]string{"is_default": "false"}},
		{ID: "nb-d", Type: "sagemaker_notebook", Metadata: map[string]string{"subnet_id": "subnet-d"}},
		{ID: "nb-c", Type: "sagemaker_notebook", Metadata: map[string]string{"subnet_id": "subnet-c"}},
		{ID: "nb-x", Type: "sagemaker_notebook", Metadata: map[string]string{"subnet_id": "subnet-gone"}},
		{ID: "nb-n", Type: "sagemaker_notebook", Metadata: map[string]string{"subnet_id": ""}},
	}
	stampSageMakerNotebookVPC(as)
	m := smByID(as)
	require.Equal(t, "true", m["nb-d"].Metadata["in_default_vpc"])
	require.Equal(t, "false", m["nb-c"].Metadata["in_default_vpc"])
	_, ok := m["nb-x"].Metadata["in_default_vpc"]
	require.False(t, ok, "a subnet missing from the sweep leaves the VPC unknown")
	_, ok = m["nb-n"].Metadata["in_default_vpc"]
	require.False(t, ok)
}

func TestDescribeAllRecoversPanics(t *testing.T) {
	rs := []listedResource{{name: "a"}, {name: "b"}}
	out := describeAll(context.Background(), "r", "x:Describe", rs, func(r listedResource) (map[string]string, error) {
		if r.name == "a" {
			panic("boom")
		}
		return map[string]string{"k": "v"}, nil
	})
	require.Nil(t, out[0])
	require.Equal(t, "v", out[1]["k"])
}
