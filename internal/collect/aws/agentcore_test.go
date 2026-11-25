package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bactypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/stretchr/testify/require"
)

type fakeAgentCore struct {
	runtimes     []bactypes.AgentRuntime
	runtimeDesc  map[string]*bedrockagentcorecontrol.GetAgentRuntimeOutput
	gatewayPages [][]bactypes.GatewaySummary
	browsers     []bactypes.BrowserSummary
	browserDesc  map[string]*bedrockagentcorecontrol.GetBrowserOutput
	browserType  bactypes.ResourceType
	listErr      error
}

func (f *fakeAgentCore) ListAgentRuntimes(context.Context, *bedrockagentcorecontrol.ListAgentRuntimesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error) {
	return &bedrockagentcorecontrol.ListAgentRuntimesOutput{AgentRuntimes: f.runtimes}, nil
}

func (f *fakeAgentCore) GetAgentRuntime(_ context.Context, in *bedrockagentcorecontrol.GetAgentRuntimeInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	if d, ok := f.runtimeDesc[*in.AgentRuntimeId]; ok {
		return d, nil
	}
	return nil, errors.New("AccessDeniedException")
}

func (f *fakeAgentCore) ListGateways(_ context.Context, in *bedrockagentcorecontrol.ListGatewaysInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	i := 0
	if in.NextToken != nil {
		i = 1
	}
	out := &bedrockagentcorecontrol.ListGatewaysOutput{}
	if i < len(f.gatewayPages) {
		out.Items = f.gatewayPages[i]
	}
	if i == 0 && len(f.gatewayPages) > 1 {
		out.NextToken = awssdk.String("p2")
	}
	return out, nil
}

func (f *fakeAgentCore) ListBrowsers(_ context.Context, in *bedrockagentcorecontrol.ListBrowsersInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListBrowsersOutput, error) {
	f.browserType = in.Type
	return &bedrockagentcorecontrol.ListBrowsersOutput{BrowserSummaries: f.browsers}, nil
}

func (f *fakeAgentCore) GetBrowser(_ context.Context, in *bedrockagentcorecontrol.GetBrowserInput, _ ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetBrowserOutput, error) {
	return f.browserDesc[*in.BrowserId], nil
}

func TestReadAgentCore(t *testing.T) {
	f := &fakeAgentCore{
		runtimes: []bactypes.AgentRuntime{
			{AgentRuntimeArn: awssdk.String("arn:rt-pub"), AgentRuntimeId: awssdk.String("rt-pub"), AgentRuntimeName: awssdk.String("pub")},
			{AgentRuntimeArn: awssdk.String("arn:rt-cap"), AgentRuntimeId: awssdk.String("rt-cap")},
			{AgentRuntimeArn: awssdk.String("arn:rt-denied"), AgentRuntimeId: awssdk.String("rt-denied")},
		},
		runtimeDesc: map[string]*bedrockagentcorecontrol.GetAgentRuntimeOutput{
			"rt-pub": {NetworkConfiguration: &bactypes.NetworkConfiguration{NetworkMode: bactypes.NetworkModePublic}},
			"rt-cap": {CapacityProviderConfiguration: &bactypes.CapacityProviderConfiguration{CapacityProviderArn: awssdk.String("arn:cp")}},
		},
		gatewayPages: [][]bactypes.GatewaySummary{
			{{GatewayId: awssdk.String("gw-open"), Name: awssdk.String("open"), AuthorizerType: bactypes.AuthorizerTypeNone}},
			{{GatewayId: awssdk.String("gw-jwt"), AuthorizerType: bactypes.AuthorizerTypeCustomJwt}, {GatewayId: awssdk.String("gw-blank")}},
		},
		browsers: []bactypes.BrowserSummary{
			{BrowserArn: awssdk.String("arn:br-pub"), BrowserId: awssdk.String("br-pub")},
			{BrowserArn: awssdk.String("arn:br-vpc"), BrowserId: awssdk.String("br-vpc")},
		},
		browserDesc: map[string]*bedrockagentcorecontrol.GetBrowserOutput{
			"br-pub": {NetworkConfiguration: &bactypes.BrowserNetworkConfiguration{NetworkMode: bactypes.BrowserNetworkModePublic}},
			"br-vpc": {NetworkConfiguration: &bactypes.BrowserNetworkConfiguration{NetworkMode: bactypes.BrowserNetworkModeVpc},
				Recording: &bactypes.RecordingConfig{Enabled: true, S3Location: &bactypes.S3Location{Bucket: awssdk.String("rec")}}},
		},
	}
	got, err := readAgentCore(context.Background(), f, "us-east-1", "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, bactypes.ResourceTypeCustom, f.browserType, "only custom browsers are graded")
	m := smByID(got)
	require.Len(t, got, 8)

	require.Equal(t, map[string]string{"capacity_provider": "false", "network_mode": "PUBLIC"}, m["arn:rt-pub"].Metadata)
	require.Equal(t, map[string]string{"capacity_provider": "true"}, m["arn:rt-cap"].Metadata)
	require.Empty(t, m["arn:rt-denied"].Metadata)

	open := m["arn:aws:bedrock-agentcore:us-east-1:111:gateway/gw-open"]
	require.Equal(t, "agentcore_gateway", open.Type)
	require.Equal(t, "NONE", open.Metadata["authorizer_type"])
	require.Equal(t, "CUSTOM_JWT", m["arn:aws:bedrock-agentcore:us-east-1:111:gateway/gw-jwt"].Metadata["authorizer_type"])
	_, ok := m["arn:aws:bedrock-agentcore:us-east-1:111:gateway/gw-blank"].Metadata["authorizer_type"]
	require.False(t, ok, "an empty authorizer type is not an observed NONE")

	require.Equal(t, map[string]string{"network_mode": "PUBLIC", "recording_enabled": "false", "recording_s3_location": "false"}, m["arn:br-pub"].Metadata,
		"a browser with no recording config has recording off")
	require.Equal(t, map[string]string{"network_mode": "VPC", "recording_enabled": "true", "recording_s3_location": "true"}, m["arn:br-vpc"].Metadata)
}

func TestReadAgentCoreListingFailure(t *testing.T) {
	got, err := readAgentCore(context.Background(), &fakeAgentCore{listErr: errors.New("ThrottlingException")}, "us-east-1", "111", time.Now())
	require.Error(t, err)
	require.Nil(t, got)
}
