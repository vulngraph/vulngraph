package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bactypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Bedrock AgentCore runtimes, gateways and custom browsers (AWS FSBP
// BedrockAgentCore.1, .2, .5, .6). The control-plane API is
// bedrock-agentcore-control; IAM actions use the bedrock-agentcore prefix.

type agentCoreAPI interface {
	ListAgentRuntimes(context.Context, *bedrockagentcorecontrol.ListAgentRuntimesInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListAgentRuntimesOutput, error)
	GetAgentRuntime(context.Context, *bedrockagentcorecontrol.GetAgentRuntimeInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error)
	ListGateways(context.Context, *bedrockagentcorecontrol.ListGatewaysInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListGatewaysOutput, error)
	ListBrowsers(context.Context, *bedrockagentcorecontrol.ListBrowsersInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.ListBrowsersOutput, error)
	GetBrowser(context.Context, *bedrockagentcorecontrol.GetBrowserInput, ...func(*bedrockagentcorecontrol.Options)) (*bedrockagentcorecontrol.GetBrowserOutput, error)
}

func collectAgentCore(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectAgentCore: %w", err)
	}
	return readAgentCore(ctx, bedrockagentcorecontrol.NewFromConfig(awsCfg), region, accountID, now)
}

func readAgentCore(ctx context.Context, client agentCoreAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	runtimes, err := listAgentRuntimes(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readAgentCore: %w", err)
	}
	gateways, err := listGateways(ctx, client, region, accountID, now)
	if err != nil {
		return nil, fmt.Errorf("readAgentCore: %w", err)
	}
	browsers, err := listCustomBrowsers(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readAgentCore: %w", err)
	}
	mds := describeAll(ctx, region, "bedrock-agentcore:GetAgentRuntime", runtimes, func(r listedResource) (map[string]string, error) {
		d, err := client.GetAgentRuntime(ctx, &bedrockagentcorecontrol.GetAgentRuntimeInput{AgentRuntimeId: &r.id})
		if err != nil {
			return nil, err
		}
		return agentRuntimeMetadata(d), nil
	})
	out := listedAssets(mds, runtimes, "agentcore_runtime", region, accountID, now)
	out = append(out, gateways...)
	mds = describeAll(ctx, region, "bedrock-agentcore:GetBrowser", browsers, func(r listedResource) (map[string]string, error) {
		d, err := client.GetBrowser(ctx, &bedrockagentcorecontrol.GetBrowserInput{BrowserId: &r.id})
		if err != nil {
			return nil, err
		}
		return browserMetadata(d), nil
	})
	return append(out, listedAssets(mds, browsers, "agentcore_browser", region, accountID, now)...), nil
}

func listAgentRuntimes(ctx context.Context, client agentCoreAPI) ([]listedResource, error) {
	var (
		out  []listedResource
		next *string
	)
	for {
		page, err := client.ListAgentRuntimes(ctx, &bedrockagentcorecontrol.ListAgentRuntimesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listAgentRuntimes: %w", err)
		}
		for _, r := range page.AgentRuntimes {
			out = append(out, listedResource{arn: awssdk.ToString(r.AgentRuntimeArn), name: awssdk.ToString(r.AgentRuntimeName), id: awssdk.ToString(r.AgentRuntimeId)})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

// listGateways emits the gateways straight from the listing: the summary
// already carries the inbound authorizer type, the only setting graded.
// GatewaySummary has no ARN, so the asset ID is built from the gateway id.
func listGateways(ctx context.Context, client agentCoreAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out  []asset.Asset
		next *string
	)
	for {
		page, err := client.ListGateways(ctx, &bedrockagentcorecontrol.ListGatewaysInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listGateways: %w", err)
		}
		for _, g := range page.Items {
			id := awssdk.ToString(g.GatewayId)
			md := map[string]string{"status": string(g.Status)}
			if g.AuthorizerType != "" {
				md["authorizer_type"] = string(g.AuthorizerType)
			}
			out = append(out, asset.Asset{
				ID:           fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:gateway/%s", partitionFor(region), region, accountID, id),
				Name:         awssdk.ToString(g.Name),
				Type:         "agentcore_gateway",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     md,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

// listCustomBrowsers lists only CUSTOM browsers: the AWS-managed system
// browser is not configurable and FSBP grades custom browsers alone.
func listCustomBrowsers(ctx context.Context, client agentCoreAPI) ([]listedResource, error) {
	var (
		out  []listedResource
		next *string
	)
	for {
		page, err := client.ListBrowsers(ctx, &bedrockagentcorecontrol.ListBrowsersInput{Type: bactypes.ResourceTypeCustom, NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listCustomBrowsers: %w", err)
		}
		for _, b := range page.BrowserSummaries {
			out = append(out, listedResource{arn: awssdk.ToString(b.BrowserArn), name: awssdk.ToString(b.Name), id: awssdk.ToString(b.BrowserId)})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}

// agentRuntimeMetadata records the runtime's network mode and whether it is
// backed by a capacity provider (whose network configuration lives on the
// provider, so FSBP BedrockAgentCore.1 does not grade the runtime).
func agentRuntimeMetadata(d *bedrockagentcorecontrol.GetAgentRuntimeOutput) map[string]string {
	md := map[string]string{"capacity_provider": strconv.FormatBool(d.CapacityProviderConfiguration != nil)}
	if d.NetworkConfiguration != nil && d.NetworkConfiguration.NetworkMode != "" {
		md["network_mode"] = string(d.NetworkConfiguration.NetworkMode)
	}
	return md
}

// browserMetadata records the custom browser's network mode and session
// recording. GetBrowser omits Recording when recording was never configured,
// which is recording off — an observation, not unknown.
func browserMetadata(d *bedrockagentcorecontrol.GetBrowserOutput) map[string]string {
	md := map[string]string{}
	if d.NetworkConfiguration != nil && d.NetworkConfiguration.NetworkMode != "" {
		md["network_mode"] = string(d.NetworkConfiguration.NetworkMode)
	}
	rec := d.Recording
	md["recording_enabled"] = strconv.FormatBool(rec != nil && rec.Enabled)
	md["recording_s3_location"] = strconv.FormatBool(rec != nil && rec.S3Location != nil && awssdk.ToString(rec.S3Location.Bucket) != "")
	return md
}
