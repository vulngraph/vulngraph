package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Bedrock AgentCore runtime, gateway and custom-browser posture (AWS FSBP
// BedrockAgentCore.1, .2, .5, .6).

var awsAgentCoreGatewayNoInboundAuth = Check{
	ID:          "aws-agentcore-gateway-no-inbound-auth",
	Title:       "Bedrock AgentCore gateway accepts requests without authorization",
	Description: "The gateway's inbound authorizer type is NONE, so anyone who can reach its HTTPS endpoint can list and invoke every tool behind it — Lambda functions, APIs and MCP servers that run with the gateway's own credentials. The endpoint is reachable from the internet.",
	Remediation: "Configure inbound authorization (AWS_IAM or CUSTOM_JWT): `aws bedrock-agentcore-control update-gateway --gateway-identifier ID --authorizer-type CUSTOM_JWT --authorizer-configuration ...` (console: Bedrock AgentCore > Gateways > the gateway > Inbound auth).",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "agentcore_gateway",
	Violates:    func(a asset.Asset) bool { return a.Metadata["authorizer_type"] == "NONE" },
}

var awsAgentCoreRuntimePublicNetwork = Check{
	ID:          "aws-agentcore-runtime-public-network",
	Title:       "Bedrock AgentCore runtime uses public network mode",
	Description: "The agent runtime's network mode is PUBLIC, so the agent's code runs on AgentCore's internet-connected network rather than in your VPC: its traffic to the internet and to your services is outside your security groups, NACLs, endpoints and flow logs, and a prompt-injected agent can reach anything on the internet with its role's credentials. Runtimes backed by a capacity provider take their network from the provider and are not graded.",
	Remediation: "Update the runtime to VPC mode: `aws bedrock-agentcore-control update-agent-runtime --agent-runtime-id ID --network-configuration 'networkMode=VPC,networkModeConfig={subnets=[...],securityGroups=[...]}' ...` (console: Bedrock AgentCore > Runtime > the agent > Edit > Network).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "agentcore_runtime",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["network_mode"] == "PUBLIC" && a.Metadata["capacity_provider"] == "false"
	},
}

var awsAgentCoreBrowserPublicNetwork = Check{
	ID:          "aws-agentcore-browser-public-network",
	Title:       "Bedrock AgentCore custom browser uses public network mode",
	Description: "The custom browser's network mode is PUBLIC, so the browser sessions agents drive run on AgentCore's internet-connected network rather than in your VPC, outside your network controls and flow logs.",
	Remediation: "Network mode is fixed at creation: create a new custom browser with `aws bedrock-agentcore-control create-browser --network-configuration 'networkMode=VPC,vpcConfig={...}' ...`, move agents to it and delete the old one.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "agentcore_browser",
	Violates:    func(a asset.Asset) bool { return a.Metadata["network_mode"] == "PUBLIC" },
}

var awsAgentCoreBrowserNoRecording = Check{
	ID:          "aws-agentcore-browser-no-session-recording",
	Title:       "Bedrock AgentCore custom browser does not record sessions to S3",
	Description: "Session recording is off, or on without an S3 location, so there is no replayable record of what agents did in the browser — which sites they visited and what they submitted. Audit trail only.",
	Remediation: "Recording is set at creation: create a new custom browser with `--recording 'enabled=true,s3Location={bucket=BUCKET,prefix=PREFIX}'`, move agents to it and delete the old one.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "agentcore_browser",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["recording_enabled"] == "false" ||
			(a.Metadata["recording_enabled"] == "true" && a.Metadata["recording_s3_location"] == "false")
	},
}

func awsAgentCoreChecks() []Check {
	return []Check{
		awsAgentCoreGatewayNoInboundAuth,
		awsAgentCoreRuntimePublicNetwork,
		awsAgentCoreBrowserPublicNetwork,
		awsAgentCoreBrowserNoRecording,
	}
}
