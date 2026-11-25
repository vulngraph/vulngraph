package checks

import (
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// API Gateway posture (AWS FSBP APIGateway.1-.5, .8, .10, .11) from the
// api_gateway_stage, api_gateway and api_gateway_domain assets
// (collect/aws/apigateway_stages.go, apigatewayv2.go, apigateway_domains.go).
// Only the missing route authorization is an exposure; the rest is
// defence-in-depth or audit hygiene and stays Low.

// restStage reports a REST API stage — the only kind FSBP APIGateway.2-.5
// grade (HTTP and WebSocket stages have no client certificate, X-Ray, WAF or
// cache setting).
func restStage(a asset.Asset) bool { return a.Metadata["api_type"] == "REST" }

var awsAPIGatewayStageExecutionLoggingDisabled = Check{
	ID:          "aws-apigateway-stage-execution-logging-disabled",
	Title:       "API Gateway stage does not write execution logs",
	Description: "The REST or WebSocket API stage does not log execution at ERROR or INFO level for every method (stage-wide level OFF, or a method override turning it off). Execution logs record integration and authorizer responses and request IDs, which an investigation of a misbehaving or abused API needs. HTTP APIs have no execution logging and are not graded.",
	Remediation: "Console: API Gateway → the API → Stages → the stage → Logs and tracing → CloudWatch logs: Errors only or Errors and info logs. CLI (REST): `aws apigateway update-stage --rest-api-id ID --stage-name STAGE --patch-operations op=replace,path=/*/*/logging/loglevel,value=ERROR`. WebSocket: `aws apigatewayv2 update-stage --api-id ID --stage-name STAGE --default-route-settings LoggingLevel=ERROR`. The account needs a CloudWatch Logs role set in API Gateway settings first.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway_stage",
	Violates:    func(a asset.Asset) bool { return a.Metadata["execution_logging"] == "false" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"logging_level": a.Metadata["logging_level"], "api_type": a.Metadata["api_type"]}
	},
}

var awsAPIGatewayStageNoClientCertificate = Check{
	ID:          "aws-apigateway-stage-no-client-certificate",
	Title:       "API Gateway REST stage does not present a client certificate to its backend",
	Description: "The stage has no client certificate, so an HTTP backend cannot verify that a request came from API Gateway rather than from anyone who can reach the backend directly.",
	Remediation: "Generate a certificate (`aws apigateway generate-client-certificate`), attach it (`aws apigateway update-stage --rest-api-id ID --stage-name STAGE --patch-operations op=replace,path=/clientCertificateId,value=CERT_ID`) and have the backend require it. Console: Stages → the stage → Stage details → Client certificate.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway_stage",
	Violates:    func(a asset.Asset) bool { return restStage(a) && observedNone(a, "client_certificate_id") },
}

var awsAPIGatewayStageXRayDisabled = Check{
	ID:          "aws-apigateway-stage-xray-disabled",
	Title:       "API Gateway REST stage has X-Ray tracing off",
	Description: "Active X-Ray tracing is off for the stage, so requests through it cannot be followed into the services behind it. Observability only; no change to exposure.",
	Remediation: "`aws apigateway update-stage --rest-api-id ID --stage-name STAGE --patch-operations op=replace,path=/tracingEnabled,value=true`. Console: Stages → the stage → Logs and tracing → X-Ray tracing.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway_stage",
	Violates:    func(a asset.Asset) bool { return restStage(a) && a.Metadata["tracing_enabled"] == "false" },
}

var awsAPIGatewayStageNoWAF = Check{
	ID:          "aws-apigateway-stage-no-waf",
	Title:       "API Gateway REST stage has no WAF web ACL",
	Description: "No AWS WAF web ACL is associated with the stage, so requests reach the API's authorizers and integrations without managed-rule filtering (injection, known-bad inputs, IP reputation) or rate-based blocking. Low: WAF is defence in depth; whether the API is reachable is reported by aws-apigateway-public-endpoint.",
	Remediation: "Console: WAF & Shield → Web ACLs (regional) → the ACL → Associated AWS resources → Add → the API Gateway stage. CLI: `aws wafv2 associate-web-acl --web-acl-arn ACL_ARN --resource-arn arn:aws:apigateway:REGION::/restapis/ID/stages/STAGE`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway_stage",
	Violates:    func(a asset.Asset) bool { return restStage(a) && observedNone(a, "waf_web_acl_arn") },
}

var awsAPIGatewayStageCacheUnencrypted = Check{
	ID:          "aws-apigateway-stage-cache-unencrypted",
	Title:       "API Gateway REST stage caches responses unencrypted",
	Description: "The stage's cache cluster is on and at least one method caches responses without cache data encryption, so cached API responses sit unencrypted at rest. Methods with caching off are not graded.",
	Remediation: "`aws apigateway update-stage --rest-api-id ID --stage-name STAGE --patch-operations op=replace,path=/*/*/caching/dataEncrypted,value=true` (or the method's own path for a per-method override). Console: Stages → the stage → Cache settings → Encrypt cache data.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway_stage",
	Violates: func(a asset.Asset) bool {
		return restStage(a) && a.Metadata["cache_cluster_enabled"] == "true" && a.Metadata["cache_unencrypted_methods"] != ""
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"cache_unencrypted_methods": a.Metadata["cache_unencrypted_methods"]}
	},
}

// unauthenticatedRoutes reports an HTTP/WebSocket API whose route read found
// routes with no authorization. An unread route set is absent, never "".
// Routes on an API that answers on no URL (default endpoint disabled, no
// custom domain mapped: public=false) cannot be called and are not graded.
func unauthenticatedRoutes(a asset.Asset) bool {
	return a.Metadata["unauthenticated_routes"] != "" && a.Metadata["public"] == "true"
}

var awsAPIGatewayV2RouteNoAuthorization = Check{
	ID:          "aws-apigatewayv2-route-no-authorization",
	Title:       "HTTP or WebSocket API has routes with no authorization",
	Description: "Routes of this reachable API have authorization type NONE, so anyone on the internet can invoke those routes and whatever integration they front. On a WebSocket API only $connect is graded: it authorizes the whole connection, no other route can carry an authorizer, and an API with no $connect route accepts every connection anonymously. An API with its default endpoint disabled and no custom domain mapped answers on no URL and is not graded. A backend that authenticates requests itself is still safe; API Gateway is not checking. Medium, the AWS FSBP APIGateway.8 grade. This replaces aws-apigateway-public-endpoint for the API.",
	Remediation: "Attach an authorizer to each listed route: `aws apigatewayv2 update-route --api-id ID --route-id ROUTE_ID --authorization-type JWT --authorizer-id AUTH_ID` (or AWS_IAM / CUSTOM). Console: API Gateway → the API → Authorization → the route → Attach authorizer. If a route must be anonymous, keep it narrow and rate-limited.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway",
	Violates:    unauthenticatedRoutes,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"unauthenticated_routes": a.Metadata["unauthenticated_routes"],
			"route_count":            a.Metadata["route_count"],
			"api_type":               a.Metadata["api_type"],
		}
	},
}

var awsAPIGatewayV2PrivateIntegrationNoTLS = Check{
	ID:          "aws-apigatewayv2-private-integration-no-tls",
	Title:       "API Gateway private integration sends traffic to its backend without TLS",
	Description: "A VPC-link (private) integration of this API has no TLS configuration, so API Gateway forwards requests to the private load balancer over plain HTTP. A VPC link gives private connectivity, not encryption.",
	Remediation: "Serve HTTPS on the backend listener and set the integration's TLS config: `aws apigatewayv2 update-integration --api-id ID --integration-id INTEGRATION_ID --tls-config ServerNameToVerify=BACKEND_HOSTNAME`. Console: API Gateway → the API → Integrations → the integration → Advanced settings → Secure server verification.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway",
	Violates:    func(a asset.Asset) bool { return a.Metadata["private_integrations_without_tls"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"private_integrations_without_tls": a.Metadata["private_integrations_without_tls"]}
	},
}

// apiGatewayRecommendedTLSPolicies are the security policies AWS FSBP
// APIGateway.11 accepts (not customizable): the 2025 enhanced policies.
var apiGatewayRecommendedTLSPolicies = []string{
	"SecurityPolicy_TLS13_1_3_2025_09",
	"SecurityPolicy_TLS13_1_3_FIPS_2025_09",
	"SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09",
	"SecurityPolicy_TLS13_2025_EDGE",
	"SecurityPolicy_TLS12_PFS_2025_EDGE",
}

// apiGatewayTLS10Policy still accepts TLS 1.0 and 1.1 from clients.
const apiGatewayTLS10Policy = "TLS_1_0"

var awsAPIGatewayDomainWeakTLSPolicy = Check{
	ID:          "aws-apigateway-domain-weak-tls-policy",
	Title:       "API Gateway custom domain does not use a recommended TLS policy",
	Description: "The custom domain's security policy is not one of the enhanced 2025 policies AWS recommends. TLS_1_0 still accepts TLS 1.0/1.1 clients and is graded Medium; the legacy TLS_1_2 policy is TLS 1.2 with older cipher suites and is Low.",
	Remediation: "Console: API Gateway → Custom domain names → the domain → Configurations → Edit → Security policy: SecurityPolicy_TLS13_1_3_2025_09 (or a FIPS / PQ variant; *_EDGE for edge-optimized). CLI: `aws apigateway update-domain-name --domain-name DOMAIN --patch-operations op=replace,path=/securityPolicy,value=SecurityPolicy_TLS13_1_3_2025_09`. Test old clients first.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway_domain",
	Violates: func(a asset.Asset) bool {
		p, ok := a.Metadata["security_policy"]
		return ok && p != "" && !slices.Contains(apiGatewayRecommendedTLSPolicies, p)
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["security_policy"] == apiGatewayTLS10Policy {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["security_policy"] == apiGatewayTLS10Policy {
			return "API Gateway custom domain accepts TLS 1.0"
		}
		return "API Gateway custom domain does not use a recommended TLS policy"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"security_policy": a.Metadata["security_policy"]}
	},
}

func awsAPIGatewayChecks() []Check {
	return []Check{
		awsAPIGatewayStageExecutionLoggingDisabled,
		awsAPIGatewayStageNoClientCertificate,
		awsAPIGatewayStageXRayDisabled,
		awsAPIGatewayStageNoWAF,
		awsAPIGatewayStageCacheUnencrypted,
		awsAPIGatewayV2RouteNoAuthorization,
		awsAPIGatewayV2PrivateIntegrationNoTLS,
		awsAPIGatewayDomainWeakTLSPolicy,
	}
}
