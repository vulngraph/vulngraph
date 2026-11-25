package checks

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Serverless and API-edge coverage for GCP Cloud Functions and AWS API
// Gateway: end-of-life runtimes, open ingress, and internet-facing gateways.
//
// What the platform does NOT know, and therefore what these checks do not
// claim: whether an anonymous caller can actually invoke a given function.
// That requires the Cloud Functions Invoker IAM binding, which no collector
// fetches. Severities below are bounded by that limit rather than by how bad
// the worst case would be — the collector gap is the thing to close to make
// them confirmable.
//
// Every predicate below reads a metadata key the collector populates: a check
// whose predicate reads a key the collector never writes is
// silently dead and looks identical to a clean estate.

// deprecatedGCPRuntimes are Cloud Functions runtimes past end of life: Google no
// longer patches them, so a known CVE in the runtime stays exploitable until the
// function is redeployed on a supported version.
//
// Keyed on the exact strings the GCP collector writes (no dots, unlike Lambda's
// "nodejs12.x") — verified against the collector's output rather than guessed,
// because a near-miss key here is a check that never fires.
var deprecatedGCPRuntimes = map[string]bool{
	"nodejs6":  true,
	"nodejs8":  true,
	"nodejs10": true,
	"nodejs12": true,
	"nodejs14": true,
	"nodejs16": true,
	"python37": true,
	"python38": true,
	"go111":    true,
	"go113":    true,
	"go116":    true,
	"php74":    true,
	"ruby26":   true,
	"ruby27":   true,
	"java11":   true,
	"dotnet3":  true,
}

// gcpFunctionDeprecatedRuntime flags a Cloud Function on an unpatched runtime.
//
// High rather than Critical on its own: an EOL runtime is exploitable only via a
// runtime CVE, not directly. gcpFunctionOpenIngress fires on the same function when
// it is also internet-reachable, and the two together are what make it urgent —
// composing them is the enrichment layer's job, not a severity guess here.
var gcpFunctionDeprecatedRuntime = Check{
	ID:          "gcp-function-deprecated-runtime",
	Title:       "Cloud Function runs an end-of-life runtime",
	Description: "This Cloud Function executes on a runtime Google no longer supports, so the language runtime and its bundled OS libraries receive no security patches. Any CVE disclosed against that runtime stays exploitable in this function's execution environment until it is redeployed on a supported version. Node 12 reached end of life in April 2022 and Python 3.7 in June 2023.",
	Remediation: "Redeploy on a supported runtime: `gcloud functions deploy NAME --runtime nodejs22 --source .` (or python312/go122). Check for breaking changes first — the runtime upgrade is a code change, not a config flag. `gcloud functions list --format='table(name,runtime)'` enumerates what needs moving.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_function",
	Violates: func(a asset.Asset) bool {
		rt := a.Metadata["runtime"]
		if rt == "" {
			return false // runtime unknown — never guess a finding from absent data
		}
		return deprecatedGCPRuntimes[rt]
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"runtime": a.Metadata["runtime"], "url": a.Metadata["url"]}
	},
}

// gcpFunctionOpenIngress flags a Cloud Function whose network ingress admits
// the whole internet.
//
// Severity and wording are bounded by what the collector actually knows:
// public=true comes from ALLOW_ALL ingress settings alone, not from the
// allUsers invoker IAM binding (not collected), so this check cannot claim
// unauthenticated invocation — only Medium, with the description saying what
// is unknown. Confirming these needs the invoker binding in the collector;
// until then the finding's job is to point triage at the right functions, not
// to pretend it already did the triage.
var gcpFunctionOpenIngress = Check{
	ID:          "gcp-function-open-ingress",
	Title:       "Cloud Function accepts ingress from the whole internet",
	Description: "This function's ingress setting is ALLOW_ALL, so its HTTPS endpoint is reachable from anywhere on the internet rather than restricted to internal or load-balancer traffic. Whether an anonymous caller can actually INVOKE it depends on the Cloud Functions Invoker IAM binding, which this platform does not currently collect — so treat this as reachable attack surface to confirm, not as proven unauthenticated access. Check the binding before triaging: a function with allUsers as invoker is directly callable by anyone.",
	Remediation: "Confirm the invoker binding first: `gcloud functions get-iam-policy NAME` — if allUsers or allAuthenticatedUsers holds roles/cloudfunctions.invoker, remove it (`gcloud functions remove-invoker-policy-binding NAME --member=allUsers`). Independently, restrict the network path if the function is internal: `gcloud functions deploy NAME --ingress-settings=internal-only` (or internal-and-gclb when fronted by a load balancer).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_function",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public"] == "true"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"url":       a.Metadata["url"],
			"exec_role": a.Metadata["exec_role"],
			"runtime":   a.Metadata["runtime"],
		}
	},
}

// gcpFunctionOpenIngressDefaultSA flags the pairing worth prioritising: an
// internet-reachable function whose execution identity is a default
// GCP-managed service account. Those accounts carry roles/editor at project
// scope in essentially every GCP project, so a caller who reaches this
// function executes with project-wide write; a dedicated service account is
// excluded even when open, since its blast radius is whatever it was scoped
// to.
//
// High rather than Critical, for the same reason as gcpFunctionOpenIngress:
// the invoker IAM binding is not collected, so "anonymous caller" is
// unproven. This pairing is what makes it worth looking at first, not a claim
// it is already being exploited.
var gcpFunctionOpenIngressDefaultSA = Check{
	ID:          "gcp-function-open-ingress-default-sa",
	Title:       "Internet-reachable Cloud Function runs as a default service account",
	Description: "This function accepts ingress from the whole internet AND executes as a default GCP-managed service account (Compute Engine or App Engine default). Those accounts hold roles/editor at project scope by default, so anyone who can invoke this function runs code with project-wide write access to compute, storage, and IAM-adjacent resources. Invocation may still be gated by the Cloud Functions Invoker IAM binding, which is not collected — but this pairing is where to start among internet-reachable functions, because the consequence of a missing binding is project-wide.",
	Remediation: "Two independent fixes, do both. Confirm and remove any public invoker binding (`gcloud functions get-iam-policy NAME`, then `remove-invoker-policy-binding --member=allUsers`), and replace the default execution identity with a dedicated, minimally-scoped one (`gcloud functions deploy NAME --service-account=fn-specific@PROJECT.iam.gserviceaccount.com`). Leaving a project-editor credential attached keeps a project-wide compromise one bug away from any caller that gets through.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_function",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["public"] != "true" {
			return false
		}
		role := a.Metadata["exec_role"]
		if role == "" {
			return false // execution identity unknown — do not infer the worst case
		}
		return isDefaultGCPServiceAccount(role)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"url": a.Metadata["url"], "exec_role": a.Metadata["exec_role"],
			"runtime": a.Metadata["runtime"],
		}
	},
}

// isDefaultGCPServiceAccount reports whether a principal is one of the GCP-managed
// default accounts that receive roles/editor at project creation:
//
//	<project-number>-compute@developer.gserviceaccount.com   (Compute Engine default)
//	<project-id>@appspot.gserviceaccount.com                 (App Engine default)
//
// Matching on the managed suffix rather than a name pattern, so a customer account
// that merely contains "compute" is not swept in.
func isDefaultGCPServiceAccount(principal string) bool {
	return strings.HasSuffix(principal, "-compute@developer.gserviceaccount.com") ||
		strings.HasSuffix(principal, "@appspot.gserviceaccount.com")
}

// awsAPIGatewayPublic flags an internet-facing API Gateway.
//
// Scope note, deliberately honest: the collector records endpoint reachability
// (public / endpoint_type) but NOT whether methods carry an authorizer, so this
// check cannot claim "unauthenticated". It reports the reachable attack surface and
// says so in the description. Overstating it as missing-auth would be a finding
// nobody can verify from the evidence attached — the fastest way to teach a
// responder to ignore a whole check.
var awsAPIGatewayPublic = Check{
	ID:          "aws-apigateway-public-endpoint",
	Title:       "API Gateway is internet-facing",
	Description: "This API Gateway accepts requests from the internet (a REGIONAL or EDGE endpoint rather than PRIVATE). Every route it exposes is reachable by anyone who finds the URL, so its authorizers, API-key requirements, throttling, and WAF association are the only things standing between an anonymous caller and whatever the API fronts. This finding reports reachability, not missing authentication — confirm the authorizer configuration on each method. An HTTP or WebSocket API with its default endpoint disabled and no custom domain mapped answers on no URL and is not reported.",
	Remediation: "If a REST API is internal, switch it to a PRIVATE endpoint behind a VPC endpoint: `aws apigateway update-rest-api --rest-api-id ID --patch-operations op=replace,path=/endpointConfiguration/types/PRIVATE`. HTTP and WebSocket APIs have no private endpoint type: turn off the default endpoint with `aws apigatewayv2 update-api --api-id ID --disable-execute-api-endpoint` and reach the API only through a custom domain you control, or delete it if unused. If it must stay public, verify every method has an authorizer or requires an API key (`aws apigateway get-method --rest-api-id ID --resource-id RID --http-method ANY`), and attach a WAF web ACL and throttling limits.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway",
	// Steps aside when the route read proved routes with no authorization:
	// aws-apigatewayv2-route-no-authorization reports the same API at High
	// with the routes named, and strictly dominates this reachability finding.
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public"] == "true" && !unauthenticatedRoutes(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"endpoint_type": a.Metadata["endpoint_type"],
			"api_id":        a.Metadata["api_id"],
		}
	},
}

// serverlessChecks are the serverless/API-edge checks registered by Default().
func serverlessChecks() []Check {
	return []Check{
		gcpFunctionDeprecatedRuntime,
		gcpFunctionOpenIngress,
		gcpFunctionOpenIngressDefaultSA,
		awsAPIGatewayPublic,
	}
}
