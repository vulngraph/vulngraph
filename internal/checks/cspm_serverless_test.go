package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// liveFunction builds a cloud_function asset with the metadata shape the GCP
// collector actually writes — a test that asserts against imagined keys proves
// the check works on data that does not exist, which is precisely how a check
// ships dark.
func liveFunction(id, runtime, public, execRole string) asset.Asset {
	return asset.Asset{
		ID: id, Type: "cloud_function", Provider: asset.ProviderGCP,
		Metadata: map[string]string{
			"runtime": runtime, "public": public, "exec_role": execRole,
			"public_access": "possible",
			"url":           "https://europe-west1-example-functions.cloudfunctions.net/" + id,
		},
	}
}

func TestServerless_GCPFunctionRuntimeAndExposure(t *testing.T) {
	r := NewRegistry()
	r.Register(serverlessChecks()...)

	assets := []asset.Asset{
		// A common shape: nodejs12, public, running a dedicated runtime SA.
		liveFunction("fn-eol-public", "nodejs12", "true", "serviceAccount:function-runtime@example-functions.iam.gserviceaccount.com"),
		// Supported runtime, still public → exposure only, no runtime finding.
		liveFunction("fn-current-public", "nodejs20", "true", "serviceAccount:function-runtime@p.iam.gserviceaccount.com"),
		// EOL runtime but private → runtime finding only, no exposure finding.
		liveFunction("fn-eol-private", "python37", "false", "serviceAccount:function-runtime@p.iam.gserviceaccount.com"),
		// The toxic pair: anonymous callers reaching a default (roles/editor) SA.
		liveFunction("fn-public-default-sa", "nodejs20", "true", "serviceAccount:5004567890123-compute@developer.gserviceaccount.com"),
		// Fully healthy → silent. A check that cannot stay quiet is a noise source.
		liveFunction("fn-clean", "nodejs22", "false", "serviceAccount:function-runtime@p.iam.gserviceaccount.com"),
	}

	fired := map[string][]string{}
	for _, f := range r.Run(assets, fixedTime) {
		fired[f.ResourceID] = append(fired[f.ResourceID], f.CheckID)
	}

	require.ElementsMatch(t, []string{"gcp-function-deprecated-runtime", "gcp-function-open-ingress"},
		fired["fn-eol-public"], "an EOL internet-reachable function is both unpatched and exposed")
	require.ElementsMatch(t, []string{"gcp-function-open-ingress"}, fired["fn-current-public"])
	require.ElementsMatch(t, []string{"gcp-function-deprecated-runtime"}, fired["fn-eol-private"])
	require.ElementsMatch(t, []string{"gcp-function-open-ingress", "gcp-function-open-ingress-default-sa"},
		fired["fn-public-default-sa"])
	require.Empty(t, fired["fn-clean"], "a patched, private function must produce nothing")
}

// Absent metadata must never manufacture a finding. The collector can omit runtime
// or exec_role, and inferring the worst case from missing data is how a check earns
// a reputation for lying.
func TestServerless_MissingMetadataIsSilent(t *testing.T) {
	r := NewRegistry()
	r.Register(serverlessChecks()...)

	findings := r.Run([]asset.Asset{
		{ID: "fn-no-runtime", Type: "cloud_function", Provider: asset.ProviderGCP,
			Metadata: map[string]string{"public": "false"}},
		{ID: "fn-public-unknown-sa", Type: "cloud_function", Provider: asset.ProviderGCP,
			Metadata: map[string]string{"public": "true", "runtime": "nodejs22"}},
	}, fixedTime)

	for _, f := range findings {
		require.NotEqual(t, "gcp-function-deprecated-runtime", f.CheckID,
			"an unknown runtime is not a deprecated runtime")
		require.NotEqual(t, "gcp-function-open-ingress-default-sa", f.CheckID,
			"an unknown execution identity must not be assumed to be a default SA")
	}
}

// The default-SA matcher keys on the GCP-managed suffixes, so a customer account
// whose name merely contains "compute" is not swept in.
func TestIsDefaultGCPServiceAccount(t *testing.T) {
	require.True(t, isDefaultGCPServiceAccount("serviceAccount:5004567890123-compute@developer.gserviceaccount.com"))
	require.True(t, isDefaultGCPServiceAccount("serviceAccount:example-project@appspot.gserviceaccount.com"))
	require.False(t, isDefaultGCPServiceAccount("serviceAccount:compute-worker@my-proj.iam.gserviceaccount.com"),
		"a customer SA with 'compute' in its name is not a default account")
	require.False(t, isDefaultGCPServiceAccount("serviceAccount:function-runtime@example-functions.iam.gserviceaccount.com"))
	require.False(t, isDefaultGCPServiceAccount(""))
}

func TestServerless_APIGatewayEndpointReachability(t *testing.T) {
	r := NewRegistry()
	r.Register(serverlessChecks()...)

	// One gateway of each endpoint type: REGIONAL, EDGE, and PRIVATE.
	findings := r.Run([]asset.Asset{
		{ID: "api-regional", Type: "api_gateway", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"public": "true", "endpoint_type": "REGIONAL", "api_id": "ghi789"}},
		{ID: "api-edge", Type: "api_gateway", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"public": "true", "endpoint_type": "EDGE", "api_id": "abc123"}},
		{ID: "api-private", Type: "api_gateway", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"public": "false", "endpoint_type": "PRIVATE", "api_id": "def456"}},
	}, fixedTime)

	fired := map[string]finding.Finding{}
	for _, f := range findings {
		fired[f.ResourceID] = f
	}
	require.Contains(t, fired, "api-regional")
	require.Contains(t, fired, "api-edge")
	require.NotContains(t, fired, "api-private", "a PRIVATE endpoint is not internet-facing")
	// Evidence must carry the endpoint type: "internet-facing" is only actionable if
	// the responder can see which endpoint made it so.
	require.Equal(t, "REGIONAL", fired["api-regional"].Metadata["endpoint_type"])
	// Medium, not high: this reports reachability, and the check cannot see whether
	// an authorizer is attached. Claiming "unauthenticated" would be unverifiable
	// from the evidence and would teach responders to distrust the whole check.
	require.Equal(t, finding.SeverityMedium, fired["api-regional"].Severity)
}

// Guard against the class of gap that motivated this file: an asset type that is
// collected in volume but that no registered check ever looks at is invisible, and
// nothing previously detected that state. These four types now have coverage; the
// list records the types the collectors populate.
func TestServerless_CoveredAssetTypesHaveAtLeastOneCheck(t *testing.T) {
	// One deliberately-violating asset per type, run through the REAL registry: this
	// proves a check both matches the type AND fires on the collector's own metadata
	// shape, which is stronger than asserting that some check merely names the type.
	probes := []asset.Asset{
		liveFunction("probe-fn", "nodejs12", "true", "serviceAccount:5004567890123-compute@developer.gserviceaccount.com"),
		{ID: "probe-api", Type: "api_gateway", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"public": "true", "endpoint_type": "REGIONAL", "api_id": "x"}},
	}
	covered := map[string]bool{}
	for _, f := range Default().Run(probes, fixedTime) {
		covered[f.ResourceType] = true
	}
	for _, ty := range []string{"cloud_function", "api_gateway"} {
		require.True(t, covered[ty],
			"asset type %q is collected in volume and must have at least one check that fires on real collector metadata — an uncovered type is a blind spot no metric reports", ty)
	}
}
