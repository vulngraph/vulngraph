package httpsrv

import (
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/stretchr/testify/require"
)

// specPath is the OpenAPI index, relative to this package. kin-openapi
// follows the external $refs into openapi/domains/*.yaml from here. Shared with
// the integration-tagged contract test.
const specPath = "../../openapi/openapi.yaml"

// specExemptRoutes are the registered /api routes deliberately outside the
// OpenAPI contract. Every entry needs a reason — an endpoint is either
// documented in openapi/ or listed here, never silently neither. "It has no
// JSON response body" is not a reason to be exempt: the SSE routes (chat,
// refine) and the HTML JIT-approval links are documented, because the request
// bodies, path params, error statuses and security posture are all contract,
// and the frontend client is generated from this spec.
var specExemptRoutes = map[string]string{
	"POST /api/mcp":                  "JSON-RPC 2.0 seam, out of contract scope by design",
	"POST /api/webhooks/github/{id}": "provider webhook, HMAC-authed, caller is GitHub not the API client",

	// Browser navigation steps in an IdP redirect dance, not API operations:
	// no request/response body, an opaque provider-defined query string in and
	// a redirect out. The frontend never calls them through the generated
	// client. The auth logic that matters — domain allowlist, auto-provisioned
	// role — is pinned by unit tests in internal/app/auth instead.
	"GET /api/auth/google":          "browser OAuth redirect leg — no request/response body, IdP-defined query string",
	"GET /api/auth/google/callback": "browser OAuth redirect leg — no request/response body, IdP-defined query string",
	"GET /api/auth/okta":            "browser OAuth redirect leg — no request/response body, IdP-defined query string",
	"GET /api/auth/okta/callback":   "browser OAuth redirect leg — no request/response body, IdP-defined query string",
}

// handleFuncPattern extracts "METHOD /api/..." route patterns from server.go's
// mux registrations. Only /api is in contract scope: the kubelet/compose probes
// GET /healthz and GET /readyz are infrastructure, deliberately undocumented.
var handleFuncPattern = regexp.MustCompile(`HandleFunc\("([A-Z]+) (/api/[^"]+)"`)

// pathParamPattern rewrites Go 1.22 ServeMux {param} segments to a concrete
// value so the spec router (which matches concrete URLs against templated
// paths) can resolve the route.
var pathParamPattern = regexp.MustCompile(`\{[^}]+\}`)

// TestSpecCoversAllRoutes enumerates every route registered in server.go and
// fails if any is absent from openapi/openapi.yaml (or explicitly exempted
// above with a reason). The runtime contract test (server_contract_test.go,
// integration-tagged) validates response shapes for the routes it drives;
// this closes the other half. Source-parse rather than runtime enumeration so
// conditionally-registered handlers (nil-gated intel/alerts/cost/...) are
// still covered without wiring the full server.
func TestSpecCoversAllRoutes(t *testing.T) {
	src, err := os.ReadFile("server.go")
	require.NoError(t, err)

	matches := handleFuncPattern.FindAllStringSubmatch(string(src), -1)
	require.NotEmpty(t, matches, "no routes parsed from server.go — registration style changed? update handleFuncPattern")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	doc, err := loader.LoadFromFile(specPath)
	require.NoError(t, err)
	require.NoError(t, doc.Validate(loader.Context))
	doc.Servers = nil
	router, err := gorillamux.NewRouter(doc)
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, m := range matches {
		method, path := m[1], m[2]
		route := method + " " + path
		if seen[route] {
			continue
		}
		seen[route] = true
		if _, exempt := specExemptRoutes[route]; exempt {
			continue
		}

		concrete := pathParamPattern.ReplaceAllString(path, "x-test-value")
		req := httptest.NewRequest(method, concrete, nil)
		_, _, err := router.FindRoute(req)
		require.NoErrorf(t, err,
			"%s is registered in server.go but missing from openapi/ — add it to the domain file and the openapi.yaml index, or exempt it above with a reason",
			route)
	}

	// Exemptions must stay live: a stale entry hides a future undocumented route
	// that reuses the path.
	for route := range specExemptRoutes {
		require.Truef(t, seen[route],
			"exempt route %q is no longer registered in server.go — remove the stale exemption", route)
	}
}
