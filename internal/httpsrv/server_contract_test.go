//go:build integration

package httpsrv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

// TestOpenAPIContract is the mechanism that keeps the hand-maintained spec honest:
// it drives the real wired server and asserts every response conforms
// to api/openapi.yaml. A handler whose status code or body shape diverges from the
// spec fails here. It catches missing/required fields, wrong types, and bad enum
// values; extra undocumented fields are tolerated (JSON is forward-compatible),
// so adding a field to a *Response still needs the matching openapi/domains/*.yaml edit.
func TestOpenAPIContract(t *testing.T) {
	srv, login := buildServer(t)
	admin := login("admin")
	viewer := login("viewer")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	doc, err := loader.LoadFromFile(specPath)
	require.NoError(t, err)
	require.NoError(t, doc.Validate(loader.Context))
	doc.Servers = nil // route on the path alone; the "/" server adds no base path
	router, err := gorillamux.NewRouter(doc)
	require.NoError(t, err)

	// A real asset, so the alert-context cases validate a populated response
	// (asset, sections, matches), not only the empty shape.
	alertIP := seedAlertContextAsset(t)
	// A finding carrying routing context, and a channel scoped by it, so the
	// owner/environment/suppression fields validate populated, not only empty.
	routedFinding, routedAsset := seedRoutedFinding(t)
	channelName := "contract-routing-" + time.Now().Format("150405.000000")
	channelBody := `{"type":"webhook","name":"` + channelName + `","webhook_url":"https://example.com/h","enabled":true,` +
		`"event_types":["finding"],"severities":[],"owner_teams":["@acme/Payments"],"environments":["prod"],"route_unowned":true}`

	createBody := `{"type":"aws","name":"contract-aws","config":{"role_arn":"arn:x","region":"eu-west-1"}}`
	t.Cleanup(func() {
		pool, _ := db.NewPool(context.Background(), pgDSN, db.MaxConnsWorker)
		defer pool.Close()
		_, _ = pool.Exec(context.Background(), "DELETE FROM connectors WHERE name = 'contract-aws'")
		_, _ = pool.Exec(context.Background(), "DELETE FROM finding_suppressions WHERE finding_id = 'contract-suppressed'")
		_, _ = pool.Exec(context.Background(), "DELETE FROM finding_suppressions WHERE finding_id = $1", routedFinding)
		_, _ = pool.Exec(context.Background(), "DELETE FROM alert_channels WHERE name = $1", channelName)
	})
	suppressBody := `{"reason":"contract","expires_at":"` + time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339) + `"}`
	reviewBody := `{"expires_at":"` + time.Now().Add(60*24*time.Hour).UTC().Format(time.RFC3339) + `"}`

	cases := []struct {
		name   string
		method string
		path   string
		cookie *http.Cookie
		body   string
		status int // asserted when non-zero; 0 means "any documented status is fine"
	}{
		{"current user", http.MethodGet, "/api/auth/me", admin, "", http.StatusOK},
		{"list assets", http.MethodGet, "/api/assets", admin, "", http.StatusOK},
		{"list findings", http.MethodGet, "/api/findings", admin, "", http.StatusOK},
		{"findings summary", http.MethodGet, "/api/findings/summary", admin, "", http.StatusOK},
		{"list findings by owner and environment", http.MethodGet, "/api/findings?owner=payments&environment=prod", admin, "", http.StatusOK},
		{"list unowned findings", http.MethodGet, "/api/findings?owner=unowned", admin, "", http.StatusOK},
		{"list findings bad environment", http.MethodGet, "/api/findings?environment=production", admin, "", http.StatusBadRequest},
		{"finding detail unsuppressed", http.MethodGet, "/api/findings/" + routedFinding, admin, "", http.StatusOK},
		{"suppress routed finding", http.MethodPost, "/api/findings/" + routedFinding + "/suppress", admin, suppressBody, http.StatusCreated},
		{"finding detail suppressed", http.MethodGet, "/api/findings/" + routedFinding, admin, "", http.StatusOK},
		{"asset detail with owner", http.MethodGet, "/api/assets/" + routedAsset, admin, "", http.StatusOK},
		{"create scoped channel", http.MethodPost, "/api/alerts/channels", admin, channelBody, http.StatusCreated},
		{"create channel bad environment", http.MethodPost, "/api/alerts/channels", admin,
			`{"type":"webhook","name":"x","webhook_url":"https://example.com/h","environments":["production"]}`, http.StatusBadRequest},
		{"list channels", http.MethodGet, "/api/alerts/channels", admin, "", http.StatusOK},
		{"suppress finding", http.MethodPost, "/api/findings/contract-suppressed/suppress", admin, suppressBody, http.StatusCreated},
		{"suppress without expiry", http.MethodPost, "/api/findings/contract-suppressed/suppress", admin, `{"reason":"contract"}`, http.StatusBadRequest},
		{"review suppression", http.MethodPost, "/api/findings/contract-suppressed/suppress/review", admin, reviewBody, http.StatusOK},
		{"list suppressions", http.MethodGet, "/api/suppressions", admin, "", http.StatusOK},
		{"list decisions", http.MethodGet, "/api/decisions", admin, "", http.StatusOK},
		{"compliance", http.MethodGet, "/api/compliance", admin, "", http.StatusOK},
		{"compliance frameworks", http.MethodGet, "/api/compliance/frameworks", viewer, "", http.StatusOK},
		{"compliance framework", http.MethodGet, "/api/compliance/frameworks/pci-dss-4.0", viewer, "", http.StatusOK},
		{"compliance framework unknown", http.MethodGet, "/api/compliance/frameworks/nope", viewer, "", http.StatusNotFound},
		{"compliance export", http.MethodGet, "/api/compliance/frameworks/nist-800-53-r5/export", admin, "", http.StatusOK},
		{"compliance export viewer", http.MethodGet, "/api/compliance/frameworks/nist-800-53-r5/export", viewer, "", http.StatusForbidden},
		{"list scans", http.MethodGet, "/api/scans", admin, "", http.StatusOK},
		{"list connectors", http.MethodGet, "/api/connectors", admin, "", http.StatusOK},
		{"llm usage", http.MethodGet, "/api/llm/usage", admin, "", http.StatusOK},
		{"llm usage bad month", http.MethodGet, "/api/llm/usage?month=13", admin, "", http.StatusBadRequest},
		{"kev additions", http.MethodGet, "/api/kev/additions?limit=5", viewer, "", http.StatusOK},
		{"kev additions bad limit", http.MethodGet, "/api/kev/additions?limit=0", viewer, "", http.StatusBadRequest},
		{"drift analyses", http.MethodGet, "/api/drift/analyses?limit=5", viewer, "", http.StatusOK},
		{"drift analyses bad since", http.MethodGet, "/api/drift/analyses?since=7d", viewer, "", http.StatusBadRequest},
		{"drift analysis unknown", http.MethodGet, "/api/drift/analyses/nope", viewer, "", http.StatusNotFound},
		{"drift analyses unauthenticated", http.MethodGet, "/api/drift/analyses", nil, "", http.StatusUnauthorized},
		{"disk scans", http.MethodGet, "/api/disk-scans?limit=5", viewer, "", http.StatusOK},
		{"disk scans bad limit", http.MethodGet, "/api/disk-scans?limit=0", viewer, "", http.StatusBadRequest},
		{"disk scans unauthenticated", http.MethodGet, "/api/disk-scans", nil, "", http.StatusUnauthorized},
		{"asset disk scan unknown", http.MethodGet, "/api/assets/nope/disk-scan", viewer, "", http.StatusNotFound},
		{"connector disk scan unknown", http.MethodGet, "/api/connectors/00000000-0000-0000-0000-000000000000/disk-scan", admin, "", http.StatusNotFound},
		{"connector disk scan viewer", http.MethodGet, "/api/connectors/00000000-0000-0000-0000-000000000000/disk-scan", viewer, "", http.StatusForbidden},
		{"create connector", http.MethodPost, "/api/connectors", admin, createBody, http.StatusCreated},
		{"graph query", http.MethodPost, "/api/graph/query", admin, `{"seed":{"types":["aws_ec2"]}}`, 0},
		{"alert context resolved", http.MethodPost, "/api/context/alert", viewer, `{"identifiers":["` + alertIP + `","10.254.254.254"]}`, http.StatusOK},
		{"alert context empty", http.MethodPost, "/api/context/alert", viewer, `{"identifiers":[]}`, http.StatusBadRequest},
		{"alert context unauthenticated", http.MethodPost, "/api/context/alert", nil, `{"identifiers":["x"]}`, http.StatusUnauthorized},
		{"unauthenticated", http.MethodGet, "/api/findings", nil, "", http.StatusUnauthorized},
		{"forbidden", http.MethodPost, "/api/connectors", viewer, createBody, http.StatusForbidden},
		{"bad request", http.MethodPost, "/api/graph/translate", admin, `not json`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(srv, tc.method, tc.path, tc.cookie, tc.body)
			if tc.status != 0 {
				require.Equalf(t, tc.status, rec.Code, "body: %s", rec.Body.String())
			}
			conformsToSpec(t, router, tc.method, tc.path, rec)
		})
	}

	// The connector created above, so the populated opt-in response (modes,
	// confirmation sentence, warning) is validated, not only the 404.
	t.Run("connector disk scan populated", func(t *testing.T) {
		list := do(srv, http.MethodGet, "/api/connectors", admin, "")
		var conns []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		require.NoError(t, json.Unmarshal(list.Body.Bytes(), &conns))
		var id string
		for _, c := range conns {
			if c.Name == "contract-aws" {
				id = c.ID
			}
		}
		require.NotEmpty(t, id, "the create connector case runs first")
		path := "/api/connectors/" + id + "/disk-scan"
		rec := do(srv, http.MethodGet, path, admin, "")
		require.Equalf(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		conformsToSpec(t, router, http.MethodGet, path, rec)
	})
}

// conformsToSpec validates one recorded response against the spec: the route must
// exist, the status must be documented, and the body must match that response's
// schema.
func conformsToSpec(t *testing.T, router routers.Router, method, path string, rec *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	route, pathParams, err := router.FindRoute(req)
	require.NoErrorf(t, err, "no spec route for %s %s — add it to openapi/", method, path)

	in := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
		},
		Status: rec.Code,
		Header: rec.Header(),
		// IncludeResponseStatus fails the validation when the status code itself
		// isn't declared for the operation — catching undocumented responses.
		Options: &openapi3filter.Options{IncludeResponseStatus: true},
	}
	in.SetBodyBytes(rec.Body.Bytes())

	err = openapi3filter.ValidateResponse(context.Background(), in)
	require.NoErrorf(t, err, "%s %s: status %d response does not conform to the spec\nbody: %s",
		method, path, rec.Code, rec.Body.String())
}

// seedAlertContextAsset ingests one ec2 instance reachable by a unique public IP
// and returns that IP. The asset is removed when the test ends.
func seedAlertContextAsset(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	ch, err := db.NewCH(ctx, chDSN, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	id := "it-contract-alertctx-" + time.Now().Format("150405.000000")
	ip := "198.51.100." + time.Now().Format("5")
	now := time.Now().Truncate(time.Second)
	require.NoError(t, asset.NewService(asset.NewCHRepo(ch)).Ingest(ctx, []asset.Asset{{
		ID: id, Name: id, Type: "ec2_instance", Provider: asset.ProviderAWS, PublicIP: ip,
		Tags: map[string]string{"environment": "prod"}, DiscoveredAt: now, LastSeen: now,
	}}, nil))
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", id) })
	return ip
}

// seedRoutedFinding records one finding on a tagged asset, with its enrich-stamped
// routing context, and returns the finding and asset ids. Both are removed when
// the test ends.
func seedRoutedFinding(t *testing.T) (findingID, assetID string) {
	t.Helper()
	ctx := context.Background()
	ch, err := db.NewCH(ctx, chDSN, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	assetID, findingID = "it-contract-routed-"+suffix, "it-contract-routed-f-"+suffix
	now := time.Now().Truncate(time.Second)
	require.NoError(t, asset.NewService(asset.NewCHRepo(ch)).Ingest(ctx, []asset.Asset{{
		ID: assetID, Name: assetID, Type: "ec2_instance", Provider: asset.ProviderAWS,
		Tags: map[string]string{"environment": "prod", "team": "Payments"}, DiscoveredAt: now, LastSeen: now,
	}}, nil))
	repo := finding.NewCHRepo(ch)
	f := finding.Finding{ID: findingID, Source: "cspm", Type: "exposure", Severity: finding.SeverityHigh,
		Title: "routed", ResourceType: "ec2_instance", ResourceID: assetID, CheckID: "contract-routed", DetectedAt: now,
		Score: 70, ScoreBand: "high", EnrichedAt: now, MustFixClass: "routine",
		OwnerTeam: "payments", OwnerSource: "tag", OwnerConfidence: "high", Environment: "prod"}
	require.NoError(t, repo.Upsert(ctx, []finding.Finding{f}))
	require.NoError(t, repo.UpsertEnrichment(ctx, []finding.Enrichment{finding.EnrichmentOf(f)}))
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", assetID)
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id = ?", findingID)
	})
	return findingID, assetID
}
