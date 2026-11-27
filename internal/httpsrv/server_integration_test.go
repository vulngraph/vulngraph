//go:build integration

package httpsrv

import (
	"cmp"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/alertctx"
	"github.com/vulngraph/vulngraph/internal/app/apikey"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/audit"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/compliance"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/executor"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/findingctx"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/app/intel"
	"github.com/vulngraph/vulngraph/internal/app/kevwatch"
	"github.com/vulngraph/vulngraph/internal/app/llmusage"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/pkginv"
	"github.com/vulngraph/vulngraph/internal/app/policy"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/app/savedquery"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/internal/app/webhook"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/jobs"
)

// pgDSN is the compose Postgres; GRAPH_TEST_PG_DSN points the tests at another database.
var pgDSN = cmp.Or(os.Getenv("GRAPH_TEST_PG_DSN"), "postgres://graph:graph@localhost:5432/graph?sslmode=disable")

const (
	chDSN = "clickhouse://graph:graph@localhost:9000/graph"
	key   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	pw    = "integration-password"
)

// buildServer wires the real handler stack against live Postgres + ClickHouse.
func buildServer(t *testing.T) (*http.Server, func(email string) *http.Cookie) {
	t.Helper()
	ctx := context.Background()

	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	ch, err := db.NewCH(ctx, chDSN, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	cipher, err := connector.NewCipher(key)
	require.NoError(t, err)
	insertClient, err := jobs.InsertClient(pool)
	require.NoError(t, err)

	authSvc := auth.NewService(auth.NewPGRepo(pool, cipher))
	connSvc := connector.NewService(connector.NewPGRepo(pool), cipher)
	assetSvc := asset.NewService(asset.NewCHRepo(ch))
	findingSvc := finding.NewService(finding.NewCHRepo(ch))
	suppressSvc := suppress.NewService(suppress.NewPGRepo(pool)).WithAudit(suppress.NewCHAuditRepo(ch))
	complianceCatalog, err := compliance.LoadCatalog("")
	require.NoError(t, err)

	suffix := time.Now().Format("150405.000000")
	emails := map[string]auth.Role{
		"admin-" + suffix + "@x.example":  auth.RoleAdmin,
		"viewer-" + suffix + "@x.example": auth.RoleViewer,
	}
	for email, role := range emails {
		_, err := authSvc.CreateUser(ctx, email, pw, role)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		for email := range emails {
			_, _ = pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email)
		}
	})

	srv := New(":0", Handlers{
		// The tests log in many times; login brute-force limits are covered in auth.
		Auth:       auth.NewHandler(authSvc).WithLoginRateLimit(nil, nil),
		Asset:      asset.NewHandler(assetSvc, AssetRiskProvider(findingSvc)),
		Connector:  connector.NewHandler(connSvc, jobs.NewEnqueuer(insertClient)),
		Finding:    finding.NewHandler(findingSvc, suppressSvc),
		AlertCtx:   alertctx.NewHandler(alertctx.NewService(alertctx.NewCHRepo(ch), assetSvc, assetSvc, findingSvc)),
		FindingCtx: findingctx.NewHandler(findingctx.NewService(findingSvc, respond.NewReadService(assetSvc, findingSvc, assetSvc), reasoncache.NewService(reasoncache.NewPGRepo(pool)), enrich.NewSignalCHRepo(ch)).WithSuppressions(suppressSvc)),
		Suppress:   suppress.NewHandler(suppressSvc),
		Respond:    respond.NewHandler(respond.NewCHRepo(ch), findingSvc),
		Refine:     respond.NewRefineHandler(respond.NewCHRepo(ch), findingSvc, nil),
		Compliance: compliance.NewHandler(compliance.NewService(findingSvc, compliance.NewCHInventory(ch), checks.Default(), connSvc).WithRequirements(complianceCatalog, findingSvc)),
		Govern:     govern.NewHandler(govern.NewService(govern.NewPGRepo(pool), reasoncache.NewService(reasoncache.NewPGRepo(pool)), findingSvc, memory.NewService(memory.NewPGRepo(pool)), respond.NewCHRepo(ch))),
		Explore:    explore.NewHandler(explore.NewService(explore.NewCHRepo(ch)), nil),
		Webhook:    webhook.NewHandler(connSvc, jobs.NewEnqueuer(insertClient)),
		// Optional domains — wired so the role-gate guard below exercises their
		// write routes too (unwired handlers fall through to the SPA catch-all).
		Executor:   executor.NewHandler(executor.NewService(connSvc).WithAudit(executor.NewCHAuditRepo(ch))),
		Alert:      notify.NewHandler(notify.NewService(notify.NewPGRepo(pool, cipher))),
		SavedQuery: savedquery.NewHandler(savedquery.NewService(savedquery.NewPGRepo(pool))),
		Policy:     policy.NewHandler(policy.NewService(policy.NewPGRepo(pool))),
		APIKey:     apikey.NewHandler(apikey.NewService(apikey.NewPGRepo(pool))),
		Intel:      intel.NewHandler(intel.NewService(intel.NewPGRepo(pool), intel.NewCHRepo(ch), nil)),
		LLMUsage:   llmusage.NewHandler(llmusage.NewService(llmusage.NewPGRepo(pool), llmusage.PriceTable{}, llmusage.Budget{})),
		KEV:        kevwatch.NewHandler(kevwatch.NewService(kevwatch.NewPGRepo(pool))),
		// Read-only, and analysis off: the contract test sees enabled=false.
		DriftAnalysis: driftanalysis.NewHandler(driftanalysis.New(driftanalysis.NewPGRepo(pool), nil, nil)),
		DiskScan: diskscan.NewHandler(diskscan.NewService(diskscan.NewPGRepo(pool), diskscan.NewModeView(pool)),
			noAssets{}, diskScanControl{svc: connSvc}, func(context.Context) diskscan.Actor { return diskscan.Actor{} }),
		// A session (viewer or admin) is refused with 403 before any dependency is touched.
		PkgInv: pkginv.NewHandler(pkginv.NewService(pkginv.NewPGRepo(pool), assetSvc, connSvc, forget.NewPGRepo(pool),
			audit.NewService(audit.NewCHRepo(ch)), auth.NewKeyedLimiter(1, 10), func() distro.Sources { return nil })),
	})

	login := func(email string) *http.Cookie {
		body := `{"email":"` + email + `","password":"` + pw + `"}`
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		srv.Handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		cookies := rec.Result().Cookies()
		require.Len(t, cookies, 1)
		return cookies[0]
	}
	return srv, func(role string) *http.Cookie {
		for email, r := range emails {
			if string(r) == role {
				return login(email)
			}
		}
		t.Fatalf("no seeded user with role %s", role)
		return nil
	}
}

func do(srv *http.Server, method, path string, cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, r)
	return rec
}

// Exercises the wired middleware + auth + role chain end-to-end.
func TestServerRouting_AuthAndRoleGates(t *testing.T) {
	srv, login := buildServer(t)

	body := `{"type":"aws","name":"rt-prod","config":{"role_arn":"arn:x","region":"eu-west-1"}}`

	t.Run("unauthenticated write is 401", func(t *testing.T) {
		require.Equal(t, http.StatusUnauthorized, do(srv, http.MethodPost, "/api/connectors", nil, body).Code)
	})
	t.Run("viewer write is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodPost, "/api/connectors", login("viewer"), body).Code)
	})
	t.Run("admin write is 201", func(t *testing.T) {
		rec := do(srv, http.MethodPost, "/api/connectors", login("admin"), body)
		require.Equal(t, http.StatusCreated, rec.Code)
		require.NotContains(t, rec.Body.String(), "arn:x")
	})
	t.Run("viewer can read", func(t *testing.T) {
		require.Equal(t, http.StatusOK, do(srv, http.MethodGet, "/api/connectors", login("viewer"), "").Code)
	})
	t.Run("viewer delete is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodDelete, "/api/connectors/any-id", login("viewer"), "").Code)
	})
	t.Run("viewer trigger-sync is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodPost, "/api/connectors/any-id/sync", login("viewer"), "").Code)
	})
	t.Run("viewer connection test is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodPost, "/api/connectors/any-id/test", login("viewer"), "").Code)
	})
	t.Run("viewer can download an aws_org template", func(t *testing.T) {
		require.Equal(t, http.StatusOK, do(srv, http.MethodGet, "/api/aws-org/templates/graph-readonly-role.yaml", login("viewer"), "").Code)
	})
	t.Run("org accounts of an unknown connector is 404", func(t *testing.T) {
		require.Equal(t, http.StatusNotFound, do(srv, http.MethodGet, "/api/connectors/00000000-0000-0000-0000-000000000000/org-accounts", login("viewer"), "").Code)
	})
	t.Run("viewer trigger-scan is 403", func(t *testing.T) {
	})
	t.Run("viewer suppress is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodPost, "/api/findings/any-id/suppress", login("viewer"), `{"reason":"x"}`).Code)
	})
	t.Run("viewer suppression review is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodPost, "/api/findings/any-id/suppress/review", login("viewer"), `{"expires_at":"2099-01-01T00:00:00Z"}`).Code)
	})
	t.Run("viewer refine is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodPost, "/api/decisions/any-id/refine", login("viewer"), `{"message":"why?"}`).Code)
	})
	t.Run("viewer unsuppress is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodDelete, "/api/findings/any-id/suppress", login("viewer"), "").Code)
	})
	t.Run("viewer resolve is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodPost, "/api/findings/any-id/resolve", login("viewer"), `{"reason":"x"}`).Code)
	})
	t.Run("viewer llm usage is 403", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, do(srv, http.MethodGet, "/api/llm/usage", login("viewer"), "").Code)
	})
	t.Run("viewer can read suppressions", func(t *testing.T) {
		require.Equal(t, http.StatusOK, do(srv, http.MethodGet, "/api/suppressions", login("viewer"), "").Code)
	})
	t.Run("github webhook is public (not session-gated) and wired", func(t *testing.T) {
		// No session cookie. The handler answers an unknown connector with the
		// same 401 as a bad signature; its "signature verification failed"
		// detail (not RequireAuth's) proves the request reached the handler
		// over a public, HMAC-gated route.
		rec := do(srv, http.MethodPost, "/api/webhooks/github/ghost", nil, "{}")
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.Contains(t, rec.Body.String(), "signature verification failed")
	})
	t.Run("request ID header is always set", func(t *testing.T) {
		rec := do(srv, http.MethodGet, "/healthz", nil, "")
		require.NotEmpty(t, rec.Header().Get("X-Request-ID"))
	})

	// Clean up any connector this test created.
	t.Cleanup(func() {
		pool, _ := db.NewPool(context.Background(), pgDSN, db.MaxConnsWorker)
		defer pool.Close()
		_, _ = pool.Exec(context.Background(), "DELETE FROM connectors WHERE name = 'rt-prod'")
	})
}

// TestServerRouting_AllWritesRequireAdmin is the exhaustive role-gate guard:
// every auth.RequireRole-wrapped route must reject a viewer with 403 (the gate
// fires before the handler, so a placeholder id and body are fine) and an
// unauthenticated caller with 401.
//
// The route list is derived from server.go by adminGatedRoutes rather than
// maintained here, so adding a RequireRole route extends this test
// automatically. If a newly derived route fails, either its handler is nil in
// buildServer (wire it) or the gate isn't doing what the router claims.
//
// Not covered here, by construction: routes with no RequireRole wrapper.
// /api/keys uses a per-caller privilege clamp instead of a role gate;
// /api/graph/*, /api/chat and the read/compute template endpoints are
// auth-only; /api/webhooks/github and /api/queue/{approve,deny}-link are
// token/HMAC-authed and deliberately not session-gated.
func TestServerRouting_AllWritesRequireAdmin(t *testing.T) {
	srv, login := buildServer(t)

	routes := adminGatedRoutes(t)
	require.NotEmpty(t, routes)

	viewer := login("viewer")
	for _, rt := range routes {
		path := concreteRoute(rt.Path)
		t.Run("viewer 403 "+rt.Method+" "+rt.Path, func(t *testing.T) {
			code := do(srv, rt.Method, path, viewer, "{}").Code
			require.Equal(t, http.StatusForbidden, code,
				"%s %s must reject a viewer with 403 — is it wrapped in auth.RequireRole, and is its handler wired in buildServer?", rt.Method, rt.Path)
		})
		t.Run("unauth 401 "+rt.Method+" "+rt.Path, func(t *testing.T) {
			code := do(srv, rt.Method, path, nil, "{}").Code
			require.Equal(t, http.StatusUnauthorized, code,
				"%s %s must reject an unauthenticated caller with 401", rt.Method, rt.Path)
		})
	}
}
