package httpsrv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/alertctx"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/mcp"
)

func post(srv *http.Server, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	return rec
}

// MCP's LLM-backed tool spends from the SAME per-user limiter as the other
// LLM routes: a user who has spent it elsewhere cannot keep going over MCP.
func TestMCPGraphQuery_SharesTheLLMLimiter(t *testing.T) {
	srv := New(":0", Handlers{
		Auth:     auth.NewHandlerBypass(),
		Explore:  &explore.Handler{},
		MCP:      mcp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil),
		Security: SecurityConfig{LLMLimiter: auth.NewKeyedLimiter(1, 1)},
	})
	require.NotEqual(t, http.StatusTooManyRequests, post(srv, "/api/graph/translate", `{}`).Code)

	rec := post(srv, "/api/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"graph_query","arguments":{"question":"q"}}}`)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "rate limited", "the graph_query handler must not run")

	rec = post(srv, "/api/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	require.NotContains(t, rec.Body.String(), "rate limited", "cheap methods are not limited")
}

// Alert context runs an unindexed attribute scan: budgeted per user.
func TestAlertContext_IsBudgetedPerUser(t *testing.T) {
	srv := New(":0", Handlers{
		Auth:     auth.NewHandlerBypass(),
		AlertCtx: alertctx.NewHandler(nil),
		MCP:      mcp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil),
		Security: SecurityConfig{AlertContextLimiter: auth.NewKeyedLimiter(1, 1)},
	})
	require.Equal(t, http.StatusBadRequest, post(srv, "/api/context/alert", `not json`).Code, "the first call reaches the handler")
	require.Equal(t, http.StatusTooManyRequests, post(srv, "/api/context/alert", `not json`).Code)
}

// The REST routes that run on the caller-Cypher pool, and the MCP run_cypher
// tool, share one per-user budget; the second call gets 429 with Retry-After.
func TestCypherRoutes_AreBudgetedPerUser(t *testing.T) {
	newSrv := func() *http.Server {
		return New(":0", Handlers{
			Auth:     auth.NewHandlerBypass(),
			Explore:  &explore.Handler{},
			MCP:      mcp.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil),
			Security: SecurityConfig{CypherLimiter: auth.NewKeyedLimiter(1, 1)},
		})
	}
	for _, path := range []string{"/api/graph/cypher"} {
		srv := newSrv()
		require.NotEqual(t, http.StatusTooManyRequests, post(srv, path, `{}`).Code, "the first call reaches the handler")
		rec := post(srv, path, `{}`)
		require.Equal(t, http.StatusTooManyRequests, rec.Code)
		require.NotEmpty(t, rec.Header().Get("Retry-After"))
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/graph/queries/health"},
		{http.MethodGet, "/api/dspm/summary"},
		{http.MethodGet, "/api/dspm/stores"},
	} {
		srv := newSrv()
		get := func() *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
			return rec
		}
		require.NotEqual(t, http.StatusTooManyRequests, get().Code, c.path)
		rec := get()
		require.Equal(t, http.StatusTooManyRequests, rec.Code, c.path)
		require.NotEmpty(t, rec.Header().Get("Retry-After"), c.path)
	}
}

type okCypher struct{}

func (okCypher) RunCypher(context.Context, string, int, int) (explore.Result, error) {
	return explore.Result{}, nil
}

func TestCypherBudget_IsSharedWithMCPRunCypher(t *testing.T) {
	srv := New(":0", Handlers{
		Auth:     auth.NewHandlerBypass(),
		Explore:  &explore.Handler{},
		MCP:      mcp.NewHandler(nil, nil, nil, nil, nil, okCypher{}, nil, nil, nil, nil, nil),
		Security: SecurityConfig{CypherLimiter: auth.NewKeyedLimiter(1, 1)},
	})
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_cypher","arguments":{"query":"MATCH (n:Asset) RETURN n LIMIT 1"}}}`
	rec := post(srv, "/api/mcp", call)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "rate limited")

	require.Equal(t, http.StatusTooManyRequests, post(srv, "/api/graph/cypher", `{}`).Code, "REST shares the MCP caller's bucket")
	rec = post(srv, "/api/mcp", call)
	require.Contains(t, rec.Body.String(), "rate limited")
	require.Contains(t, rec.Body.String(), "-32029")
}
