package httpsrv

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
})

func csrfRequest(method, path, body string, headers map[string]string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Host = "graph.example.com"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestCSRF(t *testing.T) {
	jsonSameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin", "Content-Type": "application/json"}
	for _, tc := range []struct {
		name    string
		method  string
		path    string
		body    string
		headers map[string]string
		want    int
	}{
		{"same-origin JSON POST", "POST", "/api/users", `{}`, jsonSameOrigin, http.StatusNoContent},
		{"JSON with charset", "POST", "/api/users", `{}`,
			map[string]string{"Sec-Fetch-Site": "same-origin", "Content-Type": "application/json; charset=utf-8"}, http.StatusNoContent},
		{"login is covered", "POST", "/api/auth/login", `{}`,
			map[string]string{"Sec-Fetch-Site": "cross-site", "Content-Type": "application/json"}, http.StatusForbidden},
		{"cross-site POST", "POST", "/api/users", `{}`,
			map[string]string{"Sec-Fetch-Site": "cross-site", "Content-Type": "application/json"}, http.StatusForbidden},
		{"same-site subdomain POST", "DELETE", "/api/keys/1", "",
			map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"foreign Origin without fetch metadata", "POST", "/api/users", `{}`,
			map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}, http.StatusForbidden},
		{"matching Origin without fetch metadata", "POST", "/api/users", `{}`,
			map[string]string{"Origin": "http://graph.example.com", "Content-Type": "application/json"}, http.StatusNoContent},
		{"configured allowed origin", "POST", "/api/users", `{}`,
			map[string]string{"Origin": "https://ui.example.com", "Sec-Fetch-Site": "cross-site", "Content-Type": "application/json"}, http.StatusNoContent},
		{"text/plain form post", "POST", "/api/auth/login", `{"email":"a"}`,
			map[string]string{"Sec-Fetch-Site": "same-origin", "Content-Type": "text/plain"}, http.StatusBadRequest},
		{"urlencoded form post", "POST", "/api/users", `a=b`,
			map[string]string{"Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded"}, http.StatusBadRequest},
		{"body without content type", "POST", "/api/users", `{}`,
			map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusBadRequest},
		{"body-less same-origin POST", "POST", "/api/connectors", "",
			map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusNoContent},
		{"GET is never checked", "GET", "/api/users", "",
			map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusNoContent},
		{"non-API path is not checked", "POST", "/somewhere", "x",
			map[string]string{"Sec-Fetch-Site": "cross-site", "Content-Type": "text/plain"}, http.StatusNoContent},
		{"API key client without fetch metadata", "POST", "/api/mcp", `x`,
			map[string]string{"Authorization": "Bearer gph_x", "Content-Type": "text/plain"}, http.StatusNoContent},
		{"session bearer client without fetch metadata", "POST", "/api/connectors", `x`,
			map[string]string{"Authorization": "Bearer c2Vzc2lvbi10b2tlbg==", "Content-Type": "text/plain"}, http.StatusNoContent},
		{"API key JSON client", "POST", "/api/users", `{}`,
			map[string]string{"Authorization": "Bearer gph_x", "Content-Type": "application/json"}, http.StatusNoContent},
		{"cross-site with API key bearer", "POST", "/api/mcp", `x`,
			map[string]string{"Sec-Fetch-Site": "cross-site", "Authorization": "Bearer gph_x", "Content-Type": "text/plain"}, http.StatusForbidden},
		{"cross-site form with proxy-injected JWT", "POST", "/api/users", `{"role":"admin"}`,
			map[string]string{"Sec-Fetch-Site": "cross-site", "Authorization": "Bearer aaa.bbb.ccc", "Content-Type": "text/plain"}, http.StatusForbidden},
		{"foreign Origin with proxy-injected JWT", "POST", "/api/users", `{}`,
			map[string]string{"Origin": "https://evil.example", "Authorization": "Bearer aaa.bbb.ccc", "Content-Type": "application/json"}, http.StatusForbidden},
		{"same-origin text/plain with proxy-injected JWT", "POST", "/api/users", `{}`,
			map[string]string{"Sec-Fetch-Site": "same-origin", "Authorization": "Bearer aaa.bbb.ccc", "Content-Type": "text/plain"}, http.StatusBadRequest},
		{"same-origin JSON with proxy-injected JWT", "POST", "/api/users", `{}`,
			map[string]string{"Sec-Fetch-Site": "same-origin", "Authorization": "Bearer aaa.bbb.ccc", "Content-Type": "application/json"}, http.StatusNoContent},
		{"github webhook is exempt", "POST", "/api/webhooks/github/abc", `{}`,
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusNoContent},
		{"approve-link form post is exempt", "POST", "/api/queue/approve-link/tok", "",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Sec-Fetch-Site": "same-origin"}, http.StatusNoContent},
		{"deny-link form post is exempt", "POST", "/api/queue/deny-link/tok", "",
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			withCSRF([]string{"https://ui.example.com"}, okHandler).
				ServeHTTP(rec, csrfRequest(tc.method, tc.path, tc.body, tc.headers))
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}
}

func TestSecurityConfigValidate(t *testing.T) {
	require.NoError(t, SecurityConfig{AllowedOrigins: []string{"https://a.example.com"}}.Validate())
	require.Error(t, SecurityConfig{AllowedOrigins: []string{"a.example.com/path"}}.Validate())
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	withSecurityHeaders(false, okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	h := rec.Header()
	csp := h.Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'self'", "script-src 'self';", "frame-ancestors 'none'", "base-uri 'self'", "object-src 'none'"} {
		require.Contains(t, csp, d)
	}
	require.NotContains(t, csp, "script-src 'self' 'unsafe-inline'")
	require.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	require.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
	require.NotEmpty(t, h.Get("Permissions-Policy"))
	require.Empty(t, h.Get("Strict-Transport-Security"), "no HSTS over plain HTTP without a TLS proxy")

	rec = httptest.NewRecorder()
	withSecurityHeaders(true, okHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, hstsValue, rec.Header().Get("Strict-Transport-Security"))

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	withSecurityHeaders(false, okHandler).ServeHTTP(rec, req)
	require.Equal(t, hstsValue, rec.Header().Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_OnRejectedAPIRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/me", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.NotEmpty(t, rec.Header().Get("Content-Security-Policy"))
}

func TestHostAllowlist(t *testing.T) {
	h := withHostAllowlist([]string{"localhost", "127.0.0.1", "[::1]", "Graph.Internal"}, okHandler)
	for host, want := range map[string]int{
		"localhost:8080":      http.StatusNoContent,
		"127.0.0.1:8080":      http.StatusNoContent,
		"[::1]:8080":          http.StatusNoContent,
		"graph.internal":      http.StatusNoContent,
		"attacker.example":    http.StatusForbidden,
		"attacker.example:80": http.StatusForbidden,
		"localhost.evil.com":  http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, want, rec.Code, host)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Host = "10.0.0.7:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code, "probes dial the pod IP")

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "anything"
	rec = httptest.NewRecorder()
	withHostAllowlist(nil, okHandler).ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code, "no allowlist means no check")
}

func TestLLMRoutesAreBudgetedPerUser(t *testing.T) {
	srv := New(":0", Handlers{
		Auth:     auth.NewHandlerBypass(),
		Explore:  &explore.Handler{},
		Security: SecurityConfig{LLMLimiter: auth.NewKeyedLimiter(1, 1)},
	})
	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/graph/translate", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, req)
		return rec.Code
	}
	require.NotEqual(t, http.StatusTooManyRequests, post())
	require.Equal(t, http.StatusTooManyRequests, post())
}
