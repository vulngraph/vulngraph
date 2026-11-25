package httpsrv

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/pkg/log"
)

func TestWithRequestID_GeneratesWhenAbsent(t *testing.T) {
	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = log.RequestIDFromContext(r.Context())
	})

	rec := httptest.NewRecorder()
	withRequestID(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	require.NotEmpty(t, seen, "a request ID must be generated")
	require.Equal(t, seen, rec.Header().Get("X-Request-ID"), "response echoes the same ID")
}

func TestWithRequestID_PreservesProvided(t *testing.T) {
	var seen string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = log.RequestIDFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "caller-supplied")
	rec := httptest.NewRecorder()
	withRequestID(next).ServeHTTP(rec, req)

	require.Equal(t, "caller-supplied", seen)
	require.Equal(t, "caller-supplied", rec.Header().Get("X-Request-ID"))
}

func TestWithRequestID_ReplacesUnsafeValues(t *testing.T) {
	for _, bad := range []string{
		strings.Repeat("a", 65),
		"has space",
		"line\nbreak",
		"quote\"",
		"ünicode",
		"{json}",
	} {
		var seen string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			seen = log.RequestIDFromContext(r.Context())
		})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header["X-Request-Id"] = []string{bad}
		rec := httptest.NewRecorder()
		withRequestID(next).ServeHTTP(rec, req)

		require.NotEqual(t, bad, seen, "%q must not be propagated", bad)
		require.True(t, validRequestID(seen), "replacement %q must itself be valid", seen)
		require.Equal(t, seen, rec.Header().Get("X-Request-ID"))
	}
	require.True(t, validRequestID(strings.Repeat("a", 64)))
	require.True(t, validRequestID("abc.DEF_123-x"))
}

func TestWithRecover_TurnsPanicInto500(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	rec := httptest.NewRecorder()
	require.NotPanics(t, func() {
		withRecover(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	})
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestWithRecover_PassesThroughNormalResponses(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	rec := httptest.NewRecorder()
	withRecover(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusTeapot, rec.Code)
}

func TestNewRequestID_Unique(t *testing.T) {
	require.NotEqual(t, newRequestID(), newRequestID())
}

// The named-query health probe runs ~50 queries against the graph; it must
// not be reachable anonymously.
func TestQueryHealth_RequiresAuth(t *testing.T) {
	srv := New(":0", Handlers{Auth: auth.NewHandler(nil), Explore: &explore.Handler{}})
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/graph/queries/health", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestGraphStatus_RequiresAuth(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/graph/status", nil))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHealthz(t *testing.T) {
	srv := New(":0", Handlers{}) // healthz needs no handlers
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusNoContent, rec.Code)
}

// Every server New builds bounds each connection phase, the bare
// (zero-Handlers) one included.
func TestNew_BoundsEveryConnectionPhase(t *testing.T) {
	srv := New(":0", Handlers{})
	require.Positive(t, srv.ReadHeaderTimeout)
	require.Positive(t, srv.ReadTimeout)
	require.Positive(t, srv.WriteTimeout)
	require.Positive(t, srv.IdleTimeout)
}
