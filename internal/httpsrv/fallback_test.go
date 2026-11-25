package httpsrv

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

func newTestServer() *http.Server {
	return New(":0", Handlers{Auth: auth.NewHandler(nil), Explore: &explore.Handler{}})
}

func TestAPIFallback_UnknownPathIsProblem404(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/does-not-exist", nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
}

func TestAPIFallback_WrongMethodIsProblem405(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/login", nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	require.Equal(t, "POST", rec.Header().Get("Allow"))
}

func TestAPIFallback_NonAPIPathStillServesSPA(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/findings", nil))
	require.NotEqual(t, "application/problem+json", rec.Header().Get("Content-Type"))
}
