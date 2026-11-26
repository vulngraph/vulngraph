package httpsrv

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/pkginv"
)

// readAllHandler mimics a JSON handler: it reads the whole body and reports
// whether the read hit the limit.
func readAllHandler(t *testing.T, gotErr *error) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, *gotErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestWithBodyLimit_DeclaredOversizeIs413(t *testing.T) {
	var readErr error
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, readErr = io.ReadAll(r.Body)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/findings/x/suppress", bytes.NewReader(make([]byte, defaultMaxBodyBytes+1)))
	rec := httptest.NewRecorder()
	withBodyLimit(next).ServeHTTP(rec, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	require.False(t, called, "the handler must not run for a declared-oversize body")
	require.NoError(t, readErr)
}

func TestWithBodyLimit_UndeclaredOversizeIsCutOff(t *testing.T) {
	var readErr error
	req := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewReader(make([]byte, defaultMaxBodyBytes+1)))
	req.ContentLength = -1 // chunked: no declared length
	withBodyLimit(readAllHandler(t, &readErr)).ServeHTTP(httptest.NewRecorder(), req)

	var maxErr *http.MaxBytesError
	require.True(t, errors.As(readErr, &maxErr), "read past the limit must fail, got %v", readErr)
}

func TestWithBodyLimit_WithinLimitPasses(t *testing.T) {
	var readErr error
	req := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewReader(make([]byte, defaultMaxBodyBytes)))
	rec := httptest.NewRecorder()
	withBodyLimit(readAllHandler(t, &readErr)).ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.NoError(t, readErr)
}

func TestWithBodyLimit_LargerRoutesAcceptMoreThanDefault(t *testing.T) {
	for path, limit := range routeBodyLimits {
		require.Greater(t, limit, defaultMaxBodyBytes, path)
		var readErr error
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(make([]byte, 2<<20)))
		rec := httptest.NewRecorder()
		withBodyLimit(readAllHandler(t, &readErr)).ServeHTTP(rec, req)
		require.Equal(t, http.StatusNoContent, rec.Code, path)
		require.NoError(t, readErr, path)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/chat", bytes.NewReader(make([]byte, (8<<20)+1)))
	rec := httptest.NewRecorder()
	var readErr error
	withBodyLimit(readAllHandler(t, &readErr)).ServeHTTP(rec, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "per-route limits are still limits")
}

// The limit is wired into the real server chain, not only the middleware.
func TestServer_AppliesBodyLimit(t *testing.T) {
	srv := New(":0", Handlers{})
	req := httptest.NewRequest(http.MethodPost, "/healthz", bytes.NewReader(make([]byte, defaultMaxBodyBytes+1)))
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

// A package inventory may carry 10,000 packages: both routes get the larger cap,
// the asset-scoped one by path shape since its id is a path parameter.
func TestWithBodyLimit_PackageInventoryRoutes(t *testing.T) {
	for _, path := range []string{"/api/package-inventory", "/api/assets/i-0abc/package-inventory"} {
		var readErr error
		req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(make([]byte, 3<<20)))
		rec := httptest.NewRecorder()
		withBodyLimit(readAllHandler(t, &readErr)).ServeHTTP(rec, req)
		require.Equal(t, http.StatusNoContent, rec.Code, path)
		require.NoError(t, readErr, path)

		req = httptest.NewRequest(http.MethodPut, path, bytes.NewReader(make([]byte, pkginv.MaxBodyBytes+1)))
		rec = httptest.NewRecorder()
		withBodyLimit(readAllHandler(t, &readErr)).ServeHTTP(rec, req)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, path)
	}
	require.Equal(t, defaultMaxBodyBytes, bodyLimitFor("/api/assets/i-0abc/changes"), "other asset routes keep the default")
}
