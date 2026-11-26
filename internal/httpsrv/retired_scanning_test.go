package httpsrv

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetiredScanningEndpointsAreUnavailable(t *testing.T) {
	srv := New(":0", Handlers{})
	for _, path := range []string{"/api/scans", "/api/scans/import", "/api/scans/templates", "/api/scans/templates/test", "/api/scans/templates/validate", "/api/scans/templates/generate", "/api/scan-profiles", "/api/workflows/presets"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, path, nil)
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, req)
			require.Equal(t, http.StatusNotFound, rec.Code, "%s %s", method, path)
			require.Equal(t, defaultMaxBodyBytes, bodyLimitFor(path))
			require.False(t, isLongRunning(req))
		}
	}
}
