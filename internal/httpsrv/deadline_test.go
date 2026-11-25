package httpsrv

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithDeadline_LongRunningRoutesGetLongerDeadline(t *testing.T) {
	cases := []struct {
		method, path string
		want         time.Duration // 0 = no deadline
	}{
		{http.MethodGet, "/api/assets", requestDeadline},
		{http.MethodPost, "/api/chat", 0},
		{http.MethodPost, "/api/scans/templates/test", longRequestDeadline},
		{http.MethodPost, "/api/scans/templates/generate", longRequestDeadline},
		{http.MethodPost, "/api/decisions/abc/refine", longRequestDeadline},
		{http.MethodGet, "/api/decisions/abc/refine", requestDeadline},
		{http.MethodPost, "/api/scans/import", longRequestDeadline},
	}
	for _, tc := range cases {
		var got time.Duration
		h := withDeadline(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if dl, ok := r.Context().Deadline(); ok {
				got = time.Until(dl).Round(time.Minute)
			}
		}))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.path, nil))
		require.Equal(t, tc.want.Round(time.Minute), got, "%s %s", tc.method, tc.path)
	}
}

// A scan import may upload for longer than the server's ReadTimeout; other
// routes are still cut off by it.
func TestWithDeadline_ImportOutlivesServerReadTimeout(t *testing.T) {
	read := func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	srv := httptest.NewUnstartedServer(withDeadline(http.HandlerFunc(read)))
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)

	slowPost := func(path string) (int, error) {
		pr, pw := io.Pipe()
		go func() {
			defer func() { _ = pw.Close() }()
			for range 6 {
				time.Sleep(150 * time.Millisecond)
				if _, err := pw.Write([]byte("x")); err != nil {
					return
				}
			}
		}()
		resp, err := http.Post(srv.URL+path, "application/json", pr) //nolint:noctx // test-local server
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, nil
	}

	code, err := slowPost("/api/scans/import")
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, code, "the import body must be read past ReadTimeout")

	code, err = slowPost("/api/assets")
	if err == nil {
		require.NotEqual(t, http.StatusNoContent, code, "other routes keep the server ReadTimeout")
	}
}
