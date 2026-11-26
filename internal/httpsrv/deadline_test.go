package httpsrv

import (
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
		{http.MethodPost, "/api/decisions/abc/refine", longRequestDeadline},
		{http.MethodGet, "/api/decisions/abc/refine", requestDeadline},
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
