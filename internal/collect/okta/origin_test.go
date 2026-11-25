package okta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrgURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		wantErr  bool
	}{
		{"dev-123.okta.com", "https://dev-123.okta.com", false},
		{"https://dev-123.okta.com/", "https://dev-123.okta.com", false},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", false},
		{"http://localhost:9000", "http://localhost:9000", false},
		{"http://[::1]:9000", "http://[::1]:9000", false},
		{"http://dev-123.okta.com", "", true},
		{"http://10.0.0.5", "", true},
		{"ftp://dev-123.okta.com", "", true},
		{"https://", "", true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := orgURL(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestCollect_RefusesPlainHTTPDomain(t *testing.T) {
	c := New()
	_, err := c.Collect(context.Background(), map[string]string{"domain": "http://dev-123.okta.com", "api_token": "t"})
	require.ErrorContains(t, err, "https")
}

// A Link rel="next" pointing at another host must not receive the SSWS token,
// and the listing fails rather than reading as complete.
func TestCollect_RefusesCrossOriginNextPage(t *testing.T) {
	var foreignHits int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&foreignHits, 1)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer foreign.Close()

	org := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<`+foreign.URL+`/api/v1/users?after=x>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer org.Close()

	c := &Collector{client: org.Client()}
	_, err := c.Collect(context.Background(), map[string]string{"domain": org.URL, "api_token": "t"})
	require.ErrorContains(t, err, "not on the Okta org origin")
	require.Zero(t, atomic.LoadInt32(&foreignHits), "the token must never reach another host")
}

func TestCollect_FollowsSameOriginNextPage(t *testing.T) {
	var srvURL string
	var pages int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/users" && r.URL.Query().Get("after") == "" {
			atomic.AddInt32(&pages, 1)
			w.Header().Set("Link", `<`+srvURL+`/api/v1/users?after=x>; rel="next"`)
		} else if r.URL.Path == "/api/v1/users" {
			atomic.AddInt32(&pages, 1)
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	srvURL = srv.URL

	c := &Collector{client: srv.Client()}
	_, err := c.Collect(context.Background(), map[string]string{"domain": srv.URL, "api_token": "t"})
	require.NoError(t, err)
	require.Equal(t, int32(2), atomic.LoadInt32(&pages))
}
