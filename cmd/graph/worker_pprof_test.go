package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// pprof exposes memory contents and on-demand CPU profiling: it must never
// listen beyond loopback.
func TestPprofAddr_LoopbackOnly(t *testing.T) {
	require.Equal(t, "127.0.0.1:6060", pprofAddr("6060"))
}

// Every connection phase on the pprof listener is bounded, and a CPU capture
// longer than the write timeout still completes: net/http/pprof extends the
// write deadline by the requested ?seconds=.
func TestNewPprofServer_BoundedAndCapturesOutlastWriteTimeout(t *testing.T) {
	srv := newPprofServer(pprofAddr("6060"))
	require.Equal(t, "127.0.0.1:6060", srv.Addr)
	require.Positive(t, srv.ReadHeaderTimeout)
	require.Positive(t, srv.ReadTimeout)
	require.Positive(t, srv.IdleTimeout)
	require.Equal(t, pprofWriteTimeout, srv.WriteTimeout)

	ts := httptest.NewUnstartedServer(srv.Handler)
	ts.Config.WriteTimeout = time.Second
	ts.Start()
	defer ts.Close()
	resp, err := ts.Client().Get(ts.URL + "/debug/pprof/profile?seconds=2")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
