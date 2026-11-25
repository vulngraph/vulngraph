package main

import (
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// pprofWriteTimeout bounds writing one profile. A ?seconds= capture on
// /debug/pprof/profile, /trace or a delta profile does not count against it:
// net/http/pprof extends the write deadline by the requested duration.
const pprofWriteTimeout = 2 * time.Minute

// newPprofServer serves net/http/pprof on addr with every connection phase
// bounded.
func newPprofServer(addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      pprofWriteTimeout,
		IdleTimeout:       2 * time.Minute,
	}
}

// pprofAddr is the loopback-only listen address for PPROF_PORT.
func pprofAddr(port string) string {
	return net.JoinHostPort("127.0.0.1", port)
}
