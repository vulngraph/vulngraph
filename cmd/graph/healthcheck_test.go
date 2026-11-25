package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func healthServer(t *testing.T, status int) func(string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	return func(k string) string {
		if k == "ADDR" {
			return ":" + port
		}
		return ""
	}
}

func TestHealthcheck_OK(t *testing.T) {
	getenv := healthServer(t, http.StatusNoContent)
	require.NoError(t, run(context.Background(), []string{"graph", "healthcheck"}, getenv))
}

func TestHealthcheck_Non2xxFails(t *testing.T) {
	getenv := healthServer(t, http.StatusServiceUnavailable)
	require.ErrorContains(t, run(context.Background(), []string{"graph", "healthcheck"}, getenv), "503")
}

func TestHealthcheck_NothingListeningFails(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	_, port, _ := net.SplitHostPort(addr)
	getenv := func(k string) string {
		if k == "ADDR" {
			return ":" + port
		}
		return ""
	}
	require.Error(t, healthcheck(context.Background(), nil, getenv))
}

// The worker's exec readiness probe hits Ladybug readiness on the internal port,
// so the NetworkPolicy need not admit node addresses to that port.
func TestHealthcheck_Worker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/graph/ready" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	getenv := func(k string) string {
		if k == "LADYBUG_INTERNAL_PORT" {
			return port
		}
		return ""
	}
	require.NoError(t, run(context.Background(), []string{"graph", "healthcheck", "worker"}, getenv))
	require.Error(t, run(context.Background(), []string{"graph", "healthcheck", "bogus"}, getenv))
}

func TestHealthcheckURL(t *testing.T) {
	u, err := healthcheckURL(":8080")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8080/healthz", u)
	u, err = healthcheckURL("0.0.0.0:9090")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:9090/healthz", u)
	_, err = healthcheckURL("8080")
	require.Error(t, err)
}
