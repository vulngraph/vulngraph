package obs

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestListenAndServeExposesMetrics(t *testing.T) {
	// Tracing disabled (no OTEL env) must be a clean no-op.
	shutdown, err := InitTracing(context.Background(), func(string) string { return "" }, "test")
	if err != nil {
		t.Fatalf("InitTracing (disabled) errored: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	m := New()
	m.RegisterSources(Sources{
		QueueDepth: func(context.Context) []QueueStat { return []QueueStat{{Queue: "enrich", State: "available", N: 7}} },
		Graph:      func() GraphStats { return GraphStats{Nodes: 12345, LastBuiltUnix: 1720000000} },
		Connectors: func(context.Context) []ConnectorStat { return []ConnectorStat{{Name: "aws-prod", Stale: true}} },
	})
	m.ObserveJob("enrich", "EnrichWorker", "ok", 0.3)
	m.ObserveRebuild(12.5)

	addr := freeAddr(t)
	go func() { _ = m.ListenAndServe(t.Context(), addr) }()

	body := getWithRetry(t, "http://"+addr+"/metrics")
	for _, want := range []string{
		"graph_river_queue_depth", "graph_ladybug_node_count", "graph_connector_stale",
		"graph_job_runs_total", "graph_ladybug_rebuild_duration_seconds", "go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics output missing %q", want)
		}
	}
}

// The metrics listener is reachable by any pod in the cluster, so every
// connection phase is bounded.
func TestNewMetricsServer_BoundsEveryConnectionPhase(t *testing.T) {
	srv := newMetricsServer(":0", http.NotFoundHandler())
	for name, d := range map[string]time.Duration{
		"ReadHeaderTimeout": srv.ReadHeaderTimeout,
		"ReadTimeout":       srv.ReadTimeout,
		"WriteTimeout":      srv.WriteTimeout,
		"IdleTimeout":       srv.IdleTimeout,
	} {
		if d <= 0 {
			t.Errorf("%s unset", name)
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func getWithRetry(t *testing.T, url string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return string(b)
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s never succeeded: %v", url, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
