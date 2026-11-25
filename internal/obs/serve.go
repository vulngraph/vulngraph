package obs

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// ListenAndServe runs the /metrics endpoint on addr until ctx is cancelled,
// with no auth. Callers bind it on METRICS_PORT on all interfaces, so it is not
// behind the Service or Ingress but any pod in the cluster can reach it unless
// the chart's networkPolicy.metricsNamespace limits it to the scraper's
// namespace. Blocks; run in a goroutine. A nil Metrics is a no-op (returns
// immediately).
func (m *Metrics) ListenAndServe(ctx context.Context, addr string) error {
	if m == nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{}))
	srv := newMetricsServer(addr, mux)
	// Deferred recover, not cmd/graph's safego: safego is package main and this is
	// a library package. This goroutine outlives every request, and an unrecovered
	// panic in it takes down the whole single-binary process — losing the metrics
	// listener AND everything else in the pod. Same shape as the shutdown watcher
	// in cmd/graph/worker.go, which safego already covers.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.FromContext(ctx).Error().Str("goroutine", "obs-metrics-shutdown").
					Interface("panic", r).Msg("background goroutine panicked — recovered, subsystem is now stopped")
			}
		}()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	log.FromContext(ctx).Info().Str("addr", addr).Msg("obs: metrics listener started")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func newMetricsServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}
