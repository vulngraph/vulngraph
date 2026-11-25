// Package log is a thin wrapper around zerolog that auto-injects correlation
// IDs (run_id, request_id, trace_id, span_id) from context, so call sites
// never need to attach them by hand.
//
// Usage:
//
//	ctx = log.WithRun(ctx, runID)
//	log.FromContext(ctx).Info().Msg("dispatching signal")
//
// Every log line from FromContext also carries trace_id and span_id from
// the OpenTelemetry span in ctx, enabling click-from-log-to-trace in Grafana.
package log

import (
	"context"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/trace"
)

type ctxKey int

const (
	ctxKeyRunID ctxKey = iota
	ctxKeyRequestID
)

// WithRun attaches runID to ctx.
func WithRun(ctx context.Context, runID string) context.Context {
	if runID == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRunID, runID)
}

// WithRequestID attaches a request_id (typically the X-Request-ID header).
func WithRequestID(ctx context.Context, requestID string) context.Context {
	if requestID == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRequestID, requestID)
}

// FromContext returns a zerolog Logger pointer populated with whichever correlation
// IDs are present in ctx, plus trace_id + span_id from the OpenTelemetry span.
// Missing IDs are simply omitted from the log line.
func FromContext(ctx context.Context) *zerolog.Logger {
	logger := zlog.Logger.With()
	if v, ok := ctx.Value(ctxKeyRunID).(string); ok && v != "" {
		logger = logger.Str("run_id", v)
	}
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok && v != "" {
		logger = logger.Str("request_id", v)
	}
	if sc := trace.SpanFromContext(ctx).SpanContext(); sc.HasTraceID() {
		logger = logger.Str("trace_id", sc.TraceID().String())
		if sc.HasSpanID() {
			logger = logger.Str("span_id", sc.SpanID().String())
		}
	}
	l := logger.Logger()
	return &l
}

// RequestIDFromContext extracts the request ID from context, if set.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}
