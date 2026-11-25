package obs

import (
	"context"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/vulngraph/vulngraph/pkg/log"
)

const tracerName = "github.com/vulngraph/vulngraph"

// InitTracing sets the global OpenTelemetry tracer provider. If
// OTEL_EXPORTER_OTLP_ENDPOINT is set it builds a batched OTLP/HTTP exporter;
// otherwise it installs a no-op provider so span creation everywhere else is a
// cheap no-op with zero configuration, off by default. serviceName
// is the process role ("serve"/"worker"/"scanner"). The returned shutdown func
// flushes pending spans and must be deferred by the caller. The OTLP endpoint
// and headers are read from the standard OTEL_* env vars by the exporter itself.
func InitTracing(ctx context.Context, getenv func(string) string, serviceName string) (shutdown func(context.Context) error, err error) {
	if getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		// No-op provider: spans created via otel.Tracer(...) become no-ops.
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("graph"),
		semconv.ServiceInstanceID(serviceName),
	))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	log.FromContext(ctx).Info().Str("role", serviceName).Msg("obs: OTLP tracing enabled")
	return tp.Shutdown, nil
}

// HTTPMiddleware wraps an HTTP handler so each request is a span. It is a no-op
// in effect when tracing is disabled (the global provider is the no-op one).
func HTTPMiddleware(next http.Handler) http.Handler {
	return otelhttp.NewHandler(next, "http.request")
}

// SpanJob starts a span for a background job (River worker, correlate sweep,
// rebuild) and returns the derived context plus an end func to defer. When
// tracing is disabled this is a cheap no-op.
func SpanJob(ctx context.Context, name string) (context.Context, func()) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, name)
	return ctx, func() { span.End() }
}
