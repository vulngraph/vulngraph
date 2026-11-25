# ADR 037 — Vendor-neutral observability (metrics + tracing)

**Status:** accepted (implemented 2026-07-06) · amended 2026-07-07 (feed freshness), 2026-08-24
(the scanner pod), 2026-08-25 (restart-gap alert wrapping). Supersedes the "no metrics
endpoint, no tracing libraries" clause of [ADR 008](008-no-monitoring-stack.md).

## Context

ADR 008 rejected a monitoring stack: for a single binary, structured
logs + the audit trail + River's job tables were enough, and it explicitly noted
*"if a metrics endpoint is ever genuinely needed, it is one additive handler —
the decision can be reversed cheaply."* That need has arrived. Logs cannot answer
some operational questions at a glance: a growing enrich backlog or a gradual
worker memory climb (ending in an OOM kill) is invisible until it causes harm,
and there is no way to watch queue depth, graph rebuild latency, or connector
freshness as time series or alert on them. A vendor-specific SDK (e.g. Datadog)
was considered and rejected — it is the wrong shape for a self-hostable,
open-source tool whose operators run a variety of monitoring stacks.

## Decision

Add observability that is **vendor-neutral and off by default**, gated by
environment variables exactly like the existing pprof listener:

- **Metrics:** a Prometheus-text `/metrics` endpoint (via
  `prometheus/client_golang`) on an internal, pod-only listener gated by
  `METRICS_PORT` — never Ingress-reachable, so no auth, mirroring the pprof and
  Ladybug-RPC ports. Exposed by both the `serve` and `worker` processes. Metrics:
  River queue depth (the enrich/respond depths are the enrichment/reasoning
  backlog signal), Ladybug node count + rebuild duration + last-built timestamp,
  per-job run counters and duration histograms, connector staleness,
  per-intel-feed last-successful-refresh timestamp, and the standard
  Go runtime/process collectors.
- **Tracing:** OpenTelemetry spans exported over OTLP/HTTP, initialised only when
  `OTEL_EXPORTER_OTLP_ENDPOINT` (or the traces-specific variant) is set; otherwise
  a no-op tracer provider is installed so span creation everywhere is a cheap
  no-op with zero configuration. HTTP requests are spanned via `otelhttp`; every
  River job, the correlate sweep, and the Ladybug rebuild get a span through a global
  River middleware and a small `obs.SpanJob` helper. `pkg/log` already injects
  `trace_id`/`span_id` into every log line, so logs and traces correlate with no
  further work.

The implementation lives in a new leaf package `internal/obs` (no internal domain
imports; live-state gauges are read on scrape through caller-supplied `Sources`
callbacks, so `obs` never depends on `jobs`/`graphstore`/`connector`).

No error-tracking stack (Sentry/GlitchTip) — that part of ADR 008 stands.

### Amendment (2026-07-07) — feed freshness

"Is each intel feed actually still updating?" is answered directly by
`graph_feed_last_success_timestamp_seconds{feed="kev|osv|epss|scc|domain_monitor"}` —
a gauge stamped by the job middleware on each *successful* feed-refresh job (derived
from the job kind, so no per-feed worker knows about metrics; a failed refresh does
not stamp, so a stuck feed goes stale). A feed that has never succeeded in the
process has no sample, which the alert below also catches. Example Prometheus rule
(cadences: KEV/OSV/EPSS/SCC daily, domain_monitor 6h):

```
- alert: IntelFeedStale
  expr: |
    time() - graph_feed_last_success_timestamp_seconds{feed=~"kev|osv|epss|scc"} > 36*3600
    or time() - graph_feed_last_success_timestamp_seconds{feed="domain_monitor"} > 12*3600
    or absent(graph_feed_last_success_timestamp_seconds)
  for: 30m
  labels: { severity: warning }
  annotations: { summary: "Intel feed {{ $labels.feed }} has not refreshed within its cadence" }
```

### Amendment (2026-08-24) — the scanner pod

"Exposed by both the `serve` and `worker` processes" (above) no longer covers
every process once `cmd/graph scanner` — the isolated pod that owns nuclei
execution so its CPU/memory spikes cannot affect the main worker — was split
out. The chart already set `METRICS_PORT`, a container port, and
`prometheus.io/*` scrape annotations for it, but the Go side had no `obs.New()`,
no listener, and `internal/jobs.ScanDeps`/`NewScanClient` had no `Middleware`
hook, so a listener alone would not have produced job-run metrics. In the split
topology (`SCAN_WORKER_DISABLED` on the main worker) this pod runs all nuclei
execution, so "did nuclei run at all?" needs series from it.

The scanner now works the same way `serve` and `worker` do: `obs.InitTracing` +
`obs.New()` + the env-gated `METRICS_PORT` listener, and a `Metrics
*obs.Metrics` field added to `ScanDeps` feeding the identical
`obsMiddleware`/`river.Config.Middleware` wiring `NewClient` already used for
the worker. No chart changes were needed — the port, annotations, and
`component=scanner` label were already there, unanswered.

### Amendment (2026-08-25) — restart-gap alert wrapping

In the Helm chart, `graph-worker` is `replicas:1`/`maxSurge:0` and `graph-scanner` uses a
`Recreate` strategy, so every routine deploy of either pod is a genuine total
scrape gap for every metric that pod alone emits. Prometheus-compatible rule evaluators have no
memory across that gap for an instant-vector comparison: the series
vanishing for even one evaluation resets the alert's `for:` pending clock to
zero, so an alert with `for: >= 30m` silently never fires across a normal
rollout — indistinguishable from a healthy system. A handful of the
`graph_ladybug_*` gauges make this worse: they aren't merely absent for the
pod-restart window, they're absent until the worker's *first Ladybug build*
completes afterward (gated behind `GraphStats.ReachComplete`/`EdgeTypeParity`
in `internal/obs/metrics.go`), which can take considerably longer on a cold
start while ClickHouse is under load.

Convention: any rule reading such a pod's gauge with `for: >= 30m` must wrap
its instant-vector comparison in `max_over_time`/`min_over_time`, sized to
that metric's own cold-start/staleness ceiling — 10m for an ordinary
worker/scanner gauge, 30m for the `ReachComplete`/`EdgeTypeParity`-gated Ladybug
family, never a borrowed default picked without checking which case applies.
Enforced by `internal/obs/alerts_test.go`'s
`TestAlertRulesWrapInstantVectorsAgainstRestartGap` (registry-derived from
which process's Go code actually emits a metric — see
`workerOnlyMetricNames`'s own doc comment for why label-text matching on
`component="worker"` was replaced) and
`TestLadybugColdStartGatedAlertsUseWidenedWindow` for the wider Ladybug-family case.

## Consequences

- Default deploys are unchanged: with neither env var set, there is no listener
  and tracing is a no-op. Nothing ships to any vendor.
- Operators point whatever Prometheus/OTLP-compatible stack they already run at
  the endpoints — no lock-in, self-hostable, OSS-friendly.
- One new direct dependency (`prometheus/client_golang`) plus the OTel SDK +
  OTLP exporter (the OTel trace API was already vendored for log correlation).
- Behaviour that can only be confirmed at runtime — e.g. that only human denials and
  executed fixes feed action confidence (ADR 087), KEV aggregation, and bulk-tier edge
  truncation — can now be validated with time-series evidence.

Cites ADR 008 (the decision this reverses in part), ADR 002 (River job tables,
still the queryable job-failure record), ADR 003 (the audit trail remains a
domain feature, not an observability concern).
