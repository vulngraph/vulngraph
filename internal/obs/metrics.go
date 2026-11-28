// Package obs is the vendor-neutral observability seam: a Prometheus /metrics
// registry and OpenTelemetry tracing, both off unless env-gated.
// It is a leaf package — it imports no internal domain
// packages. Live-state gauges (queue depth, graph size, backlogs, connector
// freshness) are read on scrape through the Sources callbacks the caller wires
// in, so obs never depends on jobs/graphstore/connector directly. Counters and
// histograms (job runs, durations) are incremented inline via the exported
// Observe* helpers.
package obs

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

const namespace = "graph"

// Metrics owns the registry and the inline counters/histograms. Construct with
// New, register the live-gauge collector with RegisterSources, expose Handler
// on the metrics listener, and call the Observe* methods from job/rebuild code.
type Metrics struct {
	reg *prometheus.Registry

	jobRuns      *prometheus.CounterVec
	jobDuration  *prometheus.HistogramVec
	rebuildDur   prometheus.Histogram
	feedRefresh  *prometheus.GaugeVec
	adjudication *prometheus.CounterVec
	consistency  *prometheus.CounterVec
	sweepOutcome *prometheus.CounterVec
	sweepLast    *prometheus.GaugeVec
	reasonCache  *prometheus.CounterVec

	costCollect      *prometheus.CounterVec
	costLastSuccess  *prometheus.GaugeVec
	costSnapshotRows prometheus.Counter

	notifyDelivery *prometheus.CounterVec

	ladybugSync          *prometheus.CounterVec
	graphTierEmpty       *prometheus.CounterVec
	ladybugPhase         *prometheus.HistogramVec
	correlateSweeps      *prometheus.CounterVec
	correlateLastFull    prometheus.Gauge
	correlateViewRows    prometheus.Gauge
	correlateViewCap     prometheus.Gauge
	correlateBufferUsed  *prometheus.GaugeVec
	correlateBufferLimit *prometheus.GaugeVec
	baseImageRunning     *prometheus.GaugeVec
	packageDepartures    *prometheus.GaugeVec

	// deletion is the observe-only deletion signal — see metrics_deletion.go.
	deletion deletionMetrics

	checkEvaluable  *prometheus.GaugeVec
	checkApplicable *prometheus.GaugeVec
	// evalByConnector holds the last evaluability reading per connector so the
	// per-check gauges can be the estate-wide totals. Each connector syncs
	// independently and most checks apply across many connectors, so a bare Set
	// per sync would make the gauge mean "whatever the last connector saw".
	evalMu          sync.Mutex
	evalByConnector map[string]map[string]CheckEvaluability
}

// CheckEvaluability is one check's ability to see the estate it grades, for one
// connector: how many assets it applied to, and how many of those carried
// enough data for its predicate to reach a conclusion.
type CheckEvaluability struct {
	CheckID    string
	Applicable int
	Evaluable  int
}

// New builds a Metrics with its own registry (not the global default, so tests
// are isolated) preloaded with Go runtime and process collectors.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		jobRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "job", Name: "runs_total",
			Help: "River job executions by queue, worker kind and terminal status.",
		}, []string{"queue", "worker", "status"}),
		jobDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "job", Name: "duration_seconds",
			Help: "River job execution wall time by worker kind.",
			// 50ms … ~49min (11 buckets): the top bucket must cover
			// adjudicateJobTimeout = 20min (internal/jobs/adjudicate.go), the
			// longest job kind that runs through this histogram — a bucket
			// boundary short of a real job budget puts every long-running sweep
			// in the unbounded +Inf bucket, making quantile reads on it meaningless.
			Buckets: prometheus.ExponentialBuckets(0.05, 3, 11),
		}, []string{"worker"}),
		rebuildDur: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "ladybug", Name: "rebuild_duration_seconds",
			Help:    "Ladybug graph rebuild (SyncFromSources) wall time.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1s … ~17min
		}),
		feedRefresh: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "feed", Name: "last_success_timestamp_seconds",
			Help: "Unix time of the last successful refresh of each intel feed (kev, osv, epss, scc, domain_monitor). Alert when time() minus this exceeds the feed's cadence — the direct 'is it still updating?' signal.",
		}, []string{"feed"}),
		adjudication: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "adjudicator", Name: "outcomes_total",
			Help: "Severity adjudication outcomes by disposition (cached = fresh belief for unchanged inputs, skipped for free; agreed = cheap sample confirmed the deterministic severity; adjudicated = confirmed belief written on disagreement; escalated = split→human review; corroboration_downgrade = a demotion contradicted by an independent public-exposure witness, forced to proposed for review; deferred = over the per-sweep cost cap; sample_error = LLM sample failed, e.g. bad model or ungrounded verdict; crystallization_candidate = count of stable corroboration-surviving patterns eligible to crystallize into a deterministic rule, report-only). Watch deferred (cap throttling), sample_error (sampler broken), corroboration_downgrade (demotions the gate caught), crystallization_candidate (rising = ripe for eval-gated promotion), and the cached ratio (steady state should be cached-dominated).",
		}, []string{"outcome"}),
		consistency: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "enrich", Name: "consistency_violations_total",
			Help: "Per-finding scoring-consistency invariant violations caught and repaired at the enrich gate, by invariant (inv1_identity_zero_hop = an identity scored as 0-hop internet-exposed, reach factor stripped; inv3_blast_only = outbound blast alone tried to re-promote a stripped identity to must_fix, capped; inv6_out_of_domain = an internet-hops value outside the valid domain, reset to unknown). Steady state is 0 — a nonzero rate means a bad reach signal is reaching enrich and is being repaired at the gate rather than at its source.",
		}, []string{"invariant"}),
		sweepOutcome: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "sweep", Name: "outcomes_total",
			Help: "Dangling-finding sweep phase outcomes by phase (dangling, stale_state, k8s_lifecycle, gce_lifecycle) and outcome (scanned = findings examined, resolved = findings auto-resolved). Watch scanned rising while resolved stays flat/zero — no other metric catches that combination.",
		}, []string{"phase", "outcome"}),
		sweepLast: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "sweep", Name: "last_resolved_timestamp_seconds",
			Help: "Unix time a dangling-sweep phase last resolved at least one finding. Only stamped on a tick that resolves >0 — alert when time() minus this exceeds a few sweep intervals while outcomes_total{outcome=\"scanned\"} keeps climbing for the same phase (scanned-high/resolved-zero).",
		}, []string{"phase"}),
		reasonCache: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "reasoncache", Name: "lookups_total",
			Help: "respond.Service.planFor lookups by result (hit = context fingerprint unchanged, cached plan reused, LLM skipped; miss = reasoner called): how often the fingerprint gate saves an LLM call versus how often Decide runs the reasoner fresh. Watch the hit ratio drop unexpectedly (a fingerprint input churning too often defeats the cache) or the miss rate spike (LLM cost/latency risk).",
		}, []string{"result"}),
		checkEvaluable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "check", Name: "evaluable_ratio",
			Help: "Fraction of the assets a CSPM check applies to whose collected metadata lets its predicate reach a conclusion at all. 1 = the check sees everything it grades; 0 = it is blind and its silence means nothing — without this, a blind check looks exactly like a clean estate. Alert on a sustained drop, and read it with graph_check_applicable_assets — a ratio over a handful of assets is not evidence. Reported as 1 when nothing applies (idle, not blind).",
		}, []string{"check_id"}),
		checkApplicable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "check", Name: "applicable_assets",
			Help: "Number of collected assets each CSPM check applies to — the denominator of graph_check_evaluable_ratio. Without it a 0.0 ratio on a two-asset population is indistinguishable from one on tens of thousands of pods.",
		}, []string{"check_id"}),
		ladybugSync: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "ladybug", Name: "sync_total",
			Help: "Ladybug graph syncs by path (full = COPY load + BFS + snapshot; signals = signal columns updated in place; noop = load set unchanged, nothing done). A rate of 0 on both cheap paths while full keeps climbing means the load digest is picking up churn on every sweep — suspect an unstable field in its topology half before suspecting the gate.",
		}, []string{"path"}),
		graphTierEmpty: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "explore", Name: "tier_empty_fallthrough_total",
			Help: "ID-keyed graph lookups (op=seed|neighbors) where a Ladybug tier answered EMPTY and the ClickHouse tier was consulted because of it — NOT counted for ordinary tier errors. Ladybug is a filtered projection: filterLadybugAssets prunes any asset with no retention edge and no risk score, and Ladybug's zero-rows-nil-error answer for such an id is byte-identical to \"no such asset\". A rate of ZERO here means the emptiness check is not being reached and pruned nodes are being reported absent.",
		}, []string{"op"}),
		ladybugPhase: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "ladybug", Name: "rebuild_phase_seconds",
			Help:    "Wall time of each phase of a Ladybug sync: load (concurrent ClickHouse read of assets+edges+signal rollup), filter (filterLadybugAssets), reach (exposure set + attacker-movement BFS), digest (the change gate's pre-pass over the whole corpus), copy (CSV generation + COPY into a fresh in-memory engine), bfs (risk propagation and its per-label score writes), swap (graph swap + signal-cache prewarm), snapshot (gob+gzip to the PVC). The first four are recorded on EVERY sync because they run before the gate decides; the last four only on a full rebuild, where together they partition rebuild_duration_seconds — a gap between the sum and the total means a step is unattributed.",
			Buckets: prometheus.ExponentialBuckets(0.1, 3, 9), // 100ms … ~11min
		}, []string{"phase"}),
		correlateSweeps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "correlate", Name: "sweeps_total",
			Help: "Correlation sweeps by mode (full = the whole-graph join, partial = the per-connector-sync subset) and status (ok; error = a genuine failure — ClickHouse timeout, view truncation, or a real Timeout under load; cancelled = the sweep's context was cancelled by the worker shutting down (SIGINT/SIGTERM), e.g. a rolling deploy interrupting an in-flight sweep — expected and self-healing via the next periodic tick, deliberately NOT counted as error). Keyed on MODE deliberately: graph_job_runs_total is keyed by worker kind, so both modes land on worker=\"correlate\" and a failing full sweep can average away behind a healthy partial rate if mode is not tracked separately.",
		}, []string{"mode", "status"}),
		correlateLastFull: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "correlate", Name: "last_full_success_timestamp_seconds",
			Help: "Unix time of the last SUCCESSFUL full correlation sweep. Alert when time() minus this exceeds a few times the sweep interval — a duration histogram cannot express \"sweeps stopped completing\" because it only samples the runs that finish. Absent (never succeeded this process lifetime) must also alert.",
		}),
		correlateViewRows: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "correlate", Name: "view_rows",
			Help: "Rows returned by the last correlation source load, including failed loads. The staged reader uses byte budgets; a zero view_limit means no row-count ceiling.",
		}),
		correlateViewCap: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "correlate", Name: "view_limit",
			Help: "The legacy correlation view's row-count ceiling; zero when staged byte budgets govern instead.",
		}),
		correlateBufferUsed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "correlate", Name: "buffer_bytes",
			Help: "Last staged pass logical byte charges by buffer (index, spool, output), including failed passes. These are not Go heap or RSS measurements.",
		}, []string{"buffer"}),
		correlateBufferLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "correlate", Name: "buffer_limit_bytes",
			Help: "Configured staged correlation logical byte ceilings by buffer (index, spool, output).",
		}, []string{"buffer"}),
		costCollect: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "cost", Name: "collect_total",
			Help: "AWS Cost Explorer collection attempts by outcome (ok = snapshots stored; empty = the API answered with nothing; permission_denied = IAM refused, almost always a missing ce:GetCostAndUsage; config_error = the connector config never produced an AWS config, so no call was made; api_error = any other Cost Explorer failure; store_error = the fetch worked and the write did not; connector_list_error = the loop could not even enumerate connectors; no_aws_connectors = nothing to collect). The per-outcome labels separate failure paths that all render in the UI as \"no cost anomalies\". Alert on permission_denied > 0 and on ok == 0 over a full collection interval.",
		}, []string{"outcome"}),
		costLastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "cost", Name: "last_success_timestamp_seconds",
			Help: "Unix time cost collection last STORED snapshots for a connector. Absent means it has never succeeded in this process's lifetime — which for a loop that runs on startup and every 6h is itself the alert. Read with graph_cost_collect_total{outcome!=\"ok\"}: the pair distinguishes \"never worked\" from \"stopped working\".",
		}, []string{"connector_id"}),
		costSnapshotRows: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "cost", Name: "snapshot_rows_written_total",
			Help: "Cost snapshot rows written to Postgres. A collection that reports ok while this stays flat means Cost Explorer is answering with an empty result set — the case SaveSnapshots silently accepts as success.",
		}),
		notifyDelivery: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "notify", Name: "delivery_total",
			Help: "Outbound alert-channel (Slack/webhook) delivery attempts by channel, event type, and terminal status (ok/error) — the aggregate signal for the outbound-alerting path, which otherwise shows failures only as log lines and notify.Channel's last_status column. Deliberately NOT labelled with channel_type: it is fixed for a given channel_id, so it adds no dimension channel_id doesn't already carry. GraphNotifyDeliveryFailing alerts on the error ratio summed across ALL channels, not per channel_id, so one channel with a revoked token/stale URL is a config problem that doesn't page forever.",
		}, []string{"channel_id", "event_type", "status"}),
		deletion:          newDeletionMetrics(),
		baseImageRunning:  newBaseImageRunning(),
		packageDepartures: newPackageDepartures(),
		evalByConnector:   map[string]map[string]CheckEvaluability{},
	}
	reg.MustRegister(m.deletion.collectors()...)
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.jobRuns, m.jobDuration, m.rebuildDur, m.feedRefresh, m.adjudication, m.consistency,
		m.sweepOutcome, m.sweepLast, m.checkEvaluable, m.checkApplicable, m.reasonCache,
		m.correlateSweeps, m.correlateLastFull, m.correlateViewRows, m.correlateViewCap,
		m.correlateBufferUsed, m.correlateBufferLimit,
		m.ladybugSync, m.graphTierEmpty, m.ladybugPhase,
		m.costCollect, m.costLastSuccess, m.costSnapshotRows,
		m.notifyDelivery, m.baseImageRunning, m.packageDepartures,
	)
	return m
}

// ObserveFeedRefresh records that an intel feed refreshed successfully at
// unixSeconds. Recorded from the job middleware on a successful feed-refresh job,
// so no per-feed worker code changes. A feed that has never succeeded in this
// process's lifetime simply has no sample — which a staleness alert also catches.
func (m *Metrics) ObserveFeedRefresh(feed string, unixSeconds float64) {
	if m == nil {
		return
	}
	m.feedRefresh.WithLabelValues(feed).Set(unixSeconds)
}

// ObserveLadybugSync records which path a Ladybug sync took and how long it ran.
// Recorded from inside graphstore, not from a caller's closure, so a serve-pod
// rebuild is visible on that pod's own /metrics.
func (m *Metrics) ObserveLadybugSync(path string, seconds float64) {
	if m == nil {
		return
	}
	m.ladybugSync.WithLabelValues(path).Inc()
	if path == "full" {
		m.rebuildDur.Observe(seconds)
	}
}

// ObserveLadybugPhase attributes one phase of a full Ladybug rebuild. Called once per
// phase per rebuild from inside graphstore, for the same reason ObserveLadybugSync is:
// a serve-pod rebuild must be visible on that pod's own /metrics.
func (m *Metrics) ObserveLadybugPhase(phase string, seconds float64) {
	if m == nil {
		return
	}
	m.ladybugPhase.WithLabelValues(phase).Observe(seconds)
}

// ObserveCorrelateSweep records the outcome of one correlation sweep. mode is
// "full" or "partial"; status is "ok", "error", or "cancelled" (jobs.correlateSweepStatus).
func (m *Metrics) ObserveCorrelateSweep(mode, status string) {
	if m == nil {
		return
	}
	m.correlateSweeps.WithLabelValues(mode, status).Inc()
}

// ObserveCorrelateFullSuccess stamps the last-successful-full-sweep gauge. Call
// only on a sweep that COMPLETED — stamping on attempt would defeat the point,
// which is to make "sweeps stopped finishing" visible.
func (m *Metrics) ObserveCorrelateFullSuccess(unixSeconds float64) {
	if m == nil {
		return
	}
	m.correlateLastFull.Set(unixSeconds)
}

// ObserveCorrelateView records the size of the last inventory-view load against its
// circuit-breaker limit, so the headroom ratio is alertable BEFORE the breaker trips.
// Recorded on every load, including one that trips it.
func (m *Metrics) ObserveCorrelateView(rows, limit int) {
	if m == nil {
		return
	}
	m.correlateViewRows.Set(float64(rows))
	m.correlateViewCap.Set(float64(limit))
}

// ObserveCorrelateBuffer records modeled bytes; process memory is measured separately.
func (m *Metrics) ObserveCorrelateBuffer(buffer string, used, limit int64) {
	if m == nil {
		return
	}
	m.correlateBufferUsed.WithLabelValues(buffer).Set(float64(used))
	m.correlateBufferLimit.WithLabelValues(buffer).Set(float64(limit))
}

// ObserveCostCollect records one cost-collection attempt's outcome. Every exit
// path of the collect loop must call this, including every early
// `return`/`continue` — an unlabelled failure lets an entire integration sit
// dark while its UI reports health.
func (m *Metrics) ObserveCostCollect(outcome string) {
	if m == nil {
		return
	}
	m.costCollect.WithLabelValues(outcome).Inc()
}

// ObserveCostCollectSuccess stamps the per-connector success gauge and adds the
// rows actually written. Call only when snapshots were STORED: stamping on
// attempt would reintroduce the failure this metric exists to expose.
func (m *Metrics) ObserveCostCollectSuccess(connectorID string, unixSeconds float64, rows int) {
	if m == nil {
		return
	}
	m.costLastSuccess.WithLabelValues(connectorID).Set(unixSeconds)
	if rows > 0 {
		m.costSnapshotRows.Add(float64(rows))
	}
}

// ObserveNotifyDelivery records one outbound notification-delivery attempt.
// Implements notify.DeliveryObserver (internal/app/notify/service.go), wired in
// from the composition root via notify.Service.WithMetrics so that domain
// package stays free of an internal/obs import.
//
// channelType is accepted, to satisfy that interface's fixed signature, but
// deliberately not put on the metric: a channel's type does not change
// independently of its id, so it is not a real additional dimension —
// channel_id already answers "which channel", and a per-backend rollup (all
// Slack channels vs all webhooks) is recoverable later by joining against the
// channel list if it is ever actually needed. status is "ok" or "error".
func (m *Metrics) ObserveNotifyDelivery(channelID, channelType, eventType, status string) {
	if m == nil {
		return
	}
	_ = channelType
	m.notifyDelivery.WithLabelValues(channelID, eventType, status).Inc()
}

// RegisterSources wires the live-state gauge collector. Call once, after New.
func (m *Metrics) RegisterSources(s Sources) {
	m.reg.MustRegister(&liveCollector{s: s, ttl: sourceTTL})
}

// Registry exposes the underlying registry (for promhttp.HandlerFor).
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// ObserveJob records one finished job execution. status is "ok" or "error".
func (m *Metrics) ObserveJob(queue, worker, status string, seconds float64) {
	if m == nil {
		return
	}
	m.jobRuns.WithLabelValues(queue, worker, status).Inc()
	m.jobDuration.WithLabelValues(worker).Observe(seconds)
}

// ObserveRebuild records one Ladybug rebuild's wall time.
func (m *Metrics) ObserveRebuild(seconds float64) {
	if m == nil {
		return
	}
	m.rebuildDur.Observe(seconds)
}

// ObserveAdjudication records one adjudication-sweep disposition tally. outcome
// is one of agreed/adjudicated/escalated/deferred; n is the count to add (0 is a
// no-op). Called once per outcome after each sweep.
func (m *Metrics) ObserveAdjudication(outcome string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.adjudication.WithLabelValues(outcome).Add(float64(n))
}

// ObserveReasonCacheLookup records one respond.Service.planFor call. hit is
// true when the cached plan was reused (LLM skipped), false when the
// reasoner ran fresh.
func (m *Metrics) ObserveReasonCacheLookup(hit bool) {
	if m == nil {
		return
	}
	result := "miss"
	if hit {
		result = "hit"
	}
	m.reasonCache.WithLabelValues(result).Inc()
}

// ObserveGraphTierFallthrough records one ID-keyed graph lookup that fell through
// to ClickHouse because a Ladybug tier answered empty rather than because it failed.
// op is "seed" or "neighbors". Satisfies explore.TierObserver.
func (m *Metrics) ObserveGraphTierFallthrough(op string) {
	if m == nil {
		return
	}
	m.graphTierEmpty.WithLabelValues(op).Inc()
}

// ObserveConsistencyViolation records n repairs of a scoring-consistency
// invariant at the enrich gate. invariant is one of inv1_identity_zero_hop,
// inv3_blast_only, inv6_out_of_domain. n<=0 is a no-op.
func (m *Metrics) ObserveConsistencyViolation(invariant string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.consistency.WithLabelValues(invariant).Add(float64(n))
}

// ObserveSweep records n findings for one dangling-sweep phase/outcome. phase
// is one of dangling/stale_state/k8s_lifecycle/gce_lifecycle; outcome is
// scanned or resolved. n<=0 is a no-op (mirrors ObserveAdjudication) — in
// particular a phase that scans a batch but resolves nothing still records
// its scanned count, which is the scanned-high/resolved-zero signal.
func (m *Metrics) ObserveSweep(phase, outcome string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.sweepOutcome.WithLabelValues(phase, outcome).Add(float64(n))
}

// ObserveSweepResolved stamps the last-resolved gauge for a sweep phase. Call
// only when that phase resolved at least one finding this tick — a phase stuck
// at scanned-high/resolved-zero must show a stale (non-advancing) timestamp,
// not a comforting fresh one.
func (m *Metrics) ObserveSweepResolved(phase string, unixSeconds float64) {
	if m == nil {
		return
	}
	m.sweepLast.WithLabelValues(phase).Set(unixSeconds)
}

// scrapeBudget bounds one whole /metrics scrape's source reads.
//
// It must be shorter than the scraper's own scrape_timeout, or a hung source
// produces a failed scrape rather than a partial one. It also dominates every
// per-source deadline — context.WithTimeout keeps the earlier deadline, so a
// source with a longer inner budget never gets to use it, and is cancelled
// here instead. That domination is intentional: cancellation must degrade to
// a stale value plus an explicit failure signal (see serveStale), never to a
// vanished series.
const scrapeBudget = 8 * time.Second

// sourceTTL is how long a source's last reading is served without re-reading.
//
// Several ClickHouse-backed sources are full-table aggregates with no cache
// of their own; re-running them on every scrape interval, from both the serve
// and worker pods, is expensive enough to threaten the instance it runs on. An
// observability layer that costs more than the thing it observes gets turned
// off, which is how a platform ends up flying blind.
//
// 60s collapses several scrapes into one read while keeping every gauge
// fresher than any alert's `for:` window and far fresher than the cadence of
// what it measures. Between refreshes the cached value is re-emitted, so the
// series stays continuous and rate()/for() semantics are unaffected.
const sourceTTL = 60 * time.Second

// sourceState is one source's last reading and its health.
type sourceState struct {
	val       any
	fetchedAt time.Time // when val was last REFRESHED (not last served)
	healthy   bool      // the most recent refresh attempt produced a reading
	haveVal   bool
}

// liveCollector emits the pull-on-scrape gauges from the Sources callbacks. It
// uses the const-metric API so values are always fresh (no staleness between a
// background tick and a scrape), behind a per-source TTL cache (sourceTTL).
//
// The zero value is usable and does no caching (ttl 0 = refresh every scrape),
// which is what the unit tests want; RegisterSources sets the production ttl.
type liveCollector struct {
	s      Sources
	ttl    time.Duration
	budget time.Duration    // 0 = scrapeBudget; overridden only by tests
	now    func() time.Time // nil = time.Now; injectable for tests

	mu    sync.Mutex
	cache map[string]*sourceState
}

func (c *liveCollector) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// readSource returns a source's current reading, from cache when it is younger
// than the TTL and otherwise by calling fn, and records whether the refresh
// worked.
//
// Failure is never silent. The Sources callbacks return a bare slice: a query
// that timed out, errored, or was cancelled by scrapeBudget comes back as nil,
// indistinguishable from "nothing to report" — which would otherwise make the
// whole series disappear from /metrics, reading as "healthy and quiet" on
// every dashboard. So a refusal to answer is treated as a failure: the last
// good reading is re-served (with its true age) and the source's health gauge
// goes to 0, which is a signal an operator can alert on.
//
// Three things count as a failed refresh: the scrape context expiring, an
// empty result from a source that has previously returned data (deliberately
// strict — for a full-table aggregate, N rows to zero is a broken query far
// more often than an emptied estate, and an emptied estate is worth alerting
// on too), and — via minLen — an empty/below-minLen result on any read for a
// source that can never legitimately return fewer than minLen rows, even on
// its first call. SourceActivity is the motivating case: its merge always
// returns at least one row per expected source on success, so an empty result
// can only mean the callback's error path was hit. Pass 0 for every other
// source to keep prior behavior unchanged (0 < 0 is never true).
func readSource[T any](ctx context.Context, c *liveCollector, name string, minLen int, fn func(context.Context) []T) []T {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = make(map[string]*sourceState)
	}
	st, ok := c.cache[name]
	if !ok {
		st = &sourceState{}
		c.cache[name] = st
	}

	now := c.clock()
	// The comma-ok is belt and braces: each name is read by exactly one call site
	// with one T, so a mismatch is impossible — and a metrics scrape must never be
	// the thing that panics the process.
	cachedVal, typeOK := st.val.([]T)
	if st.haveVal && typeOK && c.ttl > 0 && now.Sub(st.fetchedAt) < c.ttl {
		return cachedVal
	}

	// Unlocked call would be better for concurrency, but Prometheus serialises
	// gathers per registry anyway and holding the lock keeps the refresh atomic.
	got := fn(ctx)
	failed := ctx.Err() != nil || len(got) < minLen || (len(got) == 0 && st.haveVal)
	if failed {
		st.healthy = false
		if st.haveVal && typeOK {
			return cachedVal
		}
		return got
	}

	st.val, st.haveVal, st.healthy, st.fetchedAt = got, true, true, now
	return got
}

// emitSourceHealth reports, for every source read this process's lifetime,
// whether its last refresh worked and how old the served reading is.
func (c *liveCollector) emitSourceHealth(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	for name, st := range c.cache {
		up := 0.0
		if st.healthy {
			up = 1.0
		}
		ch <- prometheus.MustNewConstMetric(descSourceUp, prometheus.GaugeValue, up, name)
		age := 0.0
		if st.haveVal {
			age = now.Sub(st.fetchedAt).Seconds()
		}
		ch <- prometheus.MustNewConstMetric(descSourceAge, prometheus.GaugeValue, age, name)
	}
}

var (
	descQueueDepth = prometheus.NewDesc(namespace+"_river_queue_depth", "River jobs pending by queue and state (the enrich/respond queues are the enrichment/reasoning backlog signal).", []string{"queue", "state"}, nil)
	// descGraphNodes, descNodeBudget, descGraphBuilt and the rest of the Ladybug
	// fidelity descriptors live in metrics_graph_fidelity.go.
	descConnStale = prometheus.NewDesc(namespace+"_connector_stale", "1 when a connector's last successful sync is older than its staleness window.", []string{"connector"}, nil)
	// descConnPartialStreak exists because graph_connector_stale is blind to this
	// failure mode by construction: Stale() reads LastSuccessAt, which advances on
	// any sync with runErr == nil regardless of collect.Result.Partial, so a
	// collector that runs on schedule but never finishes a phase (a permission
	// gap, a throttle, a deadline) reads as perfectly healthy forever. A partial
	// sweep gates off deletion detection and finding auto-resolution
	// (internal/jobs/sync.go), so this can silently accumulate stale open
	// findings. connector.PartiallyStale(connector.DefaultPartialStreakThreshold)
	// is the same verdict the domain type already computes; this gauge exposes
	// the raw streak so an alert can pick its own threshold without recompiling.
	descConnPartialStreak = prometheus.NewDesc(namespace+"_connector_partial_streak", "Consecutive syncs in a row whose collection was Partial (collect.Result.Partial), per connector. See connector.PartialStreak.", []string{"connector"}, nil)
	descAssetTotal        = prometheus.NewDesc(namespace+"_asset_total", "Total current (deduplicated) assets for a provider.", []string{"provider"}, nil)
	descAssetStale        = prometheus.NewDesc(namespace+"_asset_stale", "Assets for a provider whose last_seen has fallen behind that provider's OWN collection high-water mark by more than the staleness margin (anchored to the provider's own high water, never wall-clock, so an outage of every collector for a provider freezes the mark instead of marking the whole estate stale — see asset.ProviderHighWater). A rising fraction (stale/total) means part of that provider's collection has gone quiet, such as one of several connectors.", []string{"provider"}, nil)
	descCoverSeen         = prometheus.NewDesc(namespace+"_connector_coverage_seen", "Distinct dimension values observed in already-collected assets, for a provider whose expected connector count can be derived honestly from that dimension (kubernetes: distinct region; aws: distinct account_id).", []string{"provider", "dimension"}, nil)
	descCoverConf         = prometheus.NewDesc(namespace+"_connector_coverage_configured", "Enabled connectors configured for a provider covered by _connector_coverage_seen. seen > configured means at least one live account/cluster has no connector at all — invisible from graph_connector_stale alone, which only describes connectors that already exist.", []string{"provider", "dimension"}, nil)
	descCheckJunk         = prometheus.NewDesc(namespace+"_check_junk_rate", "Per check: the fraction of resolutions that closed because the RESOURCE disappeared rather than because anyone acted (resource_gone / (fixed + resource_gone + manual)). High means the check narrates infrastructure churn instead of reporting risk. Watch it per check and burn the top of the list down.", []string{"check_id", "source"}, nil)
	descCheckRes          = prometheus.NewDesc(namespace+"_check_resolutions", "Per check and outcome (fixed, resource_gone, manual) the count of resolved findings, plus outcome=\"open\" for the currently-open count. The denominator behind _check_junk_rate; provider_closed and unknown-reason rows are deliberately absent, so these do not sum to the check's lifetime total.", []string{"check_id", "source", "outcome"}, nil)
	descCheckMeas         = prometheus.NewDesc(namespace+"_check_quality_measurable", "1 when a check has enough resolutions for its junk rate to mean anything, 0 when it does not. Without this a brand-new check is indistinguishable from a perfect one: both report a junk rate of 0.", []string{"check_id", "source"}, nil)
	descUnclassified      = prometheus.NewDesc(namespace+"_findings_must_fix_class", "Open findings per source split by state=\"blank\"|\"classified\": whether the must-fix classifier reached an opinion at all. Read as the ratio blank/(blank+classified) PER SOURCE — a source pinned near 1.0 can never reach must_fix however severe its findings are, which is invisible to every other metric because the findings still carry a score, a band and a UI page. The classifier's fall-through returns must_fix_class=routine (enrich.MustFixRoutine) rather than \"\", so a blank here means enriched-but-unclassified: the classifier failed open on missing evidence. Some sources are mostly blank by design (a ghas_code_scanning alert with no deployment lineage has nothing to classify on), so compare a source against its own baseline; never-enriched findings are excluded from this query (see mustFixCoverageBySource). Alert on a sustained per-source ratio near 1.0 rather than any nonzero count, since a new source can still arrive unclassified.", []string{"source", "state"}, nil)
	descSrcActivity       = prometheus.NewDesc(namespace+"_source_last_activity_timestamp_seconds", "Unix time of the newest last_seen across a finding source's findings — the direct \"did this source run?\" signal, and 0 for a source that is expected but has never produced a finding. A healthy check source re-stamps last_seen on its existing findings every sweep, so this advances even when the source finds nothing new; a frozen value means the source did not run, which is what no other metric could say. Alert on time() minus this exceeding several of the source's collection cycles, per source.", []string{"source"}, nil)
	descSourceUp          = prometheus.NewDesc(namespace+"_metrics_source_up", "1 when this /metrics source's last refresh produced a reading, 0 when it failed — the query errored, was cancelled by the scrape budget, or returned nothing after previously returning data. Without it a failed source would simply vanish from /metrics, which reads as healthy-and-quiet on every dashboard. When this is 0 the gauges for that source are the last good reading, not current — see _metrics_source_age_seconds. Alert on 0 sustained across scrapes.", []string{"source"}, nil)
	descSourceAge         = prometheus.NewDesc(namespace+"_metrics_source_age_seconds", "Age of the reading currently being served for this /metrics source. Normally bounded by the source TTL (60s); a value climbing past it means refreshes are failing and the gauges are frozen at their last good values.", []string{"source"}, nil)

	descUnenriched = prometheus.NewDesc(namespace+"_findings_unenriched", "Open findings the enrichment pipeline has never reached (enriched_at unset), by severity. These carry no score and no score_band, so they are excluded from every band view and sit at the bottom of every score-sorted list — invisible to every other metric. Alert on a nonzero critical/high count that is not trending down: it means the enrich sweep is not keeping up with, or not reaching, its backlog.", []string{"severity"}, nil)
	// descOSVScan* live in metrics_osv.go and descImgScan* in metrics_imagevuln.go,
	// split out to keep this file under CLAUDE.md's 800-line ceiling.
)

func (c *liveCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descUnclassified
	ch <- descQueueDepth
	c.describeGraphFidelity(ch)
	ch <- descConnStale
	ch <- descConnPartialStreak
	ch <- descAssetTotal
	ch <- descAssetStale
	ch <- descCoverSeen
	ch <- descCoverConf
	ch <- descUnenriched
	ch <- descCheckJunk
	ch <- descCheckRes
	ch <- descCheckMeas
	ch <- descSrcActivity
	ch <- descSourceUp
	ch <- descSourceAge
	c.describeOSVScanStaleness(ch)
	c.describeFindingAge(ch)
	c.describeImageScanCoverage(ch)
	c.describeMigration(ch)
	c.describeQueueAge(ch)
}

func (c *liveCollector) Collect(ch chan<- prometheus.Metric) {
	// Scrapes must be bounded; the readers are quick indexed counts but a wedged
	// DB shouldn't hang Prometheus. The caller's Sources should honor ctx.
	//
	// Bounding alone is not enough: it turns "slow" into "gone", because a
	// cancelled source returns an empty slice and its whole series disappears.
	// readSource is the other half — a TTL cache so expensive full-table
	// sources are not re-read on every scrape, and an explicit health gauge so
	// a failure is reported instead of vanishing.
	budget := c.budget
	if budget <= 0 {
		budget = scrapeBudget
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	defer c.emitSourceHealth(ch)

	if c.s.QueueDepth != nil {
		for _, q := range readSource(ctx, c, "queue_depth", 0, c.s.QueueDepth) {
			ch <- prometheus.MustNewConstMetric(descQueueDepth, prometheus.GaugeValue, float64(q.N), q.Queue, q.State)
		}
	}
	c.collectGraphFidelity(ch)
	if c.s.Connectors != nil {
		for _, cs := range readSource(ctx, c, "connectors", 0, c.s.Connectors) {
			v := 0.0
			if cs.Stale {
				v = 1.0
			}
			ch <- prometheus.MustNewConstMetric(descConnStale, prometheus.GaugeValue, v, cs.Name)
			ch <- prometheus.MustNewConstMetric(descConnPartialStreak, prometheus.GaugeValue, float64(cs.PartialStreak), cs.Name)
		}
	}
	if c.s.AssetStaleness != nil {
		for _, a := range readSource(ctx, c, "asset_staleness", 0, c.s.AssetStaleness) {
			ch <- prometheus.MustNewConstMetric(descAssetTotal, prometheus.GaugeValue, float64(a.Total), a.Provider)
			ch <- prometheus.MustNewConstMetric(descAssetStale, prometheus.GaugeValue, float64(a.Stale), a.Provider)
		}
	}
	if c.s.ConnectorCoverage != nil {
		for _, cc := range readSource(ctx, c, "connector_coverage", 0, c.s.ConnectorCoverage) {
			ch <- prometheus.MustNewConstMetric(descCoverSeen, prometheus.GaugeValue, float64(cc.Seen), cc.Provider, cc.Dimension)
			ch <- prometheus.MustNewConstMetric(descCoverConf, prometheus.GaugeValue, float64(cc.Configured), cc.Provider, cc.Dimension)
		}
	}
	if c.s.Unenriched != nil {
		for _, u := range readSource(ctx, c, "unenriched", 0, c.s.Unenriched) {
			ch <- prometheus.MustNewConstMetric(descUnenriched, prometheus.GaugeValue, float64(u.N), u.Severity)
		}
	}
	if c.s.Unclassified != nil {
		for _, u := range readSource(ctx, c, "unclassified", 0, c.s.Unclassified) {
			ch <- prometheus.MustNewConstMetric(descUnclassified, prometheus.GaugeValue, float64(u.Blank), u.Source, "blank")
			ch <- prometheus.MustNewConstMetric(descUnclassified, prometheus.GaugeValue, float64(u.Classified), u.Source, "classified")
		}
	}
	if c.s.CheckQuality != nil {
		for _, q := range readSource(ctx, c, "check_quality", 0, c.s.CheckQuality) {
			measurable := 0.0
			if q.Measurable {
				measurable = 1.0
			}
			ch <- prometheus.MustNewConstMetric(descCheckMeas, prometheus.GaugeValue, measurable, q.CheckID, q.Source)
			ch <- prometheus.MustNewConstMetric(descCheckJunk, prometheus.GaugeValue, q.JunkRate, q.CheckID, q.Source)
			ch <- prometheus.MustNewConstMetric(descCheckRes, prometheus.GaugeValue, float64(q.Open), q.CheckID, q.Source, "open")
			ch <- prometheus.MustNewConstMetric(descCheckRes, prometheus.GaugeValue, float64(q.Fixed), q.CheckID, q.Source, "fixed")
			ch <- prometheus.MustNewConstMetric(descCheckRes, prometheus.GaugeValue, float64(q.ResourceGone), q.CheckID, q.Source, "resource_gone")
			ch <- prometheus.MustNewConstMetric(descCheckRes, prometheus.GaugeValue, float64(q.Manual), q.CheckID, q.Source, "manual")
		}
	}
	if c.s.SourceActivity != nil {
		// minLen 1, not 0: see readSource's own minLen doc comment — empty can
		// only mean a real error here, first read included.
		for _, sa := range readSource(ctx, c, "source_activity", 1, c.s.SourceActivity) {
			ch <- prometheus.MustNewConstMetric(descSrcActivity, prometheus.GaugeValue, float64(sa.LastActivityUnix), sa.Source)
		}
	}
	c.collectOSVScanStaleness(ctx, ch)
	c.collectFindingAge(ctx, ch)
	c.collectImageScanCoverage(ctx, ch)
	c.collectMigration(ctx, ch)
	c.collectQueueAge(ctx, ch)
}

// ObserveCheckEvaluability records one connector's per-check evaluability and
// republishes the estate-wide gauges.
//
// Readings are kept per connector and summed rather than Set directly: a check
// like aws-ec2-public-ip applies across every AWS connector, so a plain Set
// would leave the gauge showing whichever account synced last — the same
// last-writer-wins mistake that makes an average look healthy while one account
// is completely dark.
func (m *Metrics) ObserveCheckEvaluability(connectorID string, stats []CheckEvaluability) {
	if m == nil || connectorID == "" {
		return
	}
	m.evalMu.Lock()
	defer m.evalMu.Unlock()
	if m.evalByConnector == nil {
		m.evalByConnector = map[string]map[string]CheckEvaluability{}
	}
	byCheck := make(map[string]CheckEvaluability, len(stats))
	for _, s := range stats {
		byCheck[s.CheckID] = s
	}
	m.evalByConnector[connectorID] = byCheck

	totals := map[string]CheckEvaluability{}
	for _, conn := range m.evalByConnector {
		for id, s := range conn {
			t := totals[id]
			t.Applicable += s.Applicable
			t.Evaluable += s.Evaluable
			totals[id] = t
		}
	}
	for id, t := range totals {
		m.checkApplicable.WithLabelValues(id).Set(float64(t.Applicable))
		ratio := 1.0 // nothing applies: idle, not blind
		if t.Applicable > 0 {
			ratio = float64(t.Evaluable) / float64(t.Applicable)
		}
		m.checkEvaluable.WithLabelValues(id).Set(ratio)
	}
}
