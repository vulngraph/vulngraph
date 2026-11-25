package obs

import (
	"github.com/prometheus/client_golang/prometheus"
)

// The observe-only half of the deletion signal.
//
// The platform cannot currently tell "this resource was deleted" from "we
// stopped collecting it", so it never forgets anything. The mechanism that
// would forget stale assets already exists in the sync worker but is gated
// on one boolean per connector (collect.Result.Partial), so a single flaky
// best-effort family blocks the whole connector's reconciliation every sweep.
//
// The first three gauges measure the two halves of that decision without
// taking it: which scopes can prove they enumerated everything, and how many
// stored assets a sweep would have judged deleted. The graph_forget_* series
// that follow them are the same decision taken to its conclusion — per
// (scope, type), with every refusal applied — and still published rather
// than acted on. Nothing here deletes, tombstones or resolves anything.
//
// Split into its own file to keep metrics.go under CLAUDE.md's 800-line
// ceiling; no functional distinction from the other pushed metrics.
type deletionMetrics struct {
	scopeComplete   *prometheus.GaugeVec
	scopeEnumerated *prometheus.GaugeVec
	candidates      *prometheus.GaugeVec

	// The shadow half of the deletion decision: the same decision, evaluated per (scope, type)
	// with every refusal applied, published without being taken.
	shadowCandidates *prometheus.GaugeVec
	wouldForget      *prometheus.GaugeVec
	// wouldEnforce is the FORGET_ENFORCE_TYPES-scoped subset of wouldForget —
	// see ObserveForgetVerdict's comment for why this is a separate series
	// rather than a new label on wouldForget.
	wouldEnforce *prometheus.GaugeVec
	refusals     *prometheus.CounterVec
	tombstones   prometheus.Counter
	enforcing    prometheus.Gauge
}

func newDeletionMetrics() deletionMetrics {
	return deletionMetrics{
		scopeComplete: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "sync", Name: "scope_last_complete_timestamp_seconds",
			Help: "Unix time a collector scope (\"eu-west-1/ec2:instances\", \"global/compute.instances\") last PROVED it enumerated everything it lists — every page read, no error swallowed. Read it as a watermark age: time() minus this is how long the platform has been unable to tell deletion from non-collection for that scope. Unlike connector-level staleness, this says WHICH scope cannot be trusted. A scope that has never completed in this process's lifetime has no series at all, which is the same shape as graph_feed_last_success_timestamp_seconds and means the same thing.",
		}, []string{"connector", "scope"}),
		scopeEnumerated: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "sync", Name: "scope_enumerated_assets",
			Help: "Assets found by a scope's last proven-complete enumeration. The denominator a future enforce mode's relative refusal threshold needs: \"absent\" only means something against the size of the population it was absent from, and a scope that legitimately holds 3 instances must not be judged by the same fraction as one holding tens of thousands.",
		}, []string{"connector", "scope"}),
		candidates: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "sync", Name: "deletion_candidates",
			Help: "Stored asset hashes absent from a connector's last sweep — what deletion reconciliation WOULD have acted on, observed only. completeness=\"complete\" is the count ACTUALLY deleted/resolved this sweep — NOT the raw absent count: deletion reconciliation is scoped by (region, type), so a sweep's raw absent count routinely includes rows deliberately left alone this sweep (untyped pending backfill, a type/region not proven-enumerated by any completed scope, or refused outright for exceeding the absolute deletion cap), so \"complete\" reports only what was actually acted on. completeness=\"partial\" is the subset the connector-wide gate refused outright, because one best-effort family failed somewhere in the connector and absence stopped being evidence at all. The partial series is the size of what the platform cannot currently forget.",
		}, []string{"connector", "completeness"}),
		shadowCandidates: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "forget", Name: "shadow_candidates",
			Help: "Assets in one audited (connector, scope, type) that the scope's last proven-complete enumeration did not re-observe, and that have stayed unobserved for the whole confirmation window — i.e. everything the deletion decision considered. Separate from graph_sync_deletion_candidates, which reports a single scalar per connector per sweep: this one is attributed to the scope and type a decision is actually taken at, at the cost of only covering the audited families.",
		}, []string{"connector", "scope", "asset_type"}),
		wouldForget: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "forget", Name: "would_forget",
			Help: "Of graph_forget_shadow_candidates, how many every refusal permits forgetting — 0 whenever the scope was refused. The gap between the two series IS the mechanism: a large shadow_candidates with a zero would_forget is the platform declining to act on a backlog it cannot distinguish from broken collection, which is the expected reading for high-churn types such as ec2_instance and gce_instance. NOT gated by FORGET_ENFORCE_TYPES — this is what Decide() permits, independent of which types this deployment currently enforces. See graph_forget_would_enforce for the scoped subset that actually gets written.",
		}, []string{"connector", "scope", "asset_type"}),
		wouldEnforce: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "forget", Name: "would_enforce",
			Help: "Of graph_forget_would_forget, how many are for an asset type on the FORGET_ENFORCE_TYPES allow-list AND running under FORGET_MODE=enforce — i.e. would actually be written to forget_tombstones this sweep. Always 0 under FORGET_MODE=shadow (see graph_forget_enforcing), by design: FORGET_ENFORCE_TYPES is purely additive and has no effect outside enforce mode. Under enforce mode, graph_forget_would_forget minus this series is exactly \"would forget, but this asset type is not yet in the enforce scope\".",
		}, []string{"connector", "scope", "asset_type"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "forget", Name: "refusals_total",
			Help: "Scope evaluations refused, by reason (relative_cap, absolute_cap, enumeration_shrank, unconfirmed, population_too_small, edge_truncated, edge_health_unknown, not_enforceable, delivery_mismatch). Low cardinality on purpose: this is the series that says WHICH guard is doing the work, and a permanently dominant reason is either the correct answer for this estate or a threshold that needs calibration. delivery_mismatch is not a Decide() refusal — it fires in the caller (jobs.evaluateForget), before a scope is even handed to Decide, when a collector declared a scope complete but the assets it claimed never reached collect.Result.Assets (the claim/payload divergence a panic between MarkComplete and the assets append can produce).",
		}, []string{"refusal"}),
		tombstones: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "forget", Name: "tombstones_written_total",
			Help: "Tombstone rows written — \"believed gone at T\", never a deletion. Stays at exactly 0 unless FORGET_MODE=enforce, so any non-zero value on a deployment that did not deliberately enable enforcement is an incident.",
		}),
		enforcing: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "forget", Name: "enforcing",
			Help: "1 when FORGET_MODE=enforce, 0 in shadow mode. Published so \"is it on?\" is answerable from monitoring rather than from a pod's environment.",
		}),
	}
}

func (d deletionMetrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		d.scopeComplete, d.scopeEnumerated, d.candidates,
		d.shadowCandidates, d.wouldForget, d.wouldEnforce, d.refusals, d.tombstones, d.enforcing,
	}
}

// ScopeCompletion is one proven-complete collector enumeration, as the sync
// worker reports it. Declared here rather than imported from internal/collect
// so obs stays a leaf package with no domain imports (see the package doc).
type ScopeCompletion struct {
	Scope string
	Count int
}

// ObserveScopeCompletions stamps the completeness watermark for every scope a
// sweep proved complete, and publishes each one's enumerated size.
//
// Only completed scopes are touched. A scope that failed this sweep keeps its
// PREVIOUS timestamp rather than being zeroed or deleted, which is what makes
// the age meaningful: the gauge answers "how long since this scope could be
// trusted", and resetting it on failure would answer nothing.
func (m *Metrics) ObserveScopeCompletions(connectorID string, scopes []ScopeCompletion, unixSeconds float64) {
	if m == nil || connectorID == "" {
		return
	}
	for _, s := range scopes {
		if s.Scope == "" {
			continue
		}
		m.deletion.scopeComplete.WithLabelValues(connectorID, s.Scope).Set(unixSeconds)
		m.deletion.scopeEnumerated.WithLabelValues(connectorID, s.Scope).Set(float64(s.Count))
	}
}

// ObserveDeletionCandidates records how many stored asset hashes were absent
// from one connector's sweep, and whether that sweep was complete enough for
// the existing reconciliation to have acted on them.
//
// Both series are always written, including the zero, so a connector that
// flips from partial to complete does not leave a stale non-zero reading on the
// side it no longer reports.
func (m *Metrics) ObserveDeletionCandidates(connectorID string, n int, sweepComplete bool) {
	if m == nil || connectorID == "" {
		return
	}
	acted, refused := 0, n
	if sweepComplete {
		acted, refused = n, 0
	}
	m.deletion.candidates.WithLabelValues(connectorID, "complete").Set(float64(acted))
	m.deletion.candidates.WithLabelValues(connectorID, "partial").Set(float64(refused))
}

// ObserveForgetVerdict publishes one evaluated (scope, type) decision.
//
// The candidate and would-forget gauges are written even when both are zero,
// so a scope that stops producing candidates reports the zero rather than
// holding its last non-zero reading — the opposite choice from the scope
// watermarks above, and for the opposite reason: a watermark's whole meaning
// is its age, while a candidate count's whole meaning is that it is current.
//
// enforceScoped is forget.Service.enforceScoped(assetType) — true only when
// this deployment is running FORGET_MODE=enforce and assetType is on the
// FORGET_ENFORCE_TYPES allow-list, i.e. exactly the condition under which
// Service actually writes a tombstone for this row. It gates only
// graph_forget_would_enforce below; would_forget itself is never gated by it,
// because Decide()'s permission to forget must not read differently
// depending on which types this deployment happens to enforce today. It is a
// second gauge, not a new label on wouldForget, because a label change on an
// existing series breaks or silently miscounts anyone already summing it.
//
// The scope's stored population is deliberately not published: it is the
// denominator of a refusal that is already reported by name, and a third
// gauge to re-derive a ratio readable elsewhere is not worth the cardinality.
func (m *Metrics) ObserveForgetVerdict(connectorID, scope, assetType, refusal string, confirmed, forgettable int, enforceScoped bool) {
	if m == nil || connectorID == "" || scope == "" || assetType == "" {
		return
	}
	m.deletion.shadowCandidates.WithLabelValues(connectorID, scope, assetType).Set(float64(confirmed))
	m.deletion.wouldForget.WithLabelValues(connectorID, scope, assetType).Set(float64(forgettable))
	enforced := 0
	if enforceScoped {
		enforced = forgettable
	}
	m.deletion.wouldEnforce.WithLabelValues(connectorID, scope, assetType).Set(float64(enforced))
	if refusal != "" {
		m.deletion.refusals.WithLabelValues(refusal).Inc()
	}
}

// ObserveForgetDeliveryMismatch counts a scope dropped from forget evaluation
// before Decide ever saw it: a collector declared the scope's enumeration
// complete (collect.Result.MarkComplete), but the assets it claimed to have
// found did not all reach collect.Result.Assets. See jobs.evaluateForget.
func (m *Metrics) ObserveForgetDeliveryMismatch() {
	if m == nil {
		return
	}
	m.deletion.refusals.WithLabelValues("delivery_mismatch").Inc()
}

// ObserveForgetTombstones counts tombstone rows written. Non-zero only under
// FORGET_MODE=enforce.
func (m *Metrics) ObserveForgetTombstones(_ string, written int) {
	if m == nil || written <= 0 {
		return
	}
	m.deletion.tombstones.Add(float64(written))
}

// SetForgetEnforcing publishes whether enforcement is enabled. Called once at
// startup: the value cannot change without a restart, and a gauge that is only
// ever set at boot is exactly right for a deployment-time switch.
func (m *Metrics) SetForgetEnforcing(on bool) {
	if m == nil {
		return
	}
	v := 0.0
	if on {
		v = 1
	}
	m.deletion.enforcing.Set(v)
}
