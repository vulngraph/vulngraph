package obs

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestLiveCollectorEmitsFromSources(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{
		QueueDepth: func(context.Context) []QueueStat {
			return []QueueStat{{Queue: "sync", State: "available", N: 3}, {Queue: "enrich", State: "running", N: 1}}
		},
		Graph: func() GraphStats { return GraphStats{Nodes: 200000, LastBuiltUnix: 1720000000} },
		Connectors: func(context.Context) []ConnectorStat {
			return []ConnectorStat{{Name: "aws-prod", Stale: false}, {Name: "gcp-legacy", Stale: true}}
		},
	})

	want := `
# HELP graph_connector_stale 1 when a connector's last successful sync is older than its staleness window.
# TYPE graph_connector_stale gauge
graph_connector_stale{connector="aws-prod"} 0
graph_connector_stale{connector="gcp-legacy"} 1
# HELP graph_river_queue_depth River jobs pending by queue and state (the enrich/respond queues are the enrichment/reasoning backlog signal).
# TYPE graph_river_queue_depth gauge
graph_river_queue_depth{queue="enrich",state="running"} 1
graph_river_queue_depth{queue="sync",state="available"} 3
# HELP graph_ladybug_node_count Nodes in the current in-memory graph.
# TYPE graph_ladybug_node_count gauge
graph_ladybug_node_count 200000
`
	names := []string{"graph_river_queue_depth", "graph_ladybug_node_count", "graph_connector_stale"}
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), names...); err != nil {
		t.Fatalf("live collector output mismatch:\n%v", err)
	}
}

func TestLiveCollectorEmitsPartialStreak(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{
		Connectors: func(context.Context) []ConnectorStat {
			return []ConnectorStat{
				{Name: "aws-prod", Stale: false, PartialStreak: 512},
				{Name: "gcp-legacy", Stale: true, PartialStreak: 0},
			}
		},
	})

	want := `
# HELP graph_connector_partial_streak Consecutive syncs in a row whose collection was Partial (collect.Result.Partial), per connector. See connector.PartialStreak.
# TYPE graph_connector_partial_streak gauge
graph_connector_partial_streak{connector="aws-prod"} 512
graph_connector_partial_streak{connector="gcp-legacy"} 0
`
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), "graph_connector_partial_streak"); err != nil {
		t.Fatalf("live collector output mismatch:\n%v", err)
	}
}

func TestNilSourcesEmitNothing(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{}) // all callbacks nil
	// Should not panic and should emit no live-gauge families.
	for _, name := range []string{"graph_river_queue_depth", "graph_ladybug_node_count", "graph_connector_stale", "graph_connector_partial_streak"} {
		if n := testutil.CollectAndCount(m.Registry(), name); n != 0 {
			t.Errorf("expected 0 samples for %s with nil sources, got %d", name, n)
		}
	}
}

func TestObserveJobAndRebuildRecord(t *testing.T) {
	m := New()
	m.ObserveJob("enrich", "EnrichWorker", "ok", 0.2)
	m.ObserveJob("enrich", "EnrichWorker", "error", 1.5)
	m.ObserveRebuild(42.0)

	if got := testutil.ToFloat64(m.jobRuns.WithLabelValues("enrich", "EnrichWorker", "ok")); got != 1 {
		t.Errorf("job_runs_total ok = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.jobRuns.WithLabelValues("enrich", "EnrichWorker", "error")); got != 1 {
		t.Errorf("job_runs_total error = %v, want 1", got)
	}
	if n := testutil.CollectAndCount(m.Registry(), "graph_ladybug_rebuild_duration_seconds"); n == 0 {
		t.Error("expected rebuild duration histogram to have samples")
	}
}

func TestNilMetricsObserveIsNoop(t *testing.T) {
	var m *Metrics                  // nil
	m.ObserveJob("q", "w", "ok", 1) // must not panic
	m.ObserveRebuild(1)
	m.ObserveFeedRefresh("kev", 1)           // must not panic
	m.ObserveSweep("dangling", "scanned", 1) // must not panic
	m.ObserveSweepResolved("dangling", 1)    // must not panic
	m.ObserveReasonCacheLookup(true)         // must not panic
}

func TestObserveReasonCacheLookup(t *testing.T) {
	m := New()
	m.ObserveReasonCacheLookup(true)
	m.ObserveReasonCacheLookup(true)
	m.ObserveReasonCacheLookup(false)

	if got := testutil.ToFloat64(m.reasonCache.WithLabelValues("hit")); got != 2 {
		t.Errorf("reasoncache_lookups_total{result=hit} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.reasonCache.WithLabelValues("miss")); got != 1 {
		t.Errorf("reasoncache_lookups_total{result=miss} = %v, want 1", got)
	}
}

func TestAssetStalenessAndConnectorCoverageSources(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{
		AssetStaleness: func(context.Context) []AssetStalenessStat {
			return []AssetStalenessStat{{Provider: "aws", Total: 100, Stale: 64}}
		},
		ConnectorCoverage: func(context.Context) []ConnectorCoverageStat {
			return []ConnectorCoverageStat{{Provider: "kubernetes", Dimension: "region", Seen: 6, Configured: 1}}
		},
	})

	want := `
# HELP graph_asset_stale Assets for a provider whose last_seen has fallen behind that provider's OWN collection high-water mark by more than the staleness margin (anchored to the provider's own high water, never wall-clock, so an outage of every collector for a provider freezes the mark instead of marking the whole estate stale — see asset.ProviderHighWater). A rising fraction (stale/total) means part of that provider's collection has gone quiet, such as one of several connectors.
# TYPE graph_asset_stale gauge
graph_asset_stale{provider="aws"} 64
# HELP graph_asset_total Total current (deduplicated) assets for a provider.
# TYPE graph_asset_total gauge
graph_asset_total{provider="aws"} 100
# HELP graph_connector_coverage_configured Enabled connectors configured for a provider covered by _connector_coverage_seen. seen > configured means at least one live account/cluster has no connector at all — invisible from graph_connector_stale alone, which only describes connectors that already exist.
# TYPE graph_connector_coverage_configured gauge
graph_connector_coverage_configured{dimension="region",provider="kubernetes"} 1
# HELP graph_connector_coverage_seen Distinct dimension values observed in already-collected assets, for a provider whose expected connector count can be derived honestly from that dimension (kubernetes: distinct region; aws: distinct account_id).
# TYPE graph_connector_coverage_seen gauge
graph_connector_coverage_seen{dimension="region",provider="kubernetes"} 6
`
	names := []string{"graph_asset_stale", "graph_asset_total", "graph_connector_coverage_configured", "graph_connector_coverage_seen"}
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), names...); err != nil {
		t.Fatalf("asset staleness / connector coverage output mismatch:\n%v", err)
	}
}

func TestOSVScanStalenessSource(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{
		OSVScanStaleness: func(context.Context) []OSVScanStalenessStat {
			return []OSVScanStalenessStat{{TotalPackages: 33000, NeverScanned: 5, OldestScannedAt: 1754400000}}
		},
	})

	want := `
# HELP graph_osv_scan_never_scanned Packages in the current inventory that have NEVER been checked against OSV (absent from osv_scanned_packages) — the never-covered gap, distinct from staleness of coverage that already exists.
# TYPE graph_osv_scan_never_scanned gauge
graph_osv_scan_never_scanned 5
# HELP graph_osv_scan_oldest_scanned_timestamp_seconds Unix time of the OLDEST scanned_at across every currently-tracked package (0 if none scanned yet). Directly answers 'how stale is our worst-covered package?', which graph_feed_last_success_timestamp_seconds{feed="osv"} cannot: that gauge stamps fresh on every successful refresh_osv run even when 0 new packages were scanned. A value more than osvRescanAfter (7d) + osvInterval (24h) in the past means the daily sweep is not keeping the estate's actual coverage current, independent of whether the job itself reports healthy.
# TYPE graph_osv_scan_oldest_scanned_timestamp_seconds gauge
graph_osv_scan_oldest_scanned_timestamp_seconds 1.754400e+09
# HELP graph_osv_scan_total_packages Current distinct (ecosystem,name,version) package inventory size — the denominator for graph_osv_scan_never_scanned.
# TYPE graph_osv_scan_total_packages gauge
graph_osv_scan_total_packages 33000
`
	names := []string{"graph_osv_scan_never_scanned", "graph_osv_scan_oldest_scanned_timestamp_seconds", "graph_osv_scan_total_packages"}
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), names...); err != nil {
		t.Fatalf("osv scan staleness output mismatch:\n%v", err)
	}
}

func TestNilOSVScanStalenessSourceEmitsNothing(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{}) // OSVScanStaleness nil
	for _, name := range []string{"graph_osv_scan_never_scanned", "graph_osv_scan_oldest_scanned_timestamp_seconds", "graph_osv_scan_total_packages"} {
		if n := testutil.CollectAndCount(m.Registry(), name); n != 0 {
			t.Errorf("expected 0 samples for %s with nil source, got %d", name, n)
		}
	}
}

// TestObserveSweep pins the sweep-effectiveness counters: the whole point is
// that "scanned high, resolved zero" must be visible, so scanned must record
// even when resolved is a no-op zero.
func TestObserveSweep(t *testing.T) {
	m := New()
	m.ObserveSweep("k8s_lifecycle", "scanned", 50000)
	m.ObserveSweep("k8s_lifecycle", "resolved", 0) // no-op: must NOT create a zero sample masking the gap

	if got := testutil.ToFloat64(m.sweepOutcome.WithLabelValues("k8s_lifecycle", "scanned")); got != 50000 {
		t.Errorf("sweep scanned = %v, want 50000", got)
	}
	if n := testutil.CollectAndCount(m.sweepOutcome, "graph_sweep_outcomes_total"); n != 1 {
		t.Errorf("expected only the scanned sample to exist (resolved=0 is a no-op), got %d samples", n)
	}

	m.ObserveSweep("k8s_lifecycle", "resolved", 1050)
	if got := testutil.ToFloat64(m.sweepOutcome.WithLabelValues("k8s_lifecycle", "resolved")); got != 1050 {
		t.Errorf("sweep resolved = %v, want 1050", got)
	}
}

func TestObserveSweepResolved(t *testing.T) {
	m := New()
	m.ObserveSweepResolved("dangling", 1721900000)
	if got := testutil.ToFloat64(m.sweepLast.WithLabelValues("dangling")); got != 1721900000 {
		t.Errorf("sweep last-resolved dangling = %v, want 1721900000", got)
	}
	// A phase that never resolved anything has no sample — the staleness
	// alert's other half (time() - this) fires on missing data too.
	if n := testutil.CollectAndCount(m.sweepLast, "graph_sweep_last_resolved_timestamp_seconds"); n != 1 {
		t.Errorf("expected exactly 1 sample (only the phase observed), got %d", n)
	}
}

func TestObserveFeedRefresh(t *testing.T) {
	m := New()
	m.ObserveFeedRefresh("kev", 1720000000)
	m.ObserveFeedRefresh("osv", 1720000500)
	if got := testutil.ToFloat64(m.feedRefresh.WithLabelValues("kev")); got != 1720000000 {
		t.Errorf("feed last_success kev = %v, want 1720000000", got)
	}
	if got := testutil.ToFloat64(m.feedRefresh.WithLabelValues("osv")); got != 1720000500 {
		t.Errorf("feed last_success osv = %v, want 1720000500", got)
	}
}

// TestCheckQualityGauges guards the per-check junk-rate scoreboard. Two
// properties matter beyond "a number is emitted": a check with too little
// history must be visibly unmeasurable rather than reporting a flattering
// 0.0, and the resolution breakdown must be emitted per outcome so the ratio
// is auditable instead of being a bare float nobody can check.
func TestCheckQualityGauges(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{
		CheckQuality: func(context.Context) []CheckQualityStat {
			return []CheckQualityStat{
				// A check that closes almost entirely on vanished resources, e.g.
				// findings on short-lived instances that are deleted before anyone acts.
				{CheckID: "gcp-gce-no-oslogin", Source: "cspm", Open: 1000,
					Fixed: 5, ResourceGone: 95, Manual: 0, JunkRate: 0.95, Measurable: true},
				// A brand-new check: zero junk rate, but no evidence behind it.
				{CheckID: "aws-brand-new", Source: "cspm", Open: 3,
					Fixed: 1, ResourceGone: 0, Manual: 0, JunkRate: 0, Measurable: false},
			}
		},
	})

	want := `
# HELP graph_check_quality_measurable 1 when a check has enough resolutions for its junk rate to mean anything, 0 when it does not. Without this a brand-new check is indistinguishable from a perfect one: both report a junk rate of 0.
# TYPE graph_check_quality_measurable gauge
graph_check_quality_measurable{check_id="aws-brand-new",source="cspm"} 0
graph_check_quality_measurable{check_id="gcp-gce-no-oslogin",source="cspm"} 1
`
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), "graph_check_quality_measurable"); err != nil {
		t.Fatalf("measurable gauge mismatch:\n%v", err)
	}

	junk := sampleValue(t, m, "graph_check_junk_rate", map[string]string{"check_id": "gcp-gce-no-oslogin", "source": "cspm"})
	if junk != 0.95 {
		t.Errorf("junk rate = %v, want 0.95", junk)
	}
	// The breakdown must be present, or the ratio is unauditable.
	for outcome, want := range map[string]float64{"open": 1000, "fixed": 5, "resource_gone": 95, "manual": 0} {
		if got := resolutionCount(t, m, "gcp-gce-no-oslogin", outcome); got != want {
			t.Errorf("resolutions{outcome=%q} = %v, want %v", outcome, got, want)
		}
	}
}

func resolutionCount(t *testing.T, m *Metrics, checkID, outcome string) float64 {
	t.Helper()
	return sampleValue(t, m, "graph_check_resolutions",
		map[string]string{"check_id": checkID, "source": "cspm", "outcome": outcome})
}

// sampleValue finds one sample of a gathered family by its exact label set.
func sampleValue(t *testing.T, m *Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, metric := range f.GetMetric() {
			got := map[string]string{}
			for _, lp := range metric.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			match := len(got) == len(labels)
			for k, v := range labels {
				if got[k] != v {
					match = false
				}
			}
			if match {
				return metric.GetGauge().GetValue()
			}
		}
		t.Fatalf("%s has no sample with labels %v", name, labels)
	}
	t.Fatalf("metric family %s not emitted", name)
	return 0
}

// gatherFamily returns the gathered samples for one metric family as "name{labels} value"
// lines, so a test can assert on series without pinning the (long) HELP text.
func gatherFamily(t *testing.T, m *Metrics, name string) string {
	t.Helper()
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := &strings.Builder{}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, mt := range f.GetMetric() {
			labels := make([]string, 0, len(mt.GetLabel()))
			for _, l := range mt.GetLabel() {
				labels = append(labels, l.GetName()+"=\""+l.GetValue()+"\"")
			}
			fmt.Fprintf(out, "%s{%s} %g\n", name, strings.Join(labels, ","), mt.GetGauge().GetValue())
		}
	}
	return out.String()
}

// TestUnclassifiedSourceEmitsCoverageRatio pins the prioritisation-coverage
// gauge: a source that produces findings but classifies none of them must be
// visible as a ratio, not inferable only by running a ClickHouse query by hand.
func TestUnclassifiedSourceEmitsCoverageRatio(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{
		Unclassified: func(context.Context) []UnclassifiedStat {
			return []UnclassifiedStat{
				{Source: "supply_chain", Blank: 1200, Classified: 300},
				{Source: "cspm", Blank: 4000, Classified: 16000},
			}
		},
	})

	got := gatherFamily(t, m, "graph_findings_must_fix_class")
	for _, want := range []string{
		`graph_findings_must_fix_class{source="supply_chain",state="blank"} 1200`,
		`graph_findings_must_fix_class{source="supply_chain",state="classified"} 300`,
		`graph_findings_must_fix_class{source="cspm",state="blank"} 4000`,
		`graph_findings_must_fix_class{source="cspm",state="classified"} 16000`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing series %q in:\n%s", want, got)
		}
	}
}

// A nil Unclassified source must emit nothing rather than a comforting zero: a zero
// blank-count is indistinguishable from a source nobody is measuring.
func TestUnclassifiedNilSourceEmitsNothing(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{})
	if got := gatherFamily(t, m, "graph_findings_must_fix_class"); got != "" {
		t.Errorf("expected no series, got:\n%s", got)
	}
}

// TestEdgeTypeParityGaugeEmitsPerOutcome pins that each outcome is emitted as
// its own labelled series, so an alert can target label_mismatch (always a
// bug) without being drowned by endpoint_absent (a dangling reference) or
// endpoint_expired (an ephemeral resource that no longer exists).
func TestEdgeTypeParityGaugeEmitsPerOutcome(t *testing.T) {
	m := New()
	reachOK := true
	m.RegisterSources(Sources{
		Graph: func() GraphStats {
			return GraphStats{
				ReachComplete: &reachOK,
				EdgeTypeParity: []EdgeTypeParityStat{
					{EdgeType: "federated_access", Fetched: 382, Loaded: 284, LabelMismatch: 98},
					{EdgeType: "can_assume", Fetched: 9000, Loaded: 8616, EndpointAbsent: 384},
					{EdgeType: "executes_as", Fetched: 86167, Loaded: 71848, EndpointExpired: 14319},
					{EdgeType: "member_of_zone", Fetched: 100, NotLoaded: 100},
				},
			}
		},
	})

	want := `
# HELP graph_ladybug_edge_type_rows Per edge_type, the last graph build's ClickHouse→Ladybug accounting, split by outcome: fetched (rows read out of graph_edges), loaded (rows in Ladybug), label_mismatch (endpoint node present under a DIFFERENT label than the rel declares — ALWAYS a bug), endpoint_absent (endpoint not in the inventory at all — a dangling reference, budgeted per edge type in internal/graphschema), endpoint_expired (endpoint is an ephemeral resource that is GONE — a corpse edge inside the 48h freshness window whose pod died past the 72h liveness cut; correct to drop, never a loss), not_loaded (rel deliberately gated out of Ladybug). The four drop outcomes plus loaded sum to fetched. This is the standing detector for the label-mismatch bug class: no aggregate can see it, because an edge type losing 100% of its rows is invisible inside a six-figure edges_dropped total, and rel-level counts cannot resolve it either since several edge types share one rel table. Alert on outcome="label_mismatch" going nonzero for any edge_type, on graph_ladybug_edge_dangling_over_budget, on graph_ladybug_edge_expired_share_step_change, and on outcome="loaded" falling to zero for a type whose fetched is nonzero. Never alert on the LEVEL of endpoint_expired: that level is by design for a type whose drops are dominated by ephemeral churn. graph_ladybug_edge_expired_share_step_change alerts on a STEP in that level instead.
# TYPE graph_ladybug_edge_type_rows gauge
graph_ladybug_edge_type_rows{edge_type="can_assume",outcome="endpoint_absent"} 384
graph_ladybug_edge_type_rows{edge_type="can_assume",outcome="endpoint_expired"} 0
graph_ladybug_edge_type_rows{edge_type="can_assume",outcome="fetched"} 9000
graph_ladybug_edge_type_rows{edge_type="can_assume",outcome="label_mismatch"} 0
graph_ladybug_edge_type_rows{edge_type="can_assume",outcome="loaded"} 8616
graph_ladybug_edge_type_rows{edge_type="can_assume",outcome="not_loaded"} 0
graph_ladybug_edge_type_rows{edge_type="executes_as",outcome="endpoint_absent"} 0
graph_ladybug_edge_type_rows{edge_type="executes_as",outcome="endpoint_expired"} 14319
graph_ladybug_edge_type_rows{edge_type="executes_as",outcome="fetched"} 86167
graph_ladybug_edge_type_rows{edge_type="executes_as",outcome="label_mismatch"} 0
graph_ladybug_edge_type_rows{edge_type="executes_as",outcome="loaded"} 71848
graph_ladybug_edge_type_rows{edge_type="executes_as",outcome="not_loaded"} 0
graph_ladybug_edge_type_rows{edge_type="federated_access",outcome="endpoint_absent"} 0
graph_ladybug_edge_type_rows{edge_type="federated_access",outcome="endpoint_expired"} 0
graph_ladybug_edge_type_rows{edge_type="federated_access",outcome="fetched"} 382
graph_ladybug_edge_type_rows{edge_type="federated_access",outcome="label_mismatch"} 98
graph_ladybug_edge_type_rows{edge_type="federated_access",outcome="loaded"} 284
graph_ladybug_edge_type_rows{edge_type="federated_access",outcome="not_loaded"} 0
graph_ladybug_edge_type_rows{edge_type="member_of_zone",outcome="endpoint_absent"} 0
graph_ladybug_edge_type_rows{edge_type="member_of_zone",outcome="endpoint_expired"} 0
graph_ladybug_edge_type_rows{edge_type="member_of_zone",outcome="fetched"} 100
graph_ladybug_edge_type_rows{edge_type="member_of_zone",outcome="label_mismatch"} 0
graph_ladybug_edge_type_rows{edge_type="member_of_zone",outcome="loaded"} 0
graph_ladybug_edge_type_rows{edge_type="member_of_zone",outcome="not_loaded"} 100
`
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), "graph_ladybug_edge_type_rows"); err != nil {
		t.Fatalf("edge-type parity gauge mismatch:\n%v", err)
	}
}

// TestSourcesAreCachedForTheTTL: several ClickHouse-backed sources are
// full-table aggregates with no cache of their own, so re-reading them on
// every scrape from both pods would be expensive enough to threaten the
// instance they run on.
func TestSourcesAreCachedForTheTTL(t *testing.T) {
	var calls int
	now := time.Unix(1_720_000_000, 0)
	c := &liveCollector{
		ttl: sourceTTL,
		now: func() time.Time { return now },
		s: Sources{Unenriched: func(context.Context) []UnenrichedStat {
			calls++
			return []UnenrichedStat{{Severity: "critical", N: 7}}
		}},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	// Four scrapes inside one TTL (15s apart) must read the database once.
	for range 4 {
		require.Equal(t, 1, testutil.CollectAndCount(reg, "graph_findings_unenriched"))
		now = now.Add(15 * time.Second)
	}
	require.Equal(t, 1, calls, "a 60s TTL must collapse four 15s scrapes into one read")

	// Past the TTL it refreshes, so the gauge cannot freeze.
	now = now.Add(sourceTTL)
	require.Equal(t, 1, testutil.CollectAndCount(reg, "graph_findings_unenriched"))
	require.Equal(t, 2, calls)
}

// The zero-value collector does not cache, so tests and any future caller that
// wants a live read are unaffected.
func TestZeroTTLAlwaysRefreshes(t *testing.T) {
	var calls int
	c := &liveCollector{s: Sources{Unenriched: func(context.Context) []UnenrichedStat {
		calls++
		return []UnenrichedStat{{Severity: "high", N: 1}}
	}}}
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	for range 3 {
		testutil.CollectAndCount(reg, "graph_findings_unenriched")
	}
	require.Equal(t, 3, calls)
}

// TestFailedSourceServesStaleAndReportsFailure guards the failure mode this
// exists to remove: the Sources callbacks return a bare slice, so a query
// that errored or was cancelled by the scrape budget comes back as nil, which
// must not make the whole series vanish from /metrics — a missing series
// reads as healthy-and-quiet on every dashboard, the worst behaviour for the
// one layer whose job is catching silent gaps.
func TestFailedSourceServesStaleAndReportsFailure(t *testing.T) {
	healthy := true
	now := time.Unix(1_720_000_000, 0)
	c := &liveCollector{
		ttl: sourceTTL,
		now: func() time.Time { return now },
		s: Sources{Unenriched: func(context.Context) []UnenrichedStat {
			if !healthy {
				return nil // what a timed-out / errored CH query looks like from here
			}
			return []UnenrichedStat{{Severity: "critical", N: 7}}
		}},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	require.Equal(t, 1, testutil.CollectAndCount(reg, "graph_findings_unenriched"))
	require.Equal(t, 1.0, gaugeFor(t, reg, "graph_metrics_source_up", "unenriched"))

	healthy = false
	now = now.Add(2 * sourceTTL)

	require.Equal(t, 1, testutil.CollectAndCount(reg, "graph_findings_unenriched"),
		"the series must NOT disappear when the source fails")
	require.Equal(t, 0.0, gaugeFor(t, reg, "graph_metrics_source_up", "unenriched"),
		"a failed source must say so explicitly")
	require.InDelta(t, (2 * sourceTTL).Seconds(),
		gaugeFor(t, reg, "graph_metrics_source_age_seconds", "unenriched"), 0.001,
		"the age must show the served reading is stale, not pretend it is current")

	// And it recovers on its own.
	healthy = true
	now = now.Add(2 * sourceTTL)
	testutil.CollectAndCount(reg, "graph_findings_unenriched")
	require.Equal(t, 1.0, gaugeFor(t, reg, "graph_metrics_source_up", "unenriched"))
	require.Equal(t, 0.0, gaugeFor(t, reg, "graph_metrics_source_age_seconds", "unenriched"))
}

// A source cancelled by the scrape budget is a failure even if it happens to
// return rows — it was interrupted, so its answer is partial.
func TestScrapeBudgetCancellationIsAFailure(t *testing.T) {
	c := &liveCollector{
		ttl:    sourceTTL,
		budget: 50 * time.Millisecond, // scrapeBudget's behaviour, without the wait
		s: Sources{AssetStaleness: func(ctx context.Context) []AssetStalenessStat {
			<-ctx.Done() // stand in for a full-table scan that outlives the budget
			return nil
		}},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	done := make(chan struct{})
	go func() { defer close(done); testutil.CollectAndCount(reg, "graph_asset_total") }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scrape did not return inside its own budget")
	}

	require.Equal(t, 0.0, gaugeFor(t, reg, "graph_metrics_source_up", "asset_staleness"))
}

// Health is reported only for sources that are actually wired: a nil source has
// no health to report and must not manufacture a series.
func TestHealthGaugesOnlyForWiredSources(t *testing.T) {
	c := &liveCollector{s: Sources{Unenriched: func(context.Context) []UnenrichedStat {
		return []UnenrichedStat{{Severity: "low", N: 1}}
	}}}
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	require.Equal(t, 1, testutil.CollectAndCount(reg, "graph_metrics_source_up"),
		"exactly one wired source, so exactly one health series")
}

// TestScrapeBudgetIsShorterThanTheScrapeInterval: the scrape budget must stay
// under the cluster's scrape_timeout, and it dominates every per-source
// deadline (context.WithTimeout keeps the earlier one) — a source's own
// longer inner budget never gets to bind, so the stale-serve path is
// load-bearing, not theoretical.
func TestScrapeBudgetIsShorterThanTheScrapeInterval(t *testing.T) {
	// clusterScrapeTimeout is the scrape_timeout of the job that actually
	// scrapes these pods.
	const clusterScrapeTimeout = 9 * time.Second
	require.Less(t, scrapeBudget, clusterScrapeTimeout)
	require.LessOrEqual(t, scrapeBudget, sourceTTL)
}

// A source that has never produced a finding reports 0 rather than being left
// out — the whole point of the series is that a source with nothing to say and a
// source that is not running must not look the same.
func TestSourceActivityEmitsNeverProducedAsZero(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{
		SourceActivity: func(context.Context) []SourceActivityStat {
			return []SourceActivityStat{
				{Source: "cspm", LastActivityUnix: 1720000000},
				{Source: "nuclei", LastActivityUnix: 0},
			}
		},
	})

	require.Equal(t, float64(1720000000),
		gaugeFor(t, m.Registry(), "graph_source_last_activity_timestamp_seconds", "cspm"))
	require.Zero(t, gaugeFor(t, m.Registry(), "graph_source_last_activity_timestamp_seconds", "nuclei"),
		"an expected source that has never produced must be emitted as 0, not omitted")
}

func TestSourceActivityNilSourceEmitsNothing(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{})
	require.Zero(t, testutil.CollectAndCount(m.Registry(), "graph_source_last_activity_timestamp_seconds"))
}

// TestSourceActivityFirstScrapeErrorReportsUnhealthyNotSilentlyOk guards a
// gate that is right for most sources (an empty first read can legitimately
// mean "nothing to report yet") but wrong for SourceActivity specifically:
// its merge guarantees at least one row per expected source on every
// successful call, so an empty result can only mean the query failed, even on
// the very first read. readSource's minLen parameter (1 for this source)
// closes that gap.
func TestSourceActivityFirstScrapeErrorReportsUnhealthyNotSilentlyOk(t *testing.T) {
	m := New()
	m.RegisterSources(Sources{
		// Mirrors worker_metrics.go's own error path: `if err != nil { return nil }`.
		SourceActivity: func(context.Context) []SourceActivityStat { return nil },
	})

	require.Zero(t, sourceUpFor(t, m.Registry(), "source_activity"),
		"a query error on the very first scrape must report unhealthy, not be silently cached as healthy because no prior good value existed yet to compare against")
}

// sourceUpFor returns graph_metrics_source_up's gathered value for one source
// label. Fails the test if the sample is absent.
func sourceUpFor(t *testing.T, g prometheus.Gatherer, source string) float64 {
	t.Helper()
	families, err := g.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != "graph_metrics_source_up" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "source" && l.GetValue() == source {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("no graph_metrics_source_up for source %q", source)
	return 0
}

// gaugeFor returns the gathered value of one gauge family's source-labelled
// sample. Fails the test if the sample is absent — a vanished series is exactly
// the bug these tests exist for, so it must never read as a zero.
func gaugeFor(t *testing.T, g prometheus.Gatherer, name, source string) float64 {
	t.Helper()
	families, err := g.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "source" && l.GetValue() == source {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("no %s for source %q", name, source)
	return 0
}

// The evaluability gauges must be estate-wide, not last-writer-wins. A check
// like aws-s3-no-versioning applies across every AWS connector, and each
// connector syncs on its own schedule; a bare Set per sync would leave the gauge
// showing whichever account happened to finish last — the kind of
// averaging-away that lets a completely dark collector hide behind healthy
// siblings.
func TestObserveCheckEvaluabilitySumsAcrossConnectors(t *testing.T) {
	m := New()
	m.ObserveCheckEvaluability("aws-prod", []CheckEvaluability{
		{CheckID: "aws-s3-no-versioning", Applicable: 100, Evaluable: 100},
	})
	m.ObserveCheckEvaluability("aws-legacy", []CheckEvaluability{
		{CheckID: "aws-s3-no-versioning", Applicable: 100, Evaluable: 0},
	})

	if got := testutil.ToFloat64(m.checkApplicable.WithLabelValues("aws-s3-no-versioning")); got != 200 {
		t.Errorf("applicable assets = %v, want 200 (both connectors)", got)
	}
	if got := testutil.ToFloat64(m.checkEvaluable.WithLabelValues("aws-s3-no-versioning")); got != 0.5 {
		t.Errorf("evaluable ratio = %v, want 0.5 (one dark account of two)", got)
	}

	// A re-sync replaces that connector's reading rather than adding to it.
	m.ObserveCheckEvaluability("aws-legacy", []CheckEvaluability{
		{CheckID: "aws-s3-no-versioning", Applicable: 100, Evaluable: 100},
	})
	if got := testutil.ToFloat64(m.checkEvaluable.WithLabelValues("aws-s3-no-versioning")); got != 1 {
		t.Errorf("evaluable ratio after collector fix = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.checkApplicable.WithLabelValues("aws-s3-no-versioning")); got != 200 {
		t.Errorf("applicable assets after re-sync = %v, want 200 (replaced, not accumulated)", got)
	}
}

func TestObserveCheckEvaluabilityNilSafe(t *testing.T) {
	var m *Metrics
	m.ObserveCheckEvaluability("c", []CheckEvaluability{{CheckID: "x", Applicable: 1}})
	// An empty connector ID would collapse every connector into one bucket.
	New().ObserveCheckEvaluability("", []CheckEvaluability{{CheckID: "x", Applicable: 1}})
}

// A truncated asset load must show on its own gauge: edge_fetch_complete only
// reports the edge half, so an asset-only truncation would otherwise surface
// only through reach_edges_untruncated and the refusal counter.
func TestAssetFetchCompleteGaugeIsIndependentOfEdgeFetch(t *testing.T) {
	for _, assetOK := range []bool{true, false} {
		m := New()
		reachOK := assetOK // an asset truncation also clears ReachComplete
		m.RegisterSources(Sources{
			Graph: func() GraphStats {
				return GraphStats{ReachComplete: &reachOK, EdgeFetchComplete: true, AssetFetchComplete: assetOK}
			},
		})
		want := 0.0
		if assetOK {
			want = 1.0
		}
		mfs, err := m.Registry().Gather()
		require.NoError(t, err)
		var got *float64
		for _, mf := range mfs {
			if mf.GetName() == "graph_ladybug_asset_fetch_complete" {
				v := mf.GetMetric()[0].GetGauge().GetValue()
				got = &v
			}
		}
		require.NotNil(t, got, "the gauge must be emitted on the graph-building pod")
		require.Equal(t, want, *got)
	}
}
