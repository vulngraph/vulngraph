package obs

// This file holds the Ladybug/graph-fidelity gauge descriptors (node count and
// budget, build timestamp, fidelity-gate refusals, edge fetch/load/parity
// accounting, reachability rate) plus the describe/collect glue that emits
// them from Sources.Graph — kept out of metrics.go to stay under CLAUDE.md's
// 800-line ceiling, with the same describeXxx/collectXxx split as
// OSV/image-scan/migration/queue-age. descConnStale and descConnPartialStreak stay in metrics.go (they describe
// connector staleness, not graph fidelity), as does descAssetTotal/descAssetStale
// and everything after it in that var block.

import "github.com/prometheus/client_golang/prometheus"

var (
	descGraphNodes = prometheus.NewDesc(namespace+"_ladybug_node_count", "Nodes in the current in-memory graph.", nil, nil)
	descNodeBudget = prometheus.NewDesc(namespace+"_ladybug_node_budget", "Node count the graph retention filter is designed to stay under (graphstore.NodeBudget). Alert on node_count exceeding it: without this gauge the graph can outgrow its design budget silently, because the budget would live only in a comment.", nil, nil)
	descGraphBuilt = prometheus.NewDesc(namespace+"_ladybug_last_built_timestamp_seconds", "Unix time of the last completed graph rebuild (0 if never).", nil, nil)
	// This gauge asks whether a Reach/Inherit edge type hit a fetch cap or the
	// asset load was truncated. Every Reach/Inherit type is forced into the
	// uncapped critical tier by graphschema.TestReachAndInheritTypesAreCritical,
	// so its edge half is a registry/tier-misconfiguration detector, not a
	// graph-completeness signal, and is structurally incapable of seeing a
	// failed bulk fetch pass — _ladybug_edge_fetch_complete and
	// _ladybug_asset_fetch_complete below are the completeness signals.
	descReachOK       = prometheus.NewDesc(namespace+"_ladybug_reach_edges_untruncated", "1 when no attacker-movement (Reach) or containment (Inherit) edge type hit a fetch row cap and the asset load was not truncated in the last build; 0 means internet_hops ran fail-open and must-fix demotions are paused. NOT a graph-completeness signal: every Reach/Inherit type is pinned to the uncapped critical tier by a registry guard test, so a correct configuration holds this at 1 even during a bulk-fetch failure. Use _ladybug_edge_fetch_complete and _ladybug_asset_fetch_complete for completeness.", nil, nil)
	descFetchOK       = prometheus.NewDesc(namespace+"_ladybug_edge_fetch_complete", "1 when the last build's edge fetch covered every SYNCED tier in full: no query errored and no type hit a row cap (asset.EdgeSyncResult.FetchComplete). A failed bulk-tier fetch can drop every bulk-tier edge type to zero rows while every other gauge stays green. Since the fidelity gate refuses to publish such a build, a 0 here means a REFUSED rebuild, not a degraded live graph; pair it with _ladybug_publish_refused_total.", nil, nil)
	descAssetFetchOK  = prometheus.NewDesc(namespace+"_ladybug_asset_fetch_complete", "1 when the last build's asset load did not hit the sync row cap (asset.AssetSyncResult.Truncated). The fidelity gate refuses to publish a truncated asset load unless accept-on-repeat lets it through, so a 0 here means a refused rebuild (_ladybug_publish_refused_total) or a degraded one published anyway (_ladybug_publish_degraded_accepted_total).", nil, nil)
	descRefused       = prometheus.NewDesc(namespace+"_ladybug_publish_refused_total", "Rebuilds ABANDONED by the fidelity gate this process lifetime (graphstore/fidelity.go). Nonzero means at least one candidate graph was thrown away and the previous one kept serving — the graph is stale, not degraded. It is also the only signal that proves the gate works: it cannot move unless the gate fires.", nil, nil)
	descRefusedAt     = prometheus.NewDesc(namespace+"_ladybug_last_publish_refusal_timestamp_seconds", "Unix time of the most recent fidelity-gate refusal (0 = never). Distinguishes \"refusing right now\" from \"refused once last week\", which a lifetime counter alone cannot.", nil, nil)
	descRepeatPub     = prometheus.NewDesc(namespace+"_ladybug_publish_degraded_accepted_total", "Builds published under the fidelity gate's accept-on-repeat rule, by reason: \"step\" (a shape that failed the check arrived twice, unchanged, so it is persistent reality rather than a transient failure), \"cold_start\" (a self-reported partial fetch published only because nothing was being served yet; the escape closes the instant this happens once), \"monotonic\" (three consecutive, independently-timed refusals that each declined further than the last, confirming a multi-day teardown rather than a step). Nonzero demands a human answer to \"was this an intended estate change?\" — an account purge and a permanently broken producer look identical here by construction, and cold_start/monotonic additionally demand \"why did the gate need an escape at all?\".", []string{"reason"}, nil)
	descEdgeCapHit    = prometheus.NewDesc(namespace+"_ladybug_edge_cap_hit", "1 for each edge type whose last sync fetch hit a row cap (context-edge coverage partial).", []string{"edge_type"}, nil)
	descEdgesLoad     = prometheus.NewDesc(namespace+"_ladybug_edges_loaded", "Edges loaded into Ladybug by the last build.", nil, nil)
	descEdgesDrop     = prometheus.NewDesc(namespace+"_ladybug_edges_dropped", "Edges dropped AT LOAD TIME during the last build by reason (not_loaded = rel gated out of Ladybug, endpoint_missing = FROM/TO node absent). Scope matters: the denominator is the edges the fetch RETURNED, so an edge that was never fetched (lost upstream, in ClickHouse) is never counted as dropped here. For fetch-side loss read _ladybug_edge_fetch_complete and _ladybug_edge_type_rows{outcome=\"fetched\"}.", []string{"reason"}, nil)
	descIdentity0     = prometheus.NewDesc(namespace+"_ladybug_identity_zero_hop", "Count of exposed_to_internet edges dropped last build because their source was an identity (INV-1). MUST be 0 — alert on any nonzero: a principal is being emitted as a direct internet node (the reach-poisoning bug class).", nil, nil)
	descEdgeParity    = prometheus.NewDesc(namespace+"_ladybug_edge_type_rows", "Per edge_type, the last graph build's ClickHouse→Ladybug accounting, split by outcome: fetched (rows read out of graph_edges), loaded (rows in Ladybug), label_mismatch (endpoint node present under a DIFFERENT label than the rel declares — ALWAYS a bug), endpoint_absent (endpoint not in the inventory at all — a dangling reference, budgeted per edge type in internal/graphschema), endpoint_expired (endpoint is an ephemeral resource that is GONE — a corpse edge inside the 48h freshness window whose pod died past the 72h liveness cut; correct to drop, never a loss), not_loaded (rel deliberately gated out of Ladybug). The four drop outcomes plus loaded sum to fetched. This is the standing detector for the label-mismatch bug class: no aggregate can see it, because an edge type losing 100% of its rows is invisible inside a six-figure edges_dropped total, and rel-level counts cannot resolve it either since several edge types share one rel table. Alert on outcome=\"label_mismatch\" going nonzero for any edge_type, on graph_ladybug_edge_dangling_over_budget, on graph_ladybug_edge_expired_share_step_change, and on outcome=\"loaded\" falling to zero for a type whose fetched is nonzero. Never alert on the LEVEL of endpoint_expired: that level is by design for a type whose drops are dominated by ephemeral churn. graph_ladybug_edge_expired_share_step_change alerts on a STEP in that level instead.", []string{"edge_type", "outcome"}, nil)
	descEdgeDangle    = prometheus.NewDesc(namespace+"_ladybug_edge_dangling_over_budget", "1 for each edge_type whose endpoint_absent share exceeded the DanglingBudget declared for it in internal/graphschema (default 5% of fetched, floor 100 fetched rows). The verdict is computed in the worker, where the declared budget lives, so the alarm cannot drift from the declaration. Nonzero means a producer is writing edges to ids nothing collects, or an endpoint type is being excluded from the graph that should not be.", []string{"edge_type"}, nil)
	descEdgeExpStep   = prometheus.NewDesc(namespace+"_ladybug_edge_expired_share_step_change", "1 for each edge_type whose endpoint_expired share of fetched rows moved by more than the ExpiredShareStepBudget declared for it in internal/graphschema (default 15 percentage points, floor 100 fetched rows on both builds being compared), since the PREVIOUS build. Always 0 on a process's first build, and 0 for any build whose expired/absent split was not verified against the asset table (a snapshot fast-boot). endpoint_expired has no absolute ceiling — it sits near 100% of drops for some edge types by design — so this is the alarm the level cannot be: a stable population that suddenly moves is the signature a load-set regression, a verification-query defect, or a collector losing its high-water mark would all share, though ordinary operational churn (a rolling deploy, a node pool upgrade) can also produce it — read graph_ladybug_edge_expired_share_step_delta and the worker's paired warn log before acting.", []string{"edge_type"}, nil)
	descEdgeExpDelta  = prometheus.NewDesc(namespace+"_ladybug_edge_expired_share_step_delta", "The signed change (this build's endpoint_expired share of fetched minus the previous build's) that produced graph_ladybug_edge_expired_share_step_change for this edge_type. 0 when that gauge is 0.", []string{"edge_type"}, nil)
	descNodeTableRows = prometheus.NewDesc(namespace+"_ladybug_node_table_rows", "Rows in each node table of the served graph, read back from the engine after the load. Compare against graph_ladybug_node_group_rows: a table above one node group is exposed to ladybug#1341.", []string{"label"}, nil)
	descNodeGroupRows = prometheus.NewDesc(namespace+"_ladybug_node_group_rows", "Rows in one Ladybug node group (131072), the size above which the pinned engine release can miss relationships in multi-hop and variable-length matches (ladybug#1341).", nil, nil)
	descMultiHopRisk  = prometheus.NewDesc(namespace+"_ladybug_multihop_may_be_incomplete", "1 when a node table of the served graph holds more rows than one engine node group, so multi-hop and variable-length Cypher (attack paths, blast_radius_deep, saved queries and detections, NL-to-Cypher, raw Cypher) can return fewer paths than exist with no engine error (ladybug#1341). 0 when every table fits. Absent until a build is published. Alert on 1: the API flags such results multi_hop_may_be_incomplete, and single-hop reads and risk propagation are unaffected.", nil, nil)
	descReachRate     = prometheus.NewDesc(namespace+"_ladybug_reachability_rate", "Fraction of node-signal-cache resources with a concrete internet-reach distance (hops 0..3). A sudden spike toward 1.0 is the leading symptom of reach-signal poisoning (every resource suddenly internet-reachable) — alert on a step change.", nil, nil)
)

func (c *liveCollector) describeGraphFidelity(ch chan<- *prometheus.Desc) {
	ch <- descGraphNodes
	ch <- descNodeBudget
	ch <- descGraphBuilt
	ch <- descReachOK
	ch <- descFetchOK
	ch <- descRefused
	ch <- descRefusedAt
	ch <- descRepeatPub
	ch <- descEdgeCapHit
	ch <- descEdgesLoad
	ch <- descEdgesDrop
	ch <- descIdentity0
	ch <- descEdgeParity
	ch <- descEdgeDangle
	ch <- descEdgeExpStep
	ch <- descEdgeExpDelta
	ch <- descReachRate
	ch <- descNodeTableRows
	ch <- descNodeGroupRows
	ch <- descMultiHopRisk
}

func (c *liveCollector) collectGraphFidelity(ch chan<- prometheus.Metric) {
	if c.s.Graph == nil {
		return
	}
	g := c.s.Graph()
	collectNodeGroupGuard(ch, g)
	ch <- prometheus.MustNewConstMetric(descGraphNodes, prometheus.GaugeValue, float64(g.Nodes))
	if g.NodeBudget > 0 {
		ch <- prometheus.MustNewConstMetric(descNodeBudget, prometheus.GaugeValue, float64(g.NodeBudget))
	}
	ch <- prometheus.MustNewConstMetric(descGraphBuilt, prometheus.GaugeValue, float64(g.LastBuiltUnix))
	if g.ReachComplete != nil {
		reach := 0.0
		if *g.ReachComplete {
			reach = 1.0
		}
		ch <- prometheus.MustNewConstMetric(descReachOK, prometheus.GaugeValue, reach)
		fetch := 0.0
		if g.EdgeFetchComplete {
			fetch = 1.0
		}
		ch <- prometheus.MustNewConstMetric(descFetchOK, prometheus.GaugeValue, fetch)
		assetFetch := 0.0
		if g.AssetFetchComplete {
			assetFetch = 1.0
		}
		ch <- prometheus.MustNewConstMetric(descAssetFetchOK, prometheus.GaugeValue, assetFetch)
		// Counters, not gauges: an alert needs increase() over a window to say "the
		// gate fired just now", which a gauge that also resets on restart cannot.
		ch <- prometheus.MustNewConstMetric(descRefused, prometheus.CounterValue, float64(g.PublishRefusals))
		ch <- prometheus.MustNewConstMetric(descRepeatPub, prometheus.CounterValue, float64(g.PublishDegradedAcceptedStep), "step")
		ch <- prometheus.MustNewConstMetric(descRepeatPub, prometheus.CounterValue, float64(g.PublishDegradedAcceptedColdStart), "cold_start")
		ch <- prometheus.MustNewConstMetric(descRepeatPub, prometheus.CounterValue, float64(g.PublishDegradedAcceptedMonotonic), "monotonic")
		ch <- prometheus.MustNewConstMetric(descRefusedAt, prometheus.GaugeValue, float64(g.LastRefusalUnix))
	}
	for _, et := range g.TruncatedEdgeTypes {
		ch <- prometheus.MustNewConstMetric(descEdgeCapHit, prometheus.GaugeValue, 1.0, et)
	}
	if g.ReachComplete != nil { // same "this process builds the graph" signal
		ch <- prometheus.MustNewConstMetric(descEdgesLoad, prometheus.GaugeValue, float64(g.EdgesLoaded))
		ch <- prometheus.MustNewConstMetric(descEdgesDrop, prometheus.GaugeValue, float64(g.EdgesDroppedNotLoaded), "not_loaded")
		ch <- prometheus.MustNewConstMetric(descEdgesDrop, prometheus.GaugeValue, float64(g.EdgesDroppedEndpointMiss), "endpoint_missing")
		ch <- prometheus.MustNewConstMetric(descIdentity0, prometheus.GaugeValue, float64(g.IdentityZeroHop))
		rate := 0.0
		if g.ReachRateTotal > 0 {
			rate = float64(g.ReachRateReachable) / float64(g.ReachRateTotal)
		}
		ch <- prometheus.MustNewConstMetric(descReachRate, prometheus.GaugeValue, rate)
	}
	for _, p := range g.EdgeTypeParity {
		for _, o := range []struct {
			outcome string
			n       int64
		}{
			{"fetched", p.Fetched},
			{"loaded", p.Loaded},
			{"label_mismatch", p.LabelMismatch},
			{"endpoint_absent", p.EndpointAbsent},
			{"endpoint_expired", p.EndpointExpired},
			{"not_loaded", p.NotLoaded},
		} {
			ch <- prometheus.MustNewConstMetric(descEdgeParity, prometheus.GaugeValue, float64(o.n), p.EdgeType, o.outcome)
		}
		overBudget := 0.0
		if p.OverDanglingBudget {
			overBudget = 1.0
		}
		ch <- prometheus.MustNewConstMetric(descEdgeDangle, prometheus.GaugeValue, overBudget, p.EdgeType)
		stepChanged := 0.0
		if p.ExpiredShareStepChange {
			stepChanged = 1.0
		}
		ch <- prometheus.MustNewConstMetric(descEdgeExpStep, prometheus.GaugeValue, stepChanged, p.EdgeType)
		ch <- prometheus.MustNewConstMetric(descEdgeExpDelta, prometheus.GaugeValue, p.ExpiredShareStepDelta, p.EdgeType)
	}
}

// collectNodeGroupGuard emits the multi-hop guard (graphstore/node_group_guard.go)
// only for a published build: no counts means unknown, which must not read as 0.
func collectNodeGroupGuard(ch chan<- prometheus.Metric, g GraphStats) {
	if g.NodeTableRows == nil || g.NodeGroupRows <= 0 {
		return
	}
	ch <- prometheus.MustNewConstMetric(descNodeGroupRows, prometheus.GaugeValue, float64(g.NodeGroupRows))
	risk := 0.0
	for label, n := range g.NodeTableRows {
		ch <- prometheus.MustNewConstMetric(descNodeTableRows, prometheus.GaugeValue, float64(n), label)
		if n > g.NodeGroupRows {
			risk = 1.0
		}
	}
	ch <- prometheus.MustNewConstMetric(descMultiHopRisk, prometheus.GaugeValue, risk)
}
