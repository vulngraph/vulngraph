package obs

import "context"

// Live-state stat types and the Sources callbacks that read them on scrape,
// split out to keep metrics.go under CLAUDE.md's 800-line ceiling — the same
// reason OSVScanStalenessStat lives in metrics_osv.go instead of here.

// QueueStat is one River queue/state depth reading.
type QueueStat struct {
	Queue string
	State string
	N     int
}

// GraphStats is the current in-memory graph size, last rebuild time, and edge
// fetch health of the build that produced it.
type GraphStats struct {
	Nodes int64
	// NodeBudget is the node count the retention filter is designed to hold the
	// graph under (graphstore.NodeBudget). Emitted so nodes-vs-budget is alertable
	// instead of being a comment nothing compares against.
	NodeBudget    int64
	LastBuiltUnix int64 // 0 when never built
	// ReachComplete is false when the last build's attacker-movement edge fetch
	// was truncated or failed, or its asset fetch was truncated — internet_hops
	// degraded to ReachUnknown and must-fix reachability ran fail-open (alert:
	// real demotions are paused).
	// Nil when the process doesn't build the graph (serve pod) — no gauge emitted.
	ReachComplete *bool
	// EdgeFetchComplete is the edge-completeness signal (ReachComplete is not
	// one): every synced edge tier fetched in full (no failed pass, no capped
	// type). AssetFetchComplete is the asset half: the asset load did not hit
	// the sync row cap. Only read when ReachComplete is non-nil, i.e. on the pod
	// that builds the graph.
	EdgeFetchComplete  bool
	AssetFetchComplete bool
	// PublishRefusals counts rebuilds the fidelity gate abandoned this process
	// lifetime; PublishDegradedAccepted counts those published under accept-on-repeat
	// (the sum of the three category counters below — kept as its own field so a
	// dashboard reading the unlabelled total keeps working).
	// LastRefusalUnix is the wall time of the most recent refusal (0 = never).
	PublishRefusals         int64
	PublishDegradedAccepted int64
	// PublishDegradedAcceptedStep/ColdStart/Monotonic break PublishDegradedAccepted
	// down by which accept-on-repeat rule fired: a step (the same degraded shape
	// arrived twice), a cold_start (a self-reported partial fetch published
	// because nothing was being served yet), or a monotonic decline (a
	// multi-day teardown whose shape never repeats exactly). The three are
	// operationally unrelated, so folding them into one counter would make
	// "was that you?" unanswerable.
	PublishDegradedAcceptedStep      int64
	PublishDegradedAcceptedColdStart int64
	PublishDegradedAcceptedMonotonic int64
	LastRefusalUnix                  int64
	// TruncatedEdgeTypes are edge types whose last fetch hit a row cap —
	// context-edge coverage is partial for them.
	TruncatedEdgeTypes []string
	// Edge accounting for the last build: rows loaded into Ladybug, and rows
	// dropped at each gate. A drift between fetched and loaded that isn't
	// explained by these two reasons is a new bug class.
	EdgesLoaded              int64
	EdgesDroppedNotLoaded    int64 // edge_type unmapped or rel not loaded (declared bfs_only)
	EdgesDroppedEndpointMiss int64 // FROM/TO node absent under the rel's typed label
	// IdentityZeroHop is the count of exposed_to_internet edges dropped last build
	// because their source was an identity (INV-1). Must stay 0 — nonzero means a
	// principal is being emitted as a direct internet node (the poisoning bug).
	IdentityZeroHop int64
	// ReachRateReachable/ReachRateTotal give the internet-reachability rate over
	// the node-signal cache: reachable = resources at hops 0..3, total = cached.
	// A sudden spike toward 1.0 is the leading symptom of reach-signal poisoning.
	// Both 0 when the process doesn't build the graph.
	ReachRateReachable int64
	ReachRateTotal     int64
	// EdgeTypeParity is the per-edge_type ClickHouse→Ladybug accounting for the last
	// build. Empty when the process doesn't build the graph.
	EdgeTypeParity []EdgeTypeParityStat
	// NodeTableRows is the served graph's row count per node table, and
	// NodeGroupRows the storage node-group size, not a correctness limit.
	// Nil NodeTableRows means no build was published: no gauge is emitted.
	NodeTableRows map[string]int64
	NodeGroupRows int64
}

// EdgeTypeParityStat is one edge_type's fetched-vs-loaded accounting for the last
// graph build. The four outcomes sum to Fetched.
//
// This is the standing detector for the label-mismatch bug class: a producer
// emits an edge whose endpoint type has been promoted off the node label its rel
// table declares, the loader's typed lookup finds nothing, and the row is dropped
// with no error, no warning, and no signal at all otherwise.
//
// Nothing else can see it. The aggregate edges_loaded/edges_dropped gauges are
// six-figure totals in which an edge type losing 100% of its rows is invisible,
// and rel-level counts cannot help either because several edge types share one rel
// table. Per edge_type is the granularity at which ClickHouse and Ladybug diverge.
//
// Alert on LabelMismatch: it is a bug in every case, unlike EndpointAbsent, which
// is permanent irreducible reality (cross-account root principals that are not
// assets and never will be) — summing the two together makes the alarm fire
// identically on every build and mean nothing. Loaded/Fetched dropping to zero
// for a type that previously loaded is the other signal to watch: that is a
// fetch-tier starvation or a total mismatch.
//
// EndpointExpired is the same lesson applied one level down: most endpoint-absent
// rows are edges to an ephemeral resource (e.g. a k8s_pod) whose asset read
// excludes it on liveness while the edge is still inside its freshness window —
// dropping the row is correct, the resource is gone. Counting those alongside
// genuine dangling references buries a real regression under permanent noise.
// Alert on OverDanglingBudget, never on EndpointExpired.
type EdgeTypeParityStat struct {
	EdgeType        string
	Fetched         int64
	Loaded          int64
	LabelMismatch   int64 // endpoint present under a DIFFERENT label — always a bug
	EndpointAbsent  int64 // endpoint not in the inventory at all — a dangling reference
	EndpointExpired int64 // endpoint is an expired ephemeral resource — a corpse edge
	NotLoaded       int64 // rel deliberately gated out of Ladybug (bfs_only) or unmapped
	// OverDanglingBudget is the worker's own verdict on EndpointAbsent for this
	// type, against the budget declared in internal/graphschema. It is computed
	// where the budget lives rather than in a PromQL expression so the declared
	// number cannot drift from the alarm that reads it.
	OverDanglingBudget bool
	// ExpiredShareStepChange is the worker's own verdict on EndpointExpired for
	// this type: whether its share of Fetched moved by more than
	// graphschema.ExpiredShareStepBudget since the previous build. It is a step,
	// not a level, because the level is legitimately near 100% for some types
	// by design, so a level-based alarm would either never fire or fire
	// permanently. False on a process's first build (nothing to compare against).
	ExpiredShareStepChange bool
	// ExpiredShareStepDelta is the signed change in expired share (current minus
	// previous build) that produced ExpiredShareStepChange, for the alert
	// description and for a human comparing magnitude across edge types. 0 when
	// ExpiredShareStepChange is false.
	ExpiredShareStepDelta float64
}

// ConnectorStat is one connector's freshness at scrape time.
type ConnectorStat struct {
	Name  string
	Stale bool
	// PartialStreak mirrors connector.Connector.PartialStreak: consecutive
	// syncs in a row whose collection was best-effort incomplete
	// (collect.Result.Partial). A sustained nonzero value is invisible to
	// Stale above — Stale reads LastSuccessAt, which keeps advancing on a
	// Partial-but-runErr-nil sync — and gates off deletion detection and
	// finding auto-resolution the whole time it holds. See
	// connector.PartiallyStale / connector.DefaultPartialStreakThreshold.
	PartialStreak int32
}

// AssetStalenessStat is one provider's collection freshness at scrape time.
// Stale is anchored to that provider's OWN high-water mark (asset.ProviderHighWater),
// never wall-clock — a collector outage freezes the high-water mark with it, so
// the cutoff stops advancing and nothing new is ever counted stale, instead of
// the whole estate looking freshly dead the moment collection stops.
type AssetStalenessStat struct {
	Provider string
	Total    int64
	Stale    int64 // last_seen older than the provider's high-water mark by the staleness margin
}

// UnenrichedStat is the count of open findings at one severity that the
// enrichment pipeline has never reached (enriched_at unset).
//
// Such findings are invisible to every other signal: they carry no score and
// no score_band, so Summary excludes them from ByBand and a score-sorted
// worklist buries them at the bottom. Healthy is a small, mostly same-day
// figure — the residue of normal ingest lag. Alert on a rising count or a
// high/critical entry that persists across scrapes: backlog depth, not just
// throughput, distinguishes a sweep that is keeping up from one that is not.
type UnenrichedStat struct {
	Severity string
	N        int64
}

// OSVScanStalenessStat is defined in metrics_osv.go, split out to keep this
// file under CLAUDE.md's 800-line ceiling.

// UnclassifiedStat is, for one source, how many of its open findings carry a
// must_fix_class and how many are blank — the prioritisation-coverage signal.
//
// A finding that is enriched but unclassified looks healthy everywhere else:
// it has a score, a band and a page in the UI. Nothing else asks whether the
// classifier actually reached an opinion about it, so a whole source
// producing nothing but blanks is otherwise indistinguishable from one
// working perfectly.
//
// Read it as a ratio per source: blank/(blank+classified). A source pinned
// near 1.0 means its findings can never reach must_fix no matter how severe
// they are. The classifier names its fall-through verdict rather than
// returning "", so a blank here excludes the "weighed, no
// exploitability evidence" majority — what remains is a source whose
// enrichment fails open, or rows an in-progress re-enrich sweep hasn't
// reached yet, which is why the alert is a sustained ratio near 1.0 rather
// than any nonzero count.
type UnclassifiedStat struct {
	Source     string
	Blank      int64
	Classified int64
}

// CheckQualityStat is one check's measured usefulness: how its findings ended.
//
// Without this metric, finding quality is unfalsifiable: nothing else measures
// whether a check produces work worth doing, so a persistently useless check
// can keep running unnoticed.
//
// JunkRate is resource_gone / (fixed + resource_gone + manual): the share of a
// check's resolutions that closed because the resource evaporated rather than
// because anyone acted. High is bad. provider_closed and unknown-reason rows are
// excluded (unknowable), which is why the counts do not sum to the total.
type CheckQualityStat struct {
	CheckID      string
	Source       string
	Open         int
	Fixed        int
	ResourceGone int
	Manual       int
	JunkRate     float64
	// Measurable is false when the check has too few resolutions for JunkRate to
	// mean anything. Emitted anyway, as its own series, so "not enough evidence yet"
	// is visible instead of looking like a clean 0.0.
	Measurable bool
}

// SourceActivityStat is one finding-source's production recency: the newest
// last_seen across its findings, and whether the platform expects it to produce
// at all.
//
// Zero is a finding: without this, nothing distinguishes "this source ran and
// had nothing new to say" from "this source has not run at all". last_seen,
// not first_seen, is the right anchor because a healthy source re-stamps
// last_seen on its existing findings every sweep, so the timestamp advances
// even when nothing new is found. A frozen last_seen means the source did not
// run, which is the thing worth alerting on.
//
// The caller must enumerate every source the platform expects, not only those
// with rows: a source that has never produced anything is the loudest case and
// has no rows to aggregate over. Such a source reports LastActivityUnix 0,
// which reads as an infinitely old timestamp to the staleness alert instead of
// vanishing from the series set.
type SourceActivityStat struct {
	Source string
	// LastActivityUnix is the newest last_seen over the source's findings, or 0
	// when the source is expected but has never produced one.
	LastActivityUnix int64
}

// ConnectorCoverageStat is one provider's "expected vs configured" connector
// coverage, for the (provider, dimension) pairs the platform can derive
// honestly from data it has already collected: kubernetes (distinct region)
// and aws (distinct account_id). Seen is the distinct dimension-value count
// observed in current assets; Configured is the number of enabled connectors
// of that provider type. Seen > Configured means at least one live
// account/cluster has no connector at all — invisible from ConnectorStat
// alone, which only describes connectors that exist.
type ConnectorCoverageStat struct {
	Provider   string
	Dimension  string // "region" (kubernetes) or "account_id" (aws)
	Seen       int64
	Configured int64
}

// Sources are the live-state callbacks obs reads on each scrape. Any may be nil
// (its metrics are then simply not emitted). They must be cheap and non-blocking
// enough for a scrape path — the queue/backlog readers are single indexed SQL
// counts. Each receives the scrape context for cancellation.
type Sources struct {
	QueueDepth        func(ctx context.Context) []QueueStat
	Graph             func() GraphStats
	Connectors        func(ctx context.Context) []ConnectorStat
	AssetStaleness    func(ctx context.Context) []AssetStalenessStat
	ConnectorCoverage func(ctx context.Context) []ConnectorCoverageStat
	Unenriched        func(ctx context.Context) []UnenrichedStat
	Unclassified      func(ctx context.Context) []UnclassifiedStat
	CheckQuality      func(ctx context.Context) []CheckQualityStat
	SourceActivity    func(ctx context.Context) []SourceActivityStat
	// OSVScanStaleness returns exactly one reading (wrapped in a slice to reuse
	// readSource's TTL cache and failure/health tracking — there is no natural
	// label dimension to split it by, unlike the per-provider sources above).
	OSVScanStaleness func(ctx context.Context) []OSVScanStalenessStat
	// FindingAge returns exactly one reading, wrapped in a slice for the same
	// reason as OSVScanStaleness (readSource's TTL cache and health tracking).
	FindingAge func(ctx context.Context) []FindingAgeStat
	// ImageScanCoverage returns exactly one reading, same shape and reason as
	// OSVScanStaleness. Defined in metrics_imagevuln.go.
	ImageScanCoverage func(ctx context.Context) []ImageScanCoverageStat
	// Migration returns one reading per migration set (postgres, clickhouse,
	// river). Defined in metrics_migration.go; the caller is expected to run
	// internal/migrate.Status and map its []DBStatus into []MigrationStat.
	Migration func(ctx context.Context) []MigrationStat
	// QueueOldestAvailable returns one reading per River queue that currently
	// has at least one available job. Defined in metrics_queue_age.go; the
	// caller owns the river_job query, same as QueueDepth (jobs.QueueDepths).
	QueueOldestAvailable func(ctx context.Context) []QueueAgeStat
}
