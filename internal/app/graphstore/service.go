package graphstore

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AssetSource provides all assets for the bulk sync.
//
// ListAll takes the metadata projection rather than deciding it: graphstore is the
// only thing that knows which keys the loader reads, and SyncMetadataKeys is where
// that knowledge is declared. Passing the set at the call site keeps the asset domain
// ignorant of the graph schema while still avoiding a large volume of metadata JSON
// the loader never looks at (see SyncMetadataKeys).
type AssetSource interface {
	ListAll(ctx context.Context, proj asset.SyncProjection) (asset.AssetSyncResult, error)
}

// EdgeSource provides all edges for the bulk sync, with truncation accounting
// so the graph build can degrade internet_hops to ReachUnknown (fail-open)
// instead of asserting ReachNone off an incomplete edge set.
//
// VerifyExpiredEphemeral lets bulkSyncCopy check a missing endpoint's declared
// ephemeral type against the asset table before calling it a corpse, rather
// than trusting the declared type on its own. asset.Service (the only
// production implementer) backs it with a single bulk ClickHouse query per
// build; it is never called per edge.
type EdgeSource interface {
	AllEdges(ctx context.Context, proj asset.SyncProjection) (asset.EdgeSyncResult, error)
	VerifyExpiredEphemeral(ctx context.Context, ids []string) (map[string]bool, error)
}

// NodeSignals is the per-asset security context projected onto the Asset node so
// Cypher can filter on it directly (e.g. WHERE n.has_kev AND n.exploitable).
// Exposed/ToxicCombo are derived from graph topology at sync time; the rest come
// from the finding rollup (SignalSource).
type NodeSignals struct {
	Exposed      bool
	HasKEV       bool
	Exploitable  bool
	ToxicCombo   bool
	MaxScore     int
	PrivescCount int
	// InternetHops encodes reachability as a 4-state int so "unknown" is never
	// confused with "unreachable" (which would falsely demote un-readable nodes) nor
	// with "direct" (which would falsely promote not-found ones):
	//   ReachUnknown(-2) node not found / couldn't determine — fail-open, no signal
	//   ReachNone(-1)    definitively NOT reachable from the internet
	//   0                directly internet-exposed
	//   1–3              transitively reachable via an attacker-movement path
	// Topology-derived at rebuild (graphstore reach.go); the must-fix reachability
	// source reads it.
	InternetHops int
	// CveID is the check_id of the highest-scoring supply-chain CVE finding on
	// this resource (e.g. "CVE-2023-44487"). Empty for non-package nodes.
	CveID string
	// EPSSScore is the 30-day exploit-probability (0–1) for CveID, sourced from
	// the EPSS catalog at graph-sync time. Zero when CveID is empty or unknown.
	EPSSScore float64
}

// Reachability sentinels for NodeSignals.InternetHops (see the field doc).
// The constructor and helpers live in reach.go.
const (
	ReachUnknown = -2 // node not found / couldn't determine
	ReachNone    = -1 // definitively not reachable from the internet

	maxReachHops = maxReachDepth // largest valid transitive hop count (see reach.go)
)

// SignalSource supplies the finding-derived signal rollup keyed by resource id.
// Nil disables projection (nodes keep zero-valued signal props). The worker
// adapts finding.Service to this interface, so graphstore needn't import finding.
type SignalSource interface {
	SignalsByResource(ctx context.Context) (map[string]NodeSignals, error)
}

// Service manages the Ladybug lifecycle: schema, sync, and query execution.
//
// The live graph is held behind mu so SyncFromSources can build a replacement
// in-memory database off to the side and swap it in atomically. Readers take
// mu.RLock for the full duration of a query (via withRead); the swap takes the
// write lock, so it waits for in-flight reads to drain before the old database is
// closed — readers never observe a half-built or freed graph.
type Service struct {
	mu              sync.RWMutex
	db              *ladybugDB
	bufferMB        int           // remembered so SyncFromSources can build a fresh DB
	poolSize        int           // connection pool depth (LADYBUG_POOL_SIZE)
	queryThreads    int           // per-connection Ladybug threads (LADYBUG_QUERY_THREADS)
	loadThreads     int           // COPY-load parallelism (LADYBUG_LOAD_THREADS); 0 = default
	snapshotPath    string        // LADYBUG_SNAPSHOT_PATH; empty = snapshots disabled
	synced          atomic.Bool   // true once the first full sync has completed
	lastTopoVersion atomic.Uint64 // topology version from last full SyncFromSources
	nodeCount       atomic.Int64  // asset count in the live graph; 0 = empty/never-built
	emptyConfirmed  atomic.Bool   // two consecutive sweeps built the same empty graph: an empty estate, not a blip
	lastBuiltAt     atomic.Int64  // unix-nanos of the last successful build (sync or snapshot)
	reachComplete   atomic.Bool   // last build fetched every reach edge type and all assets untruncated (obs gauge)
	// edgeFetchComplete is the completeness signal — every synced edge tier fetched
	// in full — which reachComplete must not be mistaken for. See
	// asset.EdgeSyncResult.FetchComplete.
	edgeFetchComplete atomic.Bool
	// assetFetchComplete is the asset half: the last build's asset load did not
	// hit the sync row cap (asset.AssetSyncResult.Truncated).
	assetFetchComplete atomic.Bool
	// fidelity is the publish gate's memory — the last published shape, the last
	// refusal and the counters. See fidelity.go.
	fidelity        fidelityState
	identityZeroHop atomic.Int64 // INV-1: identity exposed_to_internet seeds dropped last build (obs gauge; must be 0)
	truncatedTypes  atomic.Value // []string: edge types whose last fetch hit a cap (obs gauge)
	lastLoadStats   atomic.Value // copyStats of the last build (obs gauges: loaded/dropped)
	// prevLoadStats is lastLoadStats from ONE build ago, moved there by
	// storeLoadStats before the new value overwrites it. Its only reader is
	// EdgeTypeParity's step-change check (copyStats.expiredShareStepChanges) — a
	// step is only meaningful build-over-build, and a snapshot boot or a
	// signal-only refresh (LoadFromSnapshot, refreshScores) never calls
	// storeLoadStats at all, so this only ever advances on a real bulkSyncCopy.
	prevLoadStats atomic.Value // copyStats, one build behind lastLoadStats
	// lastDigest fingerprints the load set of the last successful build. It is the
	// change signal that decides full rebuild vs signal-only refresh vs no-op
	// (see loadDigest). The caller's sync_state.topology_version check can
	// still route a sync to the signal-only path when correlate's bump failed
	// (worker_deps.go). Stored only AFTER a successful graph swap, so a failed rebuild
	// retries rather than latching a digest it never actually loaded.
	lastDigest atomic.Pointer[loadDigest]
	// lastScores stashes the post-BFS risk score the live graph holds per node
	// (bfsScoreLabels only), so refreshScores can diff-and-write just the changed
	// rows instead of rewriting every node or reading the graph back. Replaced
	// wholesale after every build (full, snapshot, or score refresh) — like the
	// graph it mirrors, it is a disposable projection of ClickHouse.
	lastScores atomic.Pointer[map[string]uint8]
	// lastSyncPath records which path the last sync took ("full"|"signals"|"noop"),
	// so the skip ratio is observable — ObserveRebuild must fire on every path, not
	// only the full rebuild.
	lastSyncPath atomic.Value // string
	syncRecorder SyncRecorder // nil = sync-path metrics disabled

	// nodeSignalsCache deduplicates NodeSignals Ladybug queries within one enrichment
	// cycle. Each finding in EnrichWorker calls NodeSignals for the same resourceID
	// up to 3× (fingerprint PrivescBucket + AttackPaths + ToxicCombo). The cache
	// turns those 3 serialised mutex-protected Ladybug queries into 1.
	// Cleared atomically when SyncFromSources swaps in a new graph — stale signals
	// from the previous graph must not pollute the next enrichment sweep.
	nodeSignalsCache sync.Map // map[string]NodeSignals

	// lastOverlay holds the reach overlay (exposure set + internet-hop map) from the
	// most recent topology build. SignalsByResource does not carry InternetHops, so
	// the signal-rollup struct defaults it to 0 — the "internet seed" value, not
	// "unknown" — and toxic_combo is topology-derived too (exposed && privesc_count
	// > 0), so a signal-only refresh (no edges) can't recompute either. The pre-warm
	// overlays both from this stash instead of trusting the raw rollup's zero values.
	lastHopsMu    sync.RWMutex
	lastOverlay   reachOverlay
	lastReachDone bool
	// lastNodeIDs is every node id loaded into Ladybug by the most recent topology
	// build, taken from the asset slice after filterLadybugAssets so it matches what
	// bulkSyncCopy actually inserted. A signal-only refresh rebuilds no topology of
	// its own, so prewarmSignalCache reuses this list to pre-warm nodeSignalsCache
	// for every loaded node, not only the finding-bearing ones sigByResource carries.
	lastNodeIDs []string

	// blastRadiusCache memoises BlastRadiusCount results for the lifetime of the
	// current graph snapshot. BlastRadiusCount is called once per finding during
	// enrichment; the same seedID appears across many findings for the same asset,
	// so the hit rate is high. The result is deterministic per graph — no TTL needed,
	// the graph swap is the invalidation event.
	blastRadiusCache sync.Map // map["seedID:depth"]int

	// blastAdj is the retained, LoadedRels()-scoped Go adjacency
	// ladybugBlastProvider.BlastRadius (cmd/graph/ladybug_blast.go) walks instead of
	// querying Ladybug — see blast_adjacency.go. Replaced wholesale (never mutated)
	// by buildBlastAdjacency on every successful topology build
	// (LoadFromSnapshot or SyncFromSources' full-rebuild path); nil until the
	// first one completes, and — unlike blastRadiusCache — never reset on a
	// build that reuses the existing topology (signals-only refresh / no-op),
	// because the adjacency it would rebuild is identical.
	blastAdj atomic.Pointer[blastAdjacency]

	// nodeTableRows is the served graph's per-node-table row count, swapped in
	// with the graph under mu (node_table_stats.go). Nil until a build is
	// published.
	nodeTableRows atomic.Pointer[map[string]int64]
}

// Ready reports whether the graph is queryable: the initial sync completed AND
// the live graph holds at least one node, or has been confirmed empty. The
// node-count guard matters because a build can "succeed" with an empty result
// (e.g. a transient ClickHouse blip returns zero rows) — without it the
// readiness probe would pass and serve would route Cypher to an empty graph,
// returning wrong/empty answers behind the LB. A fresh install really is empty,
// so an empty graph becomes ready once a second sweep reproduces it (see
// emptyConfirmed). The count is recorded at swap time (the only moment the
// graph changes), so no per-probe query is needed and the check never adds
// Ladybug pool pressure.
func (s *Service) Ready() bool {
	return s.synced.Load() && (s.nodeCount.Load() > 0 || s.emptyConfirmed.Load())
}

// NodeCount returns the asset count of the live graph (0 when empty/never-built).
// Exposed for the health/status endpoint and observability.
func (s *Service) NodeCount() int64 { return s.nodeCount.Load() }

// EdgeSyncHealth reports the edge-fetch completeness of the last build: whether
// every attacker-movement edge type was fetched untruncated, and which edge
// types hit a row cap. Feeds the obs graph gauges (reach_complete, edge_cap_hit).
func (s *Service) EdgeSyncHealth() (reachComplete bool, truncatedTypes []string) {
	if v, ok := s.truncatedTypes.Load().([]string); ok {
		truncatedTypes = v
	}
	return s.reachComplete.Load(), truncatedTypes
}

func (s *Service) storeLoadStats(ctx context.Context, st copyStats) {
	if old, ok := s.lastLoadStats.Load().(copyStats); ok {
		s.prevLoadStats.Store(old)
		if stepped := st.expiredShareStepChanges(old); len(stepped) > 0 {
			// Warn, not Info: a step this size in an edge type's expired share is
			// the shape a load-set regression, a verification-query defect, or an
			// upstream collector losing its high-water mark would all produce —
			// see graphschema.EdgeType.ExpiredShareStepBudget. It can also be
			// genuine operational churn (a rolling deploy, a node pool upgrade);
			// this log line and the paired alert exist so a human looks, not so
			// the platform decides on its own which one happened.
			log.FromContext(ctx).Warn().Interface("edge_types_expired_share_step_change", stepped).
				Msg("graphstore: an edge type's endpoint_expired share of fetched rows moved by more than its declared step budget since the previous build — internal/graphschema.EdgeType.ExpiredShareStepBudget")
		}
	}
	s.lastLoadStats.Store(st)
}

// EdgeLoadStats reports the last build's edge accounting: rows loaded into Ladybug
// and rows dropped at each gate (rel not loaded / endpoint node missing).
func (s *Service) EdgeLoadStats() (loaded, droppedNotLoaded, droppedEndpoint int64) {
	st, ok := s.lastLoadStats.Load().(copyStats)
	if !ok {
		return 0, 0, 0
	}
	return int64(st.edgesLoaded), int64(st.droppedNotLoaded), int64(st.droppedEndpointMiss)
}

// LastBuiltAt returns the wall-clock time of the last successful build, or the
// zero time if the graph has never been built. Used for staleness observability.
func (s *Service) LastBuiltAt() time.Time {
	ns := s.lastBuiltAt.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// GraphHealth implements explore.NodeStatsProvider from the state recorded at
// swap time, so reading it never queries Ladybug. ctx is unused: the method
// matches the worker RPC, which needs one.
func (s *Service) GraphHealth(_ context.Context) (explore.GraphHealth, error) {
	h := explore.GraphHealth{Ready: s.Ready(), NodeCount: s.NodeCount(), LastBuiltAt: s.LastBuiltAt()}
	// Keep the legacy completeness fields for clients and mixed-version RPC.
	// v0.22.3 fixes the node-group bug; table size alone no longer flags paths.
	_, h.NodeTablesMeasured = s.NodeTableRows()
	h.OversizedNodeTables = map[string]int64{}
	return h, nil
}

// Open opens the Ladybug graph engine. In-memory mode is used unconditionally (the
// path argument is ignored): file-backed mode can fail in some container
// runtimes (see ADR 071), and the graph is rebuilt from ClickHouse
// post-correlate, so persistence is not needed — in-memory also avoids disk I/O.
//
// poolSize and queryThreads are runtime-tunable via LADYBUG_POOL_SIZE and
// LADYBUG_QUERY_THREADS; pass 0 to use defaults (8 and 2 respectively).
// snapshotPath is the LADYBUG_SNAPSHOT_PATH for PVC-backed fast restarts; empty
// disables snapshots.
func Open(_ string, bufferPoolMB, poolSize, queryThreads int, snapshotPath string) (*Service, error) {
	if bufferPoolMB <= 0 {
		bufferPoolMB = 256
	}
	db, err := openAndInit(bufferPoolMB, poolSize, queryThreads)
	if err != nil {
		return nil, fmt.Errorf("graphstore.Open: %w", err)
	}
	svc := &Service{
		bufferMB:     bufferPoolMB,
		poolSize:     poolSize,
		queryThreads: queryThreads,
		snapshotPath: snapshotPath,
		db:           db,
	}
	return svc, nil
}

// SetLoadThreads sets the COPY bulk-load parallelism (LADYBUG_LOAD_THREADS). Pass 0
// to use the default (min(NumCPU, 4)). Env reading stays in cmd/graph; this keeps
// graphstore free of os.Getenv.
func (s *Service) SetLoadThreads(n int) { s.loadThreads = n }

// resolveLoadThreads returns the configured COPY parallelism, or the default.
func (s *Service) resolveLoadThreads() int {
	if s.loadThreads > 0 {
		return s.loadThreads
	}
	return defaultLoadThreads()
}

// openAndInit opens a fresh in-memory Ladybug database and applies the current
// schema DDL to it. Used both at startup and for every SyncFromSources rebuild,
// so the new graph is always at SchemaVersion before any rows are inserted.
func openAndInit(bufferMB, poolSize, queryThreads int) (*ladybugDB, error) {
	db, err := openLadybug(":memory:", bufferMB, poolSize, queryThreads)
	if err != nil {
		return nil, fmt.Errorf("openAndInit: in-memory failed: %w", err)
	}
	wc, err := db.newWriteConn()
	if err != nil {
		db.close()
		return nil, fmt.Errorf("openAndInit: write conn: %w", err)
	}
	defer wc.Close()
	if err := applySchema(wc, SchemaVersion); err != nil {
		db.close()
		return nil, fmt.Errorf("openAndInit: schema: %w", err)
	}
	return db, nil
}

func (s *Service) Close() {
	s.mu.Lock()
	old := s.db
	s.db = nil
	s.mu.Unlock()
	if old != nil {
		old.close()
	}
}

// withRead runs fn against the live graph's shared read connection while holding
// the swap lock for read, so SyncFromSources cannot swap-and-close the database
// mid-query. Returns ErrLadybugUnavailable if the graph is not open. The pool wait
// honours ctx and the query is interrupted after timeout or on ctx cancellation,
// so no reader can hold the swap lock unboundedly.
func (s *Service) withRead(ctx context.Context, timeout time.Duration, fn func(*ladybug.Connection) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return ErrLadybugUnavailable
	}
	return s.db.withRead(ctx, timeout, fn)
}

// withCypher is withRead for caller-supplied Cypher: it runs on the dedicated
// cypherPool so user queries cannot starve internal reads.
func (s *Service) withCypher(ctx context.Context, fn func(*ladybug.Connection) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return ErrLadybugUnavailable
	}
	return s.db.withCypher(ctx, defaultQueryTimeout, fn)
}

// withTryRead is the non-blocking variant: returns ErrPoolBusy immediately
// if all Ladybug connections are in use. Used by blast-radius walks in the
// respond agent to fall back to ClickHouse instead of waiting minutes.
func (s *Service) withTryRead(fn func(*ladybug.Connection) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return ErrLadybugUnavailable
	}
	return s.db.withTryRead(defaultQueryTimeout, fn)
}
