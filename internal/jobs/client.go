package jobs

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertype"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/intel"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/intel/updateinfo"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
)

const (
	queueSync      = "sync"
	queueEnrich    = "enrich"
	queueRespond   = "respond"
	queueCorrelate = "correlate"
	// queueScan carries every kind that EXECUTES NUCLEI: the estate scan, profile
	// runs and drift scans. They share one lane on purpose — see queueContentScan.
	queueScan       = "scan"
	queueAdjudicate = "adjudicate" // dedicated lane: the 20-min sweep must not block the respond queue
	queueDrift      = "drift"      // dedicated lane: LLM drift analysis must not wait behind the adjudicator sweep
	queueDangling   = "dangling"   // dedicated lane: the resolve sweep must not block enrich/correlate
	queueReenrich   = "reenrich"   // dedicated lane: full-pass rounds must not occupy an enrich slot
	// queueFeeds is the dedicated lane for low-urgency periodic feed refreshes
	// (domain_monitor, refresh_kev, refresh_epss). They must not share
	// queueRespond: respondWorkers is pinned at 1 for its own decide traffic, so
	// anything else riding that lane can queue behind it indefinitely. None of these three
	// need respond's low latency; they need their own lane so a busy decide
	// backlog can't starve them (CLAUDE.md: "periodic work must never starve
	// agent runs").
	queueFeeds = "feeds"
	// queueGraph is the dedicated lane for the Ladybug rebuild and the per-minute
	// scheduler ticks. They must not ride the correlate queue, which has exactly
	// ONE worker by design (a whole-graph join at a time) and runs near
	// saturation.
	//
	// Correlate itself tolerates that — it is a steady background join. These
	// tenants cannot: ladybug_rebuild is what makes a topology change visible to
	// every graph query, and the saved-query and scan-profile ticks are
	// per-MINUTE schedules, so sitting behind a backlog would make the graph
	// stale and turn "every minute" into "whenever correlate drains".
	queueGraph = "graph"
	// queueContentScan is the second heavy-scan lane. There is one heavy lane per
	// kind of heavy work and per pod-affinity: queueScan and queueDiskScan run on
	// the scanner pod, queueContentScan on the worker.
	//
	// The routing problem: River's producer fetches by QUEUE, not by kind. Every
	// kind sharing a queue is fetched by every pod consuming that queue, whether
	// or not it can work it — and a kind it cannot work resolves to
	// rescueOnlyWorker, which errors fast and can starve the pod that CAN work
	// it. This is a STRUCTURAL argument, not a volume one.
	//
	// The split is by POD, not by kind, and each lane's MaxWorkers 1 (see
	// queueWorkerCounts) is what bounds concurrency:
	//   queueScan        nuclei execution — scan, scan_profile, scan_asset
	//   queueContentScan image content — refresh_image_vuln
	//   queueDiskScan    VM disk reads — disk_scan_volume
	// So a lane runs at most ONE heavy scan at a time; the scanner pod, which
	// consumes two lanes, can run one nuclei scan and one disk read together. Four
	// separate lanes for the nuclei kinds would have quadrupled the budget silently.
	//
	// consumedQueues derives the consumed set from the kinds a client registered a
	// REAL worker for, so a lane whose kinds this pod cannot work is not consumed.
	queueContentScan = "content_scan"
	// graphWorkers = 2: ladybug_rebuild is unique-gated (see LadybugRebuildArgs
	// InsertOpts) so at most one ever runs, and the second slot keeps the light
	// per-minute ticks from queuing behind a 2-4 minute rebuild.
	graphWorkers = 2
	syncWorkers  = 20 // sync is I/O-bound (cloud APIs); most are fingerprint no-ops (Postgres read only).
	// enrichWorkers: sized against ClickHouse's memory limit and the worker
	// pod's own memory, which is the binding constraint here, not CPU. Step
	// back down if worker memory climbs toward its limit under sustained load.
	enrichWorkers     = 10
	respondWorkers    = 1 // decide jobs are LLM-bound; one at a time keeps the backlog steady, and respondQueueMax caps depth
	correlateWorkers  = 1 // one whole-graph join at a time; never starves sync
	adjudicateWorkers = 1 // one long (≤20m) adjudication sweep at a time, isolated from respond
	driftWorkers      = 1 // one LLM drift analysis at a time; spend is bounded by the llmusage budget
	danglingWorkers   = 1 // one dangling-finding resolve sweep at a time
	// feedsWorkers: domain_monitor/refresh_kev/refresh_epss are all-or-nothing
	// periodic ticks (hours to a day apart), not a queue that needs to drain
	// fast — one worker is plenty and keeps them from ever competing with each
	// other for the same external feed.
	feedsWorkers = 1
	// reenrichWorkers: one full-pass round at a time. Rounds are sequential by
	// construction (each schedules the next), so concurrency here would only mean two
	// passes racing to enqueue the same stale findings — doubling enrich queue depth
	// against the pacing this design depends on.
	reenrichWorkers = 1
	// heavyScanWorkers: one resource-heavy scan at a time per lane. A nuclei run
	// saturates the scanner pod's CPU and memory; an image sweep pulls and unpacks
	// registry images for tens of minutes on the memory-bound worker pod. Neither is
	// something to run two of.
	heavyScanWorkers = 1

	// defaultSyncInterval is the fallback when SYNC_INTERVAL is unset. 2h gives
	// the enrichment/correlate/decide pipeline room to process between sync
	// waves without saturating ClickHouse.
	defaultSyncInterval = 2 * time.Hour

	// enqueueCheckInterval is how often EnqueueSyncsArgs' periodic TICK fires —
	// deliberately much shorter than defaultSyncInterval/SYNC_INTERVAL (the
	// backoff's own base, used only inside isDueForSync's comparison, see
	// enqueue.go). last_synced_at is stamped when a sync COMPLETES, not when
	// its tick fired, so checking at the same cadence as the backoff base would
	// silently stretch every connector's effective interval by however long its
	// sync plus queue wait took. Checking far more often than we ACT keeps that
	// timing slop small, at the cost of one cheap connector-list query every 15
	// min.
	enqueueCheckInterval = 15 * time.Minute
	// defaultCorrelateInterval: the full whole-graph sweep, kept separate from
	// sync so it can be tuned independently. A completed sweep takes several
	// minutes end-to-end, so 30m leaves comfortable idle time between runs;
	// CorrelateArgs.InsertOpts bounds retries so a failing sweep can't overlap
	// the next one.
	defaultCorrelateInterval = 30 * time.Minute
	// defaultEnrichInterval is the backstop sweep cadence. 15m (with
	// enrichSweepMax per tick) drains the never-enriched backfill quickly and
	// propagates KEV/EPSS drift within 15m; once the backlog clears, Phase 1
	// no-ops and the change-gate makes most drift-pass findings cache-skips, so
	// the frequent ticks are cheap.
	defaultEnrichInterval = 15 * time.Minute
	// adjudicateInterval: the severity adjudication sweep. Every 30
	// min picks up newly-drifted high-band findings; the per-sweep cap and the
	// deterministic-agreement fast-path keep LLM spend bounded regardless of cadence.
	adjudicateInterval = 30 * time.Minute
	// kevInterval: CISA KEV catalog. Daily is sufficient — CISA publishes updates a
	// few times per week. The periodic re-applies the refreshed catalog to standing
	// findings and (via RunOnStart) runs on every boot; there is no full ingest-time
	// re-application path (the OSV worker only chains a KEV refresh for its own new
	// findings), so this sweep is the only thing that propagates newly-listed CVEs.
	kevInterval = 24 * time.Hour
	// osvInterval: package inventory vs OSV/GHSA. Daily scan of a large package inventory avoids
	// hammering the OSV batch API, which times out under an hourly cadence. This
	// periodic is the ONLY path that produces supply-chain findings — there is no
	// ingest-time OSV trigger; the Postgres scan cursor keeps boot re-runs cheap.
	osvInterval = 24 * time.Hour
	// distroAdvisoryInterval: ALAS / ELSA updateinfo. Vendors publish a few
	// advisories a day; the steady-state run is one conditional GET per
	// repository, so daily costs almost nothing and matches OSV's cadence.
	distroAdvisoryInterval = 24 * time.Hour
	// imageVulnInterval: container-image CVE sweep. Daily is well under
	// the 48h graph_edges freshness window, so the runs_package edges the
	// sweep writes stay traversable for the must-fix path between runs.
	imageVulnInterval = 24 * time.Hour
	// epssInterval: FIRST.org publishes EPSS once daily — no point refreshing more.
	epssInterval = 24 * time.Hour
	// sccInterval: GCP Security Command Center threat findings. Daily refresh
	// is appropriate; critical detections are handled in real-time by GCP.
	sccInterval = 24 * time.Hour
	// danglingInterval: the dangling-finding resolve sweep. Hourly —
	// each tick resolves at most danglingResolveMax orphans, so hourly drains a
	// large backlog in about a day and then no-ops down to whatever the deletion
	// path missed since. It is a backstop, not a live path, so cadence is not
	// latency-sensitive.
	danglingInterval = time.Hour

	// workerSoftStopTimeout gives an in-flight job a bounded window to finish
	// naturally after SIGTERM instead of instant hard-cancellation. Without
	// it, River's work context inherits the start context directly, so every
	// deploy's SIGTERM (not just a crash) kills every in-flight job — a
	// KEV/OSV/EPSS/SCC fetch, a dangling or correlate-partial run — no matter
	// how close to finishing. Most job kinds finish in low tens of seconds and
	// are exactly what this rescues. The whole shutdown must fit
	// deployment-worker.yaml's terminationGracePeriodSeconds — see
	// WorkerStopTimeout. Does NOT rescue a correlate full sweep (20 min) or
	// anything longer — still cancelled mid-deploy, and counted "cancelled",
	// not "error".
	workerSoftStopTimeout = 20 * time.Second
	// scannerSoftStopTimeout: same mechanism, sized to deployment-scanner.yaml's
	// terminationGracePeriodSeconds: 120 — a full nuclei profile fanout (up to
	// 4h) is not rescued either, only whatever shorter scan job fits the margin.
	scannerSoftStopTimeout = 100 * time.Second

	// hardStopDrain is how long Stop waits, after the soft-stop timeout has
	// cancelled the remaining jobs, for them to return and their completions
	// to be written.
	hardStopDrain = 10 * time.Second
	// WorkerStopTimeout and ScannerStopTimeout bound client.Stop in
	// cmd/graph. Stop returns at ITS deadline even if SoftStopTimeout has not
	// fired, so a shorter Stop deadline silently cuts the soft stop short (a 30s
	// Stop deadline cuts a 100s soft stop to 30s).
	//
	// Worker shutdown = WorkerStopTimeout (30s) + the correlate coalescer's
	// final flush (correlateCoalesceFlushTimeout, 10s) + closing Ladybug/DB
	// pools: deployment-worker.yaml's grace period is 50s to cover it.
	// TestShutdownFitsTerminationGracePeriod pins both charts to these.
	WorkerStopTimeout  = workerSoftStopTimeout + hardStopDrain
	ScannerStopTimeout = scannerSoftStopTimeout + hardStopDrain

	workerShutdownBudget  = WorkerStopTimeout + correlateCoalesceFlushTimeout
	scannerShutdownBudget = ScannerStopTimeout
)

// uniqueStates are the job states in which a connector sync counts as
// "already pending" — so overlapping sweeps don't double-enqueue it. River
// requires ByState to contain all of its required states; pending is one of
// them, so omitting it makes every unique insert fail at runtime.
var uniqueStates = []rivertype.JobState{
	rivertype.JobStatePending,
	rivertype.JobStateAvailable,
	rivertype.JobStateRunning,
	rivertype.JobStateRetryable,
	rivertype.JobStateScheduled,
}

// reindexerSchedule disables River's built-in reindexer on every electable client.
//
// River runs `REINDEX CONCURRENTLY` daily over several river_job indexes.
// `REINDEX CONCURRENTLY` interrupted by a deploy, spot eviction, or statement
// timeout — all routine here — leaves behind an INVALID `_ccnew` index that
// Postgres still maintains on every write but never uses for reads: a
// permanent write-amplification tax that re-litters on the next interrupted
// run. River deletes completed jobs on its own retention schedule, so these
// indexes never accumulate the long-lived dead tuples a reindex exists to
// reclaim in the first place.
//
// Disabling the reindexer is what keeps those artefacts from appearing at all;
// the underlying indexes are created by River's own migrations.
//
// Set on the worker client AND the scanner client: both are electable, and
// River runs maintenance services on whichever wins the election.
var reindexerSchedule = river.NeverSchedule()

// Deps are the services the workers need.
type Deps struct {
	Connectors  *connector.Service
	Registry    *collect.Registry
	Assets      *asset.Service
	Findings    *finding.Service
	Checks      *checks.Registry
	Scans       *scan.Service
	Enrich      *enrich.Service
	EnrichCache EnrichCache
	// AlertCarriers names the root-cause finding carrying a package finding's
	// alerting (enrich.SupplyChainExposure); nil = every finding alerts itself.
	AlertCarriers AlertCarrier
	// EnrichMaxAge is the freshness backstop for the enrich change-gate;
	// zero uses defaultEnrichMaxAge. Set via ENRICH_MAX_AGE.
	EnrichMaxAge time.Duration
	// FullPass records which enrichment LogicVersion the corpus has been fully
	// processed for, so a version change triggers exactly one pass, and gates the
	// reenrich lane. Nil disables the full-pass mechanism entirely — correct for the
	// serve/scanner pods, which must not drive a corpus-wide re-enrichment.
	FullPass fullPassMarker
	// Forget evaluates, per proven-complete collector scope, what deletion
	// enforcement WOULD forget. Nil disables the evaluation entirely —
	// correct for any pod that does not sync connectors, and the default until
	// the worker wires it.
	Forget scopeForgetter
	// Drift enqueues drift-triggered scans (SyncWorker.drift) for the external
	// assets a connector sync reports as newly changed. Nil disables the
	// enqueue entirely — a field that compiles but is never assigned disables
	// drift scans silently (worker_wiring_guard_test.go guards that shape).
	// See jobs.NewEnqueuer(...).WithDriftProfiles(...).
	Drift    driftScanner
	Suppress *suppress.Service
	Respond  *respond.Service
	// KEVFetcher, OSV and MalFeed are outbound feeds that are on by default.
	// Nil means switched off (feeds.go): the periodic is not scheduled, but
	// the worker stays registered and no-ops, because the OSV and image-vuln
	// workers enqueue KEV refreshes of their own.
	KEVFetcher KEVFetcher
	// KEVAdditions records each newly listed KEV CVE as a `kev.added` event.
	KEVAdditions KEVAdditionRecorder
	OSV          OSVQuerier
	// MalFeed is OSV's bulk malicious-packages feed (osv_malfeed.go) — a
	// separate, much-faster-cadence path than OSV above.
	MalFeed MalFeedQuerier
	// DistroAdvisories fetches the Amazon Linux / Oracle Linux updateinfo
	// feeds for DistroAdvisorySources (Feeds.DistroAdvisorySources). Nil, or
	// no sources, means both distro feeds are switched off.
	DistroAdvisories      DistroAdvisoryFetcher
	DistroAdvisorySources []updateinfo.Source
	// EPSSFetcher + EPSSCache refresh the in-memory EPSS catalog. Nil
	// disables the feed (worker/periodic not registered).
	EPSSFetcher EPSSFetcher
	EPSSCache   EPSSCache
	// SCC pulls GCP Security Command Center threat findings. Nil disables the
	// feed (e.g. SCC_ORG_ID unset), so the worker/periodic aren't registered.
	SCC       SCCFetcher
	Correlate Correlator
	// ScanInterval schedules a periodic active scan. Zero (the default) means no
	// periodic scan is registered — active scanning then only runs when enqueued
	// explicitly. Set via SCAN_INTERVAL so scanning is never on by accident.
	ScanInterval time.Duration
	// ScanWorkerDisabled prevents the main worker from registering ANY nuclei-
	// executing worker — ScanWorker, ScanProfileWorker and ScanAssetWorker — and
	// therefore from consuming queueScan at all. Set to true when a dedicated
	// scanner pod handles scans; the main worker then owns all other queues and
	// every nuclei fan-out is isolated on the scanner.
	//
	// Profiles/DriftRunner stay wired on the worker even then: the flag, not a nil
	// dep, is what decides. A nil dep would also silently disable the pod's ability
	// to be the all-in-one worker, and cmd/graph/worker.go cannot express a typed
	// nil for these unexported interfaces anyway.
	ScanWorkerDisabled bool
	// SyncInterval overrides how often the reconciliation sweep runs. Zero uses
	// defaultSyncInterval (2h). Set via SYNC_INTERVAL env var.
	SyncInterval time.Duration
	// CorrelateInterval overrides the correlate cadence. Zero uses
	// defaultCorrelateInterval (30m). Set via CORRELATE_INTERVAL env var.
	CorrelateInterval time.Duration
	// EnrichInterval overrides the backstop sweep cadence. Zero uses
	// defaultEnrichInterval (15m). Set via
	// ENRICH_INTERVAL env var. Prompt enrichment happens ingest-time (sync worker)
	// and post-correlate; this sweep is a backstop only.
	EnrichInterval time.Duration
	// PostCorrelateEnrich enables post-correlate cache invalidation so that
	// findings on internet-exposed assets are re-scored after each topology sweep.
	// All three must be non-nil to activate; nil fields disable the feature.
	ExposedAssets          AssetExposer
	ExposedFindings        FindingsByResource
	EnrichCacheInvalidator EnrichCacheInvalidator
	// GraphContext supplies graph-derived inputs (IsExposed, PrivescBucket) for
	// the enrichment fingerprint. Nil disables graph context in fingerprint.
	GraphContext GraphContextProvider
	// LadybugSync rebuilds the Ladybug embedded graph after each correlate sweep.
	// Nil disables Ladybug sync. See ladybugSyncFn in worker.go.
	LadybugSync LadybugSyncer
	// TopologyBumper increments the topology version in sync_state after
	// each full correlate sweep. The Ladybug sync closure takes the signal-only
	// path when the version has not moved, so a failed bump defers that sweep's
	// topology to the next successful bump or a worker restart. Nil disables
	// version bumping.
	TopologyBumper TopologyBumper
	// Profiles drives scan-profile runs (target resolution, template selection,
	// lifecycle reconciliation). Nil disables ScanProfileWorker registration, and so
	// does ScanWorkerDisabled — a profile run fans nuclei out over its whole target
	// set, so it registers only where nuclei is allowed to run.
	Profiles profileRunner
	// ProfileScanner executes a scan over a resolved target set on behalf of a
	// profile run. Required when Profiles is non-nil; ignored otherwise.
	ProfileScanner profileScanner
	// DriftRunner drives drift-triggered single-asset scans (ScanAssetWorker).
	// Nil disables ScanAssetWorker registration, as does ScanWorkerDisabled (a drift
	// scan is a nuclei run). *scan.ProfileService satisfies it.
	DriftRunner assetDriftRunner
	// DriftAssets reads individual assets by ID for drift scan target resolution.
	// Required when DriftRunner is non-nil. *asset.Service satisfies it.
	DriftAssets singleAssetReader
	// CypherResolver resolves a profile's Cypher TargetQuery to scan targets.
	// Nil means a profile with a non-empty TargetQuery fails its run with an
	// explicit "not configured" error rather than silently scanning the wrong
	// (all-externals) target set — see ScanProfileWorker.Work. cmd/graph wires
	// this from the pod's local *graphstore.Service when one is available, or
	// from an explore.LadybugRPCRepo dialed at LADYBUG_RPC_URL otherwise.
	CypherResolver cypherTargetResolver
	// Intel drives domain squatting / phishing domain monitoring. Nil disables
	// DomainMonitorWorker registration.
	Intel *intel.Service
	// Notify dispatches outbound alerts (Slack). Nil disables finding-alert
	// dispatch in the enrich worker.
	Notify AlertDispatcher
	// SavedQueries runs scheduled Cypher detections. Nil disables the
	// SavedQueryWorker + its per-minute schedule tick.
	SavedQueries SavedQueryScheduler
	// ProfileSchedules fires scan profiles on their cron schedule. Nil disables
	// the ProfileScheduleWorker + its per-minute tick.
	ProfileSchedules ScheduledProfiles
	// Metrics instruments every job with a span + run/duration metric via a global
	// River middleware. Nil disables job instrumentation (spans/metrics off).
	Metrics *obs.Metrics
	// ImageVuln resolves container images to CVEs (internal/scanner/imagevuln).
	// Nil disables the ImageVulnWorker + its daily sweep — the default
	// until an ImageSource is configured (a live registry puller / mounted rootfs).
	ImageVuln ImageVulnScanner
	// BaseImageCatalogue is the replacement-base catalogue the base-image
	// root-cause findings propose from (imagevuln.LoadCatalogue). The zero value
	// proposes only the bases derived from the lifecycle table.
	BaseImageCatalogue imagevuln.Catalogue
	// Adjudicator runs the severity adjudication sweep.
	// Nil disables the AdjudicateWorker + its periodic tick — the default posture
	// until ADJUDICATOR_ENABLED wires a *belief.Adjudicator, because it spends LLM
	// budget. Requires Respond (context assembly) and Findings to be set.
	Adjudicator *belief.Adjudicator
	// DriftAnalysis runs the drift sweep and per-batch analysis. Nil, or a
	// service whose Enabled() is false, registers no worker and no periodic:
	// the default until DRIFT_ANALYSIS_ENABLED wires an analyst.
	DriftAnalysis *driftanalysis.Service
	// DiskScan wires the agentless VM disk scan: the plan and sweep workers and,
	// when this pod also runs nuclei (ScanWorkerDisabled false), the volume
	// worker. Nil leaves disk scanning off and unscheduled.
	DiskScan *DiskScanDeps
	// InventorySources are package-inventory sources applied after every
	// connector sync, beside the disk scan's own (see InventorySource).
	InventorySources []InventorySource
	// InventoryAdvisory is the advisory sources the inventory overlay judges
	// CVE-matchability against: the value the collectors were built with.
	InventoryAdvisory distro.Sources
	// CIAccessPending exposes the registered CIAccess correlate rule's unmatched
	// AWS role targets so the correlate worker can enqueue a
	// verify_ci_role job for each after every full sweep. Nil disables the
	// enqueue (e.g. the CIAccess rule isn't registered in this deployment).
	CIAccessPending PendingCIVerifier
	// LiveAWS makes real-time AWS API calls (IAM GetRole, …) using a connector's
	// stored credentials — shared with the MCP/chat live-read tools. Required for
	// VerifyCIRoleWorker; nil disables VerifyCIRoleWorker registration.
	LiveAWS liveRoleGetter
}

// NewClient builds the River client with both workers registered and the
// periodic reconciliation sweep scheduled.
func NewClient(pool *pgxpool.Pool, deps Deps) (*river.Client[pgx.Tx], error) {
	workers, rescueOnly := newWorkerRegistry(pool, deps)

	// Register the full periodic schedule, built from a deps-free config so the
	// isolated scanner client (NewScanClient) can register the IDENTICAL set. River
	// runs the periodic enqueuer only on the elected leader, and every queue-consuming
	// client is electable — so both electable clients must carry the schedule: with
	// it on only one, whenever the other won the election nothing would be
	// enqueued, silently darkening correlate/enrich/adjudicate/etc. until a
	// restart. Only the leader enqueues.
	periodic := buildPeriodicJobs(deps.periodicConfig())

	var middleware []rivertype.Middleware
	if deps.Metrics != nil {
		middleware = append(middleware, &obsMiddleware{m: deps.Metrics})
	}
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:            consumedQueues(rescueOnly),
		Workers:           workers,
		ErrorHandler:      jobErrorLogger{},
		PeriodicJobs:      periodic,
		Middleware:        middleware,
		ReindexerSchedule: reindexerSchedule,
		SoftStopTimeout:   workerSoftStopTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("NewClient: %w", err)
	}
	return client, nil
}

// newWorkerRegistry registers every worker this pod can really run and returns
// the registry plus the kinds it can NOT run (filled in as rescue-only). The
// split exists so the queue derivation and its guard test see exactly the same
// registration decisions the client does.
func newWorkerRegistry(pool *pgxpool.Pool, deps Deps) (*river.Workers, map[string]bool) {
	workers := river.NewWorkers()
	registerRealWorkers(workers, pool, deps)
	// Kinds this pod doesn't work (scan when ScanWorkerDisabled, nil-dep
	// conditionals) must still be known to its rescuer — see rescue.go. The set it
	// returns is also what decides which queues this pod consumes.
	return workers, addRescueOnlyWorkers(workers)
}

// registerRealWorkers adds every worker this pod can REALLY run, and nothing else.
// Split out from newWorkerRegistry so the queue guards can read the real registry
// before the rescue-only fill-in blurs the two together (see newPod in
// queue_registration_test.go).
//
// Returns the *ScanProfileWorker it registered (nil if profile fan-out is
// disabled on this pod) — a test seam, see addNucleiFanoutWorkers.
func registerRealWorkers(workers *river.Workers, pool *pgxpool.Pool, deps Deps) *ScanProfileWorker {
	river.AddWorker(workers, &SyncWorker{
		connectors: deps.Connectors, registry: deps.Registry, assets: deps.Assets,
		findings: deps.Findings, checks: deps.Checks, metrics: deps.Metrics,
		forget: deps.Forget, drift: deps.Drift, suppressions: suppressionCarrier(deps.Suppress),
		inventory: deps.inventoryOverlay(),
	})
	// baseSyncInterval mirrors buildPeriodicJobs' own SYNC_INTERVAL-or-default
	// fallback, so an operator override scales EnqueueWorker's backoff schedule
	// too, not just the periodic tick's own interval.
	baseSyncInterval := deps.SyncInterval
	if baseSyncInterval <= 0 {
		baseSyncInterval = defaultSyncInterval
	}
	river.AddWorker(workers, &EnqueueWorker{connectors: deps.Connectors, baseSyncInterval: baseSyncInterval})
	river.AddWorker(workers, &DiscoverAWSOrgsWorker{orgs: deps.Connectors})
	if !deps.ScanWorkerDisabled {
		river.AddWorker(workers, &ScanWorker{scans: deps.Scans})
	}
	// Stale-scan reaping is a worker-owned ticker (cmd/graph/worker.go), not a
	// River job — see the note in scan.go for why.
	river.AddWorker(workers, &EnrichWorker{
		enrich: deps.Enrich, findings: deps.Findings, suppress: deps.Suppress,
		cache: deps.EnrichCache, maxAge: deps.EnrichMaxAge,
		graph: deps.GraphContext, now: time.Now, notify: noticeDeliverer(deps.Notify),
		carriers: deps.AlertCarriers,
	})
	river.AddWorker(workers, &EnrichSweepWorker{findings: deps.Findings, alerts: alertStatePruner(deps.EnrichCache)})
	// metrics is not optional in practice: without it recordSweepPhase silently
	// no-ops and the sweep-effectiveness signal — the whole point of which is that
	// a sustained high scanned count with zero resolutions must be alertable
	// rather than buried in a log line — never reaches /metrics. Instrumentation
	// that is wired everywhere except its constructor is indistinguishable from no
	// instrumentation, which is the failure this metric exists to catch.
	river.AddWorker(workers, &DanglingSweepWorker{findings: deps.Findings, assets: deps.Assets, metrics: deps.Metrics})
	river.AddWorker(workers, &OptimizeAssetsWorker{assets: deps.Assets})
	river.AddWorker(workers, &RespondWorker{respond: deps.Respond})
	river.AddWorker(workers, &KEVWorker{fetcher: deps.KEVFetcher, findings: deps.Findings, additions: deps.KEVAdditions})
	depReaders := newDepartureReaders(deps)
	river.AddWorker(workers, &OSVWorker{querier: deps.OSV, assets: deps.Assets, findings: deps.Findings, pool: pool, departures: depReaders})
	river.AddWorker(workers, &VMVulnWorker{assets: deps.Assets, findings: deps.Findings, deletions: depReaders.deletions})
	river.AddWorker(workers, &BaseImageWorker{
		assets: deps.Assets, findings: deps.Findings,
		catalogue: deps.BaseImageCatalogue, metrics: deps.Metrics, deletions: depReaders.deletions,
	})
	river.AddWorker(workers, &MalFeedWorker{querier: deps.MalFeed, assets: deps.Assets, findings: deps.Findings, pool: pool})
	river.AddWorker(workers, &DistroAdvisoryWorker{fetcher: deps.DistroAdvisories, sources: deps.DistroAdvisorySources, assets: deps.Assets, findings: deps.Findings, departures: depReaders})
	river.AddWorker(workers, &CorrelateWorker{
		correlate:    deps.Correlate,
		assets:       deps.ExposedAssets,
		findings:     deps.ExposedFindings,
		enrichCache:  deps.EnrichCacheInvalidator,
		ladybug:      deps.LadybugSync,
		topoBumper:   deps.TopologyBumper,
		findingsList: deps.Findings,
		assetsByIDs:  deps.Assets,
		ciAccess:     deps.CIAccessPending,
		metrics:      deps.Metrics,
	})
	if deps.LiveAWS != nil && deps.Connectors != nil && deps.Assets != nil && deps.Findings != nil {
		river.AddWorker(workers, NewVerifyCIRoleWorker(deps.LiveAWS, deps.Connectors, deps.Assets, deps.Findings))
	}
	river.AddWorker(workers, &LadybugRebuildWorker{ladybug: deps.LadybugSync})
	// Always registered, like the dangling sweep: the periodic is unconditional.
	river.AddWorker(workers, &SuppressionExpiryWorker{
		suppressions: expiringSuppressions(deps.Suppress), notify: noticeDeliverer(deps.Notify),
	})
	if deps.FullPass != nil {
		// Gated on the same dep the reenrich lane is: a pod that must not drive a
		// corpus-wide re-enrichment must not consume the lane either, and
		// consumedQueues derives the lane from this registration.
		river.AddWorker(workers, &ReenrichWorker{findings: deps.Findings, cache: deps.FullPass})
	}
	if deps.SCC != nil {
		river.AddWorker(workers, &SCCWorker{
			fetcher: deps.SCC, findings: deps.Findings,
			gceResolver: newGCEIDResolver(deps.Assets), closer: deps.Findings,
		})
	}
	// Profile runs and drift scans FAN OUT NUCLEI (scanProfileConcurrency = 10, up
	// to 4h per run). They belong wherever the nuclei budget is, which is precisely
	// what ScanWorkerDisabled names — so they are registered on the same terms as
	// ScanWorker above and never on a pod that has disowned nuclei. The scanner pod
	// registers them instead (NewScanClient / addNucleiWorkers).
	var profileWorker *ScanProfileWorker
	if !deps.ScanWorkerDisabled {
		profileWorker = addNucleiFanoutWorkers(workers, nucleiFanout{
			profiles: deps.Profiles, drift: deps.DriftRunner, driftAssets: deps.DriftAssets,
			scanSvc: deps.ProfileScanner, finder: deps.Findings, cypherResolver: deps.CypherResolver,
		})
	}
	if deps.EPSSFetcher != nil && deps.EPSSCache != nil {
		river.AddWorker(workers, &EPSSWorker{fetcher: deps.EPSSFetcher, cache: deps.EPSSCache})
	}
	if deps.Intel != nil {
		river.AddWorker(workers, &DomainMonitorWorker{intel: deps.Intel})
	}
	if deps.SavedQueries != nil {
		river.AddWorker(workers, &SavedQueryWorker{queries: deps.SavedQueries})
	}
	if deps.ProfileSchedules != nil {
		river.AddWorker(workers, &ProfileScheduleWorker{profiles: deps.ProfileSchedules})
	}
	if deps.ImageVuln != nil {
		river.AddWorker(workers, &ImageVulnWorker{
			scanner: deps.ImageVuln, images: deps.Assets, assets: deps.Assets, findings: deps.Findings,
			cursor: newImageScanCursor(pool), // per-image scan cursor (image_scan_state)
			bases:  deps.Assets,
			edges:  deps.Assets,
		})
	}
	if deps.driftAnalysisOn() {
		river.AddWorker(workers, &DriftSweepWorker{svc: deps.DriftAnalysis, inserts: riverDriftInserter{}})
		river.AddWorker(workers, &DriftAnalyzeWorker{svc: deps.DriftAnalysis})
	}
	addDiskScanWorkers(workers, deps.DiskScan, deps.Assets, !deps.ScanWorkerDisabled)
	if deps.Adjudicator != nil {
		river.AddWorker(workers, &AdjudicateWorker{
			findings:     deps.Findings,
			assembler:    deps.Respond,
			publicAccess: assetPublicAccess{assets: deps.Assets},
			exposedEdge:  deps.Assets,
			adjudicator:  deps.Adjudicator,
			metrics:      deps.Metrics,
		})
	}
	return profileWorker
}

// nucleiFanout are the dependencies of the two workers that fan NUCLEI out over a
// resolved target set: ScanProfileWorker (a whole profile) and ScanAssetWorker (one
// drifted asset). Both pods that may execute nuclei — the all-in-one worker and the
// dedicated scanner — register them through this one function, so the registration
// decision cannot differ between them.
type nucleiFanout struct {
	profiles       profileRunner
	drift          assetDriftRunner
	driftAssets    singleAssetReader
	scanSvc        profileScanner
	finder         profileFindingRecorder
	cypherResolver cypherTargetResolver
}

// addNucleiFanoutWorkers registers the two nuclei-fanout workers and returns the
// *ScanProfileWorker it just registered (nil if deps.profiles was nil). The
// return value exists purely as a test seam: river.Workers keeps registered
// workers behind an unexported map, so without handing the constructed worker
// back there would be no way for a test to observe, on the real registration
// path, whether deps.cypherResolver actually reached it — see
// TestRegisterRealWorkers_PropagatesCypherResolver and
// TestRegisterScanWorkers_PropagatesCypherResolver in queue_registration_test.go.
func addNucleiFanoutWorkers(workers *river.Workers, deps nucleiFanout) *ScanProfileWorker {
	var profileWorker *ScanProfileWorker
	if deps.profiles != nil {
		profileWorker = &ScanProfileWorker{
			profiles:       deps.profiles,
			scanSvc:        deps.scanSvc,
			finder:         deps.finder,
			cypherResolver: deps.cypherResolver,
		}
		river.AddWorker(workers, profileWorker)
	}
	if deps.drift != nil && deps.driftAssets != nil {
		river.AddWorker(workers, &ScanAssetWorker{
			profiles: deps.drift,
			scanSvc:  deps.scanSvc,
			finder:   deps.finder,
			assets:   deps.driftAssets,
		})
	}
	return profileWorker
}

// NewScanClient builds the isolated scanner pod's River client: it registers
// every nuclei-executing worker (estate scan, profile runs, drift scans) and
// consumes only queueScan, keeping nuclei's resource spike contained on this
// pod and off the worker's own budget. queueScan gets ONE worker, so the three
// kinds share a single nuclei slot.
//
// The scanner is electable as River leader like any queue-consuming client,
// and the leader is the only pod that enqueues periodics — so it registers the
// SAME full periodic schedule (buildPeriodicJobs) as the worker. Otherwise a
// scanner-as-leader would enqueue nothing and darken every worker sweep. It
// still executes only scan jobs; the other periodics it enqueues run on the
// worker pod (which consumes those queues).
func NewScanClient(pool *pgxpool.Pool, deps ScanDeps, cfg PeriodicConfig) (*river.Client[pgx.Tx], error) {
	workers, rescueOnly := newScanWorkerRegistry(deps)
	// Same guard + middleware shape as NewClient (worker.go's client): a nil
	// Metrics leaves this pod's River client uninstrumented exactly as before,
	// rather than changing behavior for callers that don't pass one. Placed
	// before PeriodicJobs, not between it and ReindexerSchedule: that pair
	// stays textually adjacent on purpose —
	// TestEveryQueueConsumingClientDisablesTheReindexer's mutation fixture
	// matches the exact text "PeriodicJobs:      buildPeriodicJobs(cfg),\n\t\tReindexerSchedule: reindexerSchedule,\n"
	// here and requires it unbroken to cover THIS client. NewClient is not a
	// counter-example proving the adjacency unnecessary (even though
	// NewClient's own Middleware sits between the same two field NAMES): its
	// PeriodicJobs line reads `PeriodicJobs: periodic,` — different source
	// text — so it was never matched by, or covered by, this same fixture in
	// the first place, adjacent or not. The constraint is real for THIS
	// function's exact spelling; splitting this pair (even just to insert a
	// field alphabetically) would make the fixture's Old text fail to match
	// and silently stop this guard covering this client, the same class of
	// "a regex over the source text broke the moment the code reshuffled" gap
	// this file's other guards (see the AST-based ones in cmd/graph) exist to
	// avoid — a plain string match here is the deliberately cheaper exception.
	var middleware []rivertype.Middleware
	if deps.Metrics != nil {
		middleware = append(middleware, &obsMiddleware{m: deps.Metrics})
	}
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:            consumedQueues(rescueOnly), // one nuclei job at a time
		Workers:           workers,
		ErrorHandler:      jobErrorLogger{},
		Middleware:        middleware,
		PeriodicJobs:      buildPeriodicJobs(cfg),
		ReindexerSchedule: reindexerSchedule,
		SoftStopTimeout:   scannerSoftStopTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("NewScanClient: %w", err)
	}
	return client, nil
}
