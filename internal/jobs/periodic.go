package jobs

import (
	"fmt"
	"strings"
	"time"

	"github.com/riverqueue/river"
)

// PeriodicConfig is the deps-free description of the periodic schedule. Both the
// full worker client and the isolated scanner client build the SAME set from it
// (buildPeriodicJobs) so whichever pod River elects leader enqueues every periodic.
type PeriodicConfig struct {
	// SyncInterval is NOT consumed by buildPeriodicJobs (the EnqueueSyncsArgs
	// tick here always fires at enqueueCheckInterval, decoupled on purpose —
	// see that constant's doc). It exists on this struct only to keep the
	// env↔deps parity test honest; the real consumer is
	// EnqueueWorker.baseSyncInterval, wired in registerRealWorkers.
	SyncInterval      time.Duration // 0 → defaultSyncInterval, but see above
	CorrelateInterval time.Duration // 0 → defaultCorrelateInterval
	EnrichInterval    time.Duration // 0 → defaultEnrichInterval
	// Feature periodics. In the worker these mirror dep presence (see periodicConfig);
	// the scanner has no deps to read, so it derives them from env
	// (PeriodicConfigFromEnv). TestScannerSchedulesSameKindsAsWorker locks the two
	// derivations together so they can't drift.
	KEV              bool
	OSV              bool
	MalFeed          bool
	DistroAdvisories bool
	EPSS             bool
	SCC              bool
	DomainMonitor    bool
	SavedQueries     bool
	Adjudicator      bool
	DriftAnalysis    bool
	DiskScan         bool
	ImageVuln        bool
}

// PeriodicConfigFromEnv derives the schedule from the same environment
// cmd/graph/worker.go builds its deps from. It exists so the scanner pod cannot
// hand-maintain a second copy of the derivation.
//
// This matters because the heavy-scan lanes are split by pod-affinity: if the
// scanner-as-leader schedules a feed the worker has switched off, every job it
// enqueues sits `available` forever with no pod consuming that queue.
//
// The outbound intel feeds (KEV, OSV, MalFeed, EPSS, DomainMonitor) are on unless
// switched off — FeedsFromEnv is the one reader of those switches, shared with
// cmd/graph. The always-on entries are what the worker wires unconditionally;
// the rest key on exactly the variable the worker's dep constructor keys on. The env var
// names are duplicated from cmd/graph deliberately — this package must not import
// it — and the drift-lock test is what keeps the duplication honest.
//
// An unrecognised value in any on/off switch it reads is an error.
func PeriodicConfigFromEnv(getenv func(string) string) (PeriodicConfig, error) {
	set := func(key string) bool { return strings.TrimSpace(getenv(key)) != "" }
	feeds, err := FeedsFromEnv(getenv)
	if err != nil {
		return PeriodicConfig{}, fmt.Errorf("PeriodicConfigFromEnv: %w", err)
	}
	imageScanOff, err := SwitchFromEnv(getenv, ImageScanDisabledEnv)
	if err != nil {
		return PeriodicConfig{}, fmt.Errorf("PeriodicConfigFromEnv: %w", err)
	}
	adjudicator, err := SwitchFromEnv(getenv, AdjudicatorEnabledEnv)
	if err != nil {
		return PeriodicConfig{}, fmt.Errorf("PeriodicConfigFromEnv: %w", err)
	}
	driftAnalysis, err := SwitchFromEnv(getenv, DriftAnalysisEnabledEnv)
	if err != nil {
		return PeriodicConfig{}, fmt.Errorf("PeriodicConfigFromEnv: %w", err)
	}
	diskScan, err := SwitchFromEnv(getenv, DiskScanEnabledEnv)
	if err != nil {
		return PeriodicConfig{}, fmt.Errorf("PeriodicConfigFromEnv: %w", err)
	}
	return PeriodicConfig{
		SyncInterval:      envDuration(getenv, "SYNC_INTERVAL"),
		CorrelateInterval: envDuration(getenv, "CORRELATE_INTERVAL"),
		EnrichInterval:    envDuration(getenv, "ENRICH_INTERVAL"),
		KEV:               feeds.KEV,
		OSV:               feeds.OSV,
		MalFeed:           feeds.MalFeed,
		DistroAdvisories:  len(feeds.DistroAdvisorySources()) > 0,
		EPSS:              feeds.EPSS,
		SCC:               set("SCC_ORG_ID"),
		DomainMonitor:     feeds.DomainMonitor,
		SavedQueries:      true, // the worker always wires the saved-query scheduler
		Adjudicator:       adjudicator,
		DriftAnalysis:     driftAnalysis,
		DiskScan:          diskScan,
		// Mirrors imageVulnSource in worker.go: the registry-pull source is the
		// default, so the sweep is ON unless explicitly disabled. Every CVE match
		// goes to OSV, so the sweep is also off whenever the OSV feed is.
		ImageVuln: feeds.OSV && !imageScanOff,
	}, nil
}

// envDuration parses a duration env var, treating unset/unparseable as zero —
// which every interval field reads as "use the built-in default".
func envDuration(getenv func(string) string, key string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(getenv(key)))
	if err != nil {
		return 0
	}
	return d
}

// periodicConfig derives the schedule config from the worker's deps — the worker
// is the source of truth; the scanner mirrors it from env.
func (deps Deps) periodicConfig() PeriodicConfig {
	return PeriodicConfig{
		SyncInterval:      deps.SyncInterval,
		CorrelateInterval: deps.CorrelateInterval,
		EnrichInterval:    deps.EnrichInterval,
		KEV:               deps.KEVFetcher != nil,
		OSV:               deps.OSV != nil,
		MalFeed:           deps.MalFeed != nil,
		DistroAdvisories:  deps.DistroAdvisories != nil && len(deps.DistroAdvisorySources) > 0,
		EPSS:              deps.EPSSFetcher != nil && deps.EPSSCache != nil,
		SCC:               deps.SCC != nil,
		DomainMonitor:     deps.Intel != nil,
		SavedQueries:      deps.SavedQueries != nil,
		Adjudicator:       deps.Adjudicator != nil,
		DriftAnalysis:     deps.driftAnalysisOn(),
		DiskScan:          deps.DiskScan != nil,
		ImageVuln:         deps.ImageVuln != nil,
	}
}

// scheduledOn delays a periodic past the boot storm while keeping the args' OWN
// queue routing.
//
// Repeating the queue name here is not a safety net: River merges insert options
// with cmp.Or(insertOpts.Queue, jobInsertOpts.Queue, "default") (river@v0.39.0
// client.go:1693), so OMITTING Queue already falls back to the args' own queue.
// A second copy is a drift hazard instead: re-route a kind and the periodic keeps
// enqueueing onto the queue it left. Reading the queue off the args makes the two
// impossible to disagree, which is the reason this helper exists.
func scheduledOn(args river.JobArgs, delay time.Duration) *river.InsertOpts {
	opts := &river.InsertOpts{ScheduledAt: time.Now().Add(delay)}
	if withOpts, ok := args.(river.JobArgsWithInsertOpts); ok {
		opts.Queue = withOpts.InsertOpts().Queue
	}
	return opts
}

// periodicSingletonOpts is the InsertOpts shape for a kind the leader enqueues on
// a timer: at most one queued/running/retryable copy, and few attempts.
//
// Unique because every leader election re-runs RunOnStart and re-arms the
// schedule, so without it each election (deploy, spot churn, scanner restart)
// stacks another copy of a 45-minute sweep behind the last. Few attempts because
// uniqueStates includes retryable: under River's default 25 attempts a failing
// feed sits retryable for days of attempt^4 backoff while every periodic tick is
// skipped as a duplicate. The next tick is the retry.
func periodicSingletonOpts(queue string, maxAttempts int) river.InsertOpts {
	return river.InsertOpts{
		Queue:       queue,
		MaxAttempts: maxAttempts,
		UniqueOpts:  river.UniqueOpts{ByState: uniqueStates},
	}
}

// buildPeriodicJobs assembles the periodic schedule. It is the single source of
// the schedule, registered identically on the worker and scanner clients.
func buildPeriodicJobs(cfg PeriodicConfig) []*river.PeriodicJob {
	// cfg.SyncInterval itself is consumed elsewhere (EnqueueWorker.baseSyncInterval,
	// wired in registerRealWorkers) — this function's own sync-related periodic
	// job ticks at enqueueCheckInterval, deliberately decoupled from it.
	correlateEvery := cfg.CorrelateInterval
	if correlateEvery <= 0 {
		correlateEvery = defaultCorrelateInterval
	}
	enrichEvery := cfg.EnrichInterval
	if enrichEvery <= 0 {
		enrichEvery = defaultEnrichInterval
	}

	periodic := []*river.PeriodicJob{
		// RunOnStart: true — connector sync must kick off immediately at startup
		// so the first wave runs before the first backoff window expires.
		// Without this, a pod restart delays all sync by up to enqueueCheckInterval.
		//
		// Tick interval is enqueueCheckInterval (15m), NOT syncEvery — the actual
		// per-connector cadence is enforced inside EnqueueWorker.Work via
		// isDueForSync/backoffInterval (using syncEvery as the backoff's base),
		// not by this tick's own period. See enqueueCheckInterval's doc for why
		// the two must stay decoupled.
		river.NewPeriodicJob(
			river.PeriodicInterval(enqueueCheckInterval),
			func() (river.JobArgs, *river.InsertOpts) { return EnqueueSyncsArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true},
		),
		// RunOnStart: true — same failure class as KEV/OSV below: RunOnStart:false
		// plus an interval longer than the worker's restart cadence re-arms the next
		// run to now+interval on every boot, so the job can go indefinitely without
		// firing. The never-enriched backfill is this sweep's only trigger, and
		// ingest-time enqueueEnrich only covers genuinely new findings, so a dark
		// sweep here leaves the whole standing corpus stuck on stale scoring with
		// no visible symptom (freshness on new findings looks fine).
		//
		// Offset past the sync/correlate boot storm, same as KEV/OSV, so the
		// original "don't pile onto the sync wave" concern still holds.
		river.NewPeriodicJob(
			river.PeriodicInterval(enrichEvery),
			func() (river.JobArgs, *river.InsertOpts) {
				return EnrichSweepArgs{}, scheduledOn(EnrichSweepArgs{}, 8*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
		// RunOnStart: true — aws_org discovery is the only producer of org
		// child connectors, and an hourly interval on a worker that restarts
		// more often would never fire. Offset a minute so the first wave of
		// existing connectors' syncs is enqueued first.
		river.NewPeriodicJob(
			river.PeriodicInterval(awsOrgDiscoveryInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return DiscoverAWSOrgsArgs{}, scheduledOn(DiscoverAWSOrgsArgs{}, time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
		river.NewPeriodicJob(
			river.PeriodicInterval(5*time.Minute),
			func() (river.JobArgs, *river.InsertOpts) { return InventoryRetirementArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: false},
		),
		// RunOnStart: false — the dangling-finding resolve sweep is a
		// backstop, not a boot-critical path (the 365d TTL is the ultimate floor),
		// so keep it off the deploy-time thundering herd. Always-on (unlike the feeds):
		// registered identically on worker and scanner so whichever pod River elects
		// leader enqueues it; only the worker consumes queueDangling.
		river.NewPeriodicJob(
			river.PeriodicInterval(danglingInterval),
			func() (river.JobArgs, *river.InsertOpts) { return DanglingSweepArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: false},
		),
		// RunOnStart: true — ClickHouse compaction (optimize.go); same never-fires
		// risk as the other RunOnStart:false + long-interval periodics above on a
		// worker that restarts more often than the interval. Offset 22 minutes so
		// it lands after the sync, correlate, Ladybug-rebuild and feed-refresh boot
		// storm has drained — a merge competing with the first write wave is the
		// worst possible time for it.
		river.NewPeriodicJob(
			river.PeriodicInterval(optimizeInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return OptimizeAssetsArgs{}, scheduledOn(OptimizeAssetsArgs{}, 22*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
		// RunOnStart: true — a daily interval on a worker that restarts more often
		// never elapses (the KEV/OSV failure class). Safe to fire on every boot:
		// each expiry is announced once (expiry_notified_at), so a restart storm
		// sends nothing new. Offset 24 minutes, past the boot storm.
		river.NewPeriodicJob(
			river.PeriodicInterval(suppressionExpiryInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return SuppressionExpiryArgs{}, scheduledOn(SuppressionExpiryArgs{}, 24*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		),
		// RunOnStart: false — the boot sweep is EnqueueBootCorrelate, called by the
		// worker itself (the leader may be the scanner, whose boot must not add a
		// sweep). Unlike the 24h feeds above, a 30m interval cannot be starved by
		// restarts, and the worker's boot insert covers every worker restart. Both
		// share fullCorrelateOpts, so whichever lands second is a no-op: one
		// sweep per boot.
		river.NewPeriodicJob(
			river.PeriodicInterval(correlateEvery),
			func() (river.JobArgs, *river.InsertOpts) { return CorrelateArgs{}, fullCorrelateOpts() },
			&river.PeriodicJobOpts{RunOnStart: false},
		),
	}
	// The intel feeds are on by default; each has an opt-out (feeds.go).
	if cfg.KEV {
		// RunOnStart: true — KEV and OSV fire on every worker boot, offset past the
		// sync/correlate boot storm and staggered a couple minutes apart so they don't
		// hit the network in the same second. On a worker that restarts more often
		// than the interval, RunOnStart:false would re-arm the next run to now+interval
		// on every boot and the periodic would effectively never fire — neither has an
		// ingest-time trigger of its own to fall back on. Same failure class the
		// EPSS/domain-monitor periodics guard against below.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(kevInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return RefreshKEVArgs{}, scheduledOn(RefreshKEVArgs{}, 12*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		))
	}
	if cfg.OSV {
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(osvInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return RefreshOSVArgs{}, scheduledOn(RefreshOSVArgs{}, 16*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		))
	}
	if cfg.DistroAdvisories {
		// RunOnStart: true for the same reason as OSV — this periodic is the only
		// producer of Amazon Linux / Oracle Linux package findings. Offset past
		// OSV(16m) so the two package sweeps do not page the inventory together.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(distroAdvisoryInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return RefreshDistroAdvisoriesArgs{}, scheduledOn(RefreshDistroAdvisoriesArgs{}, 22*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		))
	}
	if cfg.MalFeed {
		// RunOnStart: true — the mal-feed job (osv_malfeed.go) is the sole producer
		// of the fast malicious-package detection path, so it gets the same
		// treatment as KEV/OSV above even though its hourly interval makes the
		// failure milder: a job whose whole purpose is fast detection shouldn't
		// accept any avoidable delay. Offset past
		// KEV(12m)/OSV(16m)/EPSS(10m)/SCC(14m)/ImageVuln(18m) so the boot storm has
		// drained before the bulk-feed download joins it.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(malFeedInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return RefreshMalFeedArgs{}, scheduledOn(RefreshMalFeedArgs{}, 20*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		))
	}
	// Stale-scan reaping runs as a worker-owned ticker (cmd/graph/worker.go), not
	// a River periodic — see the note in scan.go.
	if cfg.EPSS {
		// RunOnStart: true — EPSS is populated ONLY by this periodic and its catalog
		// lives in memory, lost on every restart, so it MUST re-fetch on boot: unlike
		// KEV/OSV/SCC (whose findings are durable in ClickHouse), a missed boot fetch
		// here leaves the in-memory catalog empty until the next interval elapses.
		// Fire on every boot, offset 10 min past the sync/correlate/Ladybug-rebuild boot
		// storm.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(epssInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return RefreshEPSSArgs{}, scheduledOn(RefreshEPSSArgs{}, 10*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		))
	}
	if cfg.SCC {
		// RunOnStart: true — SCC threat findings are org-scoped and pulled ONLY by
		// this periodic; there is no ingest path, so the same never-fires risk
		// applies as above. Fire on every boot, offset 14 min past the boot storm
		// and staggered from KEV/OSV/EPSS. SCC records onto the enrich queue.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(sccInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return RefreshSCCArgs{}, scheduledOn(RefreshSCCArgs{}, 14*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		))
	}
	if cfg.ImageVuln {
		// RunOnStart: true, offset 18 min past the boot storm and staggered from
		// KEV/OSV/EPSS/SCC. Like those feeds the sweep is the ONLY producer of its
		// findings (no ingest-time trigger), so RunOnStart:false on a sub-24h-
		// restarting worker would never fire. Records onto queueContentScan, which
		// only the worker pod — the pod with an ImageSource — consumes.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(imageVulnInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return RefreshImageVulnArgs{}, scheduledOn(RefreshImageVulnArgs{}, 18*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		))
	}
	if cfg.DomainMonitor {
		// Fire ~10min after boot (staggered past the sync/correlate boot storm, so
		// CT-log polling isn't part of the thundering herd) but on EVERY start.
		// RunOnStart:false + the 6h interval would never fire on a worker that
		// restarts more often than 6h (spot churn / frequent deploys), so domain
		// phishing tracking would silently never run.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(domainMonitorInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return DomainMonitorArgs{}, scheduledOn(DomainMonitorArgs{}, 10*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: true},
		))
	}
	if cfg.SavedQueries {
		// Per-minute tick: evaluate scheduled saved-query cron expressions and run
		// the ones due this minute. Light work (a few read-only Cypher queries).
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(time.Minute),
			func() (river.JobArgs, *river.InsertOpts) { return RunSavedQueriesArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: false},
		))
	}
	if cfg.Adjudicator {
		// RunOnStart: false + a boot offset — adjudication reads enriched findings,
		// so let the first enrich/correlate wave settle before the first sweep, and
		// keep it off the deploy-time thundering herd.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(adjudicateInterval),
			func() (river.JobArgs, *river.InsertOpts) {
				return AdjudicateArgs{}, scheduledOn(AdjudicateArgs{}, 15*time.Minute)
			},
			&river.PeriodicJobOpts{RunOnStart: false},
		))
	}
	if cfg.DriftAnalysis {
		// RunOnStart: false: discovery reads connector_asset_hashes, which the
		// first syncs after boot are still filling.
		periodic = append(periodic, river.NewPeriodicJob(
			river.PeriodicInterval(driftSweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return DriftSweepArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: false},
		))
	}
	if cfg.DiskScan {
		// The sweep ticks often so a leftover snapshot never outlives its TTL by
		// much; the plan is cheap when nothing is due (results are reused for a day).
		periodic = append(periodic,
			river.NewPeriodicJob(
				river.PeriodicInterval(diskScanPlanInterval),
				func() (river.JobArgs, *river.InsertOpts) {
					return DiskScanPlanArgs{}, scheduledOn(DiskScanPlanArgs{}, 10*time.Minute)
				},
				&river.PeriodicJobOpts{RunOnStart: false},
			),
			river.NewPeriodicJob(
				river.PeriodicInterval(diskScanSweepInterval),
				func() (river.JobArgs, *river.InsertOpts) { return DiskScanSweepArgs{}, nil },
				&river.PeriodicJobOpts{RunOnStart: false},
			),
		)
	}
	return periodic
}
