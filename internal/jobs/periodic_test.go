package jobs

import (
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/internal/app/intel"
)

// fullConfig is every periodic enabled — a fully-configured worker's shape.
func fullConfig() PeriodicConfig {
	return PeriodicConfig{
		KEV:              true,
		OSV:              true,
		MalFeed:          true,
		DistroAdvisories: true,
		EPSS:             true,
		SCC:              true,
		DomainMonitor:    true,
		SavedQueries:     true,
		Adjudicator:      true,
		DriftAnalysis:    true,
		DiskScan:         true,
		ImageVuln:        true,
	}
}

func TestBuildPeriodicJobs_Gating(t *testing.T) {
	// 7 always-on base jobs: sync, aws_org discovery, enrich, dangling, optimize,
	// suppression expiry, correlate. (Discovery calls AWS only for configured
	// aws_org connectors, so it is not an outbound feed.) The outbound feeds (kev, osv, osv malfeed, epss, domain monitor)
	// are toggles, so OFFLINE_MODE can switch every one of them off.
	const base = 7

	// Everything off, no scan interval → just the base schedule.
	require.Len(t, buildPeriodicJobs(PeriodicConfig{}), base,
		"minimal config schedules only the unconditional base jobs")

	// Full config → base + 11 feature periodics + 2 disk jobs.
	require.Len(t, buildPeriodicJobs(fullConfig()), base+11+2,
		"full config schedules base + every feature periodic")
}

// The disk scan switch schedules two jobs: the plan and the sweep.
func TestBuildPeriodicJobs_DiskScanAddsPlanAndSweep(t *testing.T) {
	baseCount := len(buildPeriodicJobs(PeriodicConfig{}))
	jobs := buildPeriodicJobs(PeriodicConfig{DiskScan: true})
	require.Len(t, jobs, baseCount+2)
	periodicByKind(t, jobs, "disk_scan_plan")
	periodicByKind(t, jobs, "disk_scan_sweep")
}

func TestBuildPeriodicJobs_EachToggleAddsOne(t *testing.T) {
	baseCount := len(buildPeriodicJobs(PeriodicConfig{}))
	toggles := []func(*PeriodicConfig){
		func(c *PeriodicConfig) { c.KEV = true },
		func(c *PeriodicConfig) { c.OSV = true },
		func(c *PeriodicConfig) { c.MalFeed = true },
		func(c *PeriodicConfig) { c.DistroAdvisories = true },
		func(c *PeriodicConfig) { c.EPSS = true },
		func(c *PeriodicConfig) { c.SCC = true },
		func(c *PeriodicConfig) { c.DomainMonitor = true },
		func(c *PeriodicConfig) { c.SavedQueries = true },
		func(c *PeriodicConfig) { c.Adjudicator = true },
		func(c *PeriodicConfig) { c.DriftAnalysis = true },
		func(c *PeriodicConfig) { c.ImageVuln = true },
	}
	for i, toggle := range toggles {
		cfg := PeriodicConfig{}
		toggle(&cfg)
		require.Lenf(t, buildPeriodicJobs(cfg), baseCount+1,
			"toggle %d should add exactly one periodic job", i)
	}
}

// TestDepsPeriodicConfig locks the worker's deps→config derivation: the feature
// bools reflect dep presence, so the scanner (which mirrors this from env in
// cmd/graph/scanner.go) schedules the same set. If a new feature periodic is added,
// update this mapping, the scanner literal, and the gating test above together.
func TestDepsPeriodicConfig(t *testing.T) {
	// Nothing wired → all feature periodics off, no intervals.
	require.Equal(t, PeriodicConfig{}, Deps{}.periodicConfig(),
		"empty deps → no feature periodics")

	// Intervals pass through unchanged.
	got := Deps{
		SyncInterval:      time.Hour,
		CorrelateInterval: 2 * time.Hour,
		EnrichInterval:    3 * time.Hour,
	}.periodicConfig()
	require.Equal(t, time.Hour, got.SyncInterval)
	require.Equal(t, 2*time.Hour, got.CorrelateInterval)
	require.Equal(t, 3*time.Hour, got.EnrichInterval)

	// The adjudicator gate: present → scheduled.
	require.False(t, Deps{}.periodicConfig().Adjudicator)
	require.True(t, Deps{Adjudicator: &belief.Adjudicator{}}.periodicConfig().Adjudicator)
	// The drift analysis gate: a nil or disabled service is not scheduled.
	require.False(t, Deps{}.periodicConfig().DriftAnalysis)
	require.False(t, Deps{DriftAnalysis: driftanalysis.New(nil, nil, nil)}.periodicConfig().DriftAnalysis)
	require.True(t, Deps{DriftAnalysis: enabledDriftService()}.periodicConfig().DriftAnalysis)

	// The outbound feeds: a nil dep (switched off in cmd/graph) unschedules each.
	require.True(t, Deps{KEVFetcher: stubKEV{}}.periodicConfig().KEV)
	require.True(t, Deps{OSV: stubOSV{}}.periodicConfig().OSV)
	require.True(t, Deps{MalFeed: stubMalFeed{}}.periodicConfig().MalFeed)
	require.False(t, Deps{DistroAdvisories: stubDistroAdvisories{}}.periodicConfig().DistroAdvisories,
		"a fetcher with no release to read schedules nothing")
	require.True(t, Deps{DistroAdvisories: stubDistroAdvisories{},
		DistroAdvisorySources: Feeds{ALAS: true}.DistroAdvisorySources()}.periodicConfig().DistroAdvisories)
}

// TestBuildPeriodicJobs_EPSSRunsOnStart guards the fix for the EPSS-dark bug:
// the refresh_epss periodic MUST fire on every worker boot.
//
// It was RunOnStart:false + a 24h interval. The worker restarts far more often
// than 24h (spot churn / deploys), so River re-armed the next run to now+24h on
// every boot and the interval never elapsed — the in-memory catalog stayed empty
// and EPSS contributed to ZERO findings. Unlike KEV/OSV/SCC, EPSS has no
// ingest-time refresh path, so this periodic is its only population trigger.
func TestBuildPeriodicJobs_EPSSRunsOnStart(t *testing.T) {
	args, opts, runOnStart := periodicByKind(t, buildPeriodicJobs(fullConfig()), "refresh_epss")
	require.NotNil(t, args, "EPSS refresh periodic must be scheduled when EPSS is enabled")
	require.True(t, runOnStart, "EPSS refresh must run on every worker boot, not only on the 24h interval")
	require.NotNil(t, opts, "EPSS refresh must set explicit insert opts")
	require.Equal(t, queueFeeds, opts.Queue, "EPSS refresh must land on a consumed queue")
	require.False(t, opts.ScheduledAt.IsZero(), "EPSS refresh must be offset past the boot thundering herd")
}

// TestBuildPeriodicJobs_IntelFeedsRunOnStart guards the fix for the KEV/OSV/SCC-dark
// bug — the same latent bug as EPSS. Each of these periodics was
// RunOnStart:false + a 24h interval, so on a worker that restarts more often than
// 24h (spot churn / deploys) River re-armed the next run to now+24h on every boot
// and the interval never elapsed. Symptoms of this failure:
//   - refresh_kev/osv/scc have ZERO rows in river_job (never fired);
//   - supply_chain (OSV) and gcp_scc findings stop being detected after one old window;
//   - few CVE-bearing findings carry known_exploited (KEV under-applied).
//
// OSV and SCC have NO ingest-time population path (grep: nothing enqueues their
// refresh outside the periodic); KEV's only other trigger is the OSV worker, which
// is itself gated behind OSV — so all three darkened. Each must now fire on every
// boot, land on a consumed queue, and carry a staggered boot offset.
func TestBuildPeriodicJobs_IntelFeedsRunOnStart(t *testing.T) {
	periodics := buildPeriodicJobs(fullConfig())
	cases := []struct {
		kind  string
		queue string
	}{
		{"refresh_kev", queueFeeds},
		{"refresh_osv", queueEnrich},
		{"refresh_scc", queueEnrich},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			args, opts, runOnStart := periodicByKind(t, periodics, tc.kind)
			require.NotNil(t, args, "%s periodic must be scheduled", tc.kind)
			require.True(t, runOnStart, "%s must run on every worker boot, not only on the 24h interval", tc.kind)
			require.NotNil(t, opts, "%s must set explicit insert opts", tc.kind)
			require.Equal(t, tc.queue, opts.Queue, "%s must land on a consumed queue", tc.kind)
			require.False(t, opts.ScheduledAt.IsZero(), "%s must be offset past the boot thundering herd", tc.kind)
		})
	}
}

// TestBuildPeriodicJobs_EnrichSweepRunsOnStart guards the fix for the
// enrich-sweep-dark bug — the same failure as EPSS / KEV-OSV-SCC above. With
// RunOnStart:false and a long ENRICH_INTERVAL (e.g. 24h), every worker restart
// re-armed the next run to now+interval and the interval never elapsed.
//
// Symptoms of this failure:
//   - river_job holds rows for every other periodic and ZERO for enrich_sweep;
//   - some findings are never enriched, including high/critical ones sitting at
//     score 0 in monitor;
//   - many carry enrichment older than the last deploy, so any change to scoring
//     cannot take effect on the standing corpus.
//
// This sweep is the ONLY trigger for the never-enriched backfill and for drift
// re-enrichment (grep: nothing else constructs EnrichSweepArgs). Ingest-time
// enqueueEnrich covers new findings only, which is exactly why the gap stayed
// invisible — freshness looked healthy while the backlog never drained.
func TestBuildPeriodicJobs_EnrichSweepRunsOnStart(t *testing.T) {
	periodics := buildPeriodicJobs(fullConfig())
	args, opts, runOnStart := periodicByKind(t, periodics, "enrich_sweep")
	require.NotNil(t, args, "enrich_sweep periodic must be scheduled")
	require.True(t, runOnStart,
		"enrich_sweep must run on every worker boot — a 24h interval never elapses on a pod that restarts more often")
	require.NotNil(t, opts, "enrich_sweep must set explicit insert opts")
	require.Equal(t, queueEnrich, opts.Queue, "enrich_sweep must land on a consumed queue")
	require.False(t, opts.ScheduledAt.IsZero(),
		"enrich_sweep must be offset past the boot thundering herd, not piled onto the sync wave")
}

// TestBuildPeriodicJobs_MalFeedRunsOnStart guards refresh_osv_malfeed against
// the exact same dark-periodic-job failure class as
// TestBuildPeriodicJobs_IntelFeedsRunOnStart above: it is the SOLE producer of
// the fast malicious-package detection path (see malFeedInterval's doc), so
// RunOnStart:false would leave it just as silently exposed to a worker that
// restarts more often than its interval.
func TestBuildPeriodicJobs_MalFeedRunsOnStart(t *testing.T) {
	args, opts, runOnStart := periodicByKind(t, buildPeriodicJobs(fullConfig()), "refresh_osv_malfeed")
	require.NotNil(t, args, "refresh_osv_malfeed periodic must be scheduled when the feed is enabled")
	require.True(t, runOnStart, "refresh_osv_malfeed must run on every worker boot, not only on the hourly interval")
	require.NotNil(t, opts, "refresh_osv_malfeed must set explicit insert opts")
	require.Equal(t, queueEnrich, opts.Queue, "refresh_osv_malfeed must land on a consumed queue")
	require.False(t, opts.ScheduledAt.IsZero(), "refresh_osv_malfeed must be offset past the boot thundering herd")
}

// periodicByKind finds the periodic whose constructor produces the given job kind
// and returns its args, insert opts, and RunOnStart flag. River keeps the
// constructor and options on unexported PeriodicJob fields with no accessor, so we
// read them reflectively — this is the only seam to assert a periodic's scheduling.
func periodicByKind(t *testing.T, periodics []*river.PeriodicJob, kind string) (river.JobArgs, *river.InsertOpts, bool) {
	t.Helper()
	for _, pj := range periodics {
		e := reflect.ValueOf(pj).Elem()
		ctor := *(*river.PeriodicJobConstructor)(unsafe.Pointer(e.FieldByName("constructorFunc").UnsafeAddr()))
		args, opts := ctor()
		if args.Kind() != kind {
			continue
		}
		runOnStart := false
		if jobOpts := *(**river.PeriodicJobOpts)(unsafe.Pointer(e.FieldByName("opts").UnsafeAddr())); jobOpts != nil {
			runOnStart = jobOpts.RunOnStart
		}
		return args, opts, runOnStart
	}
	return nil, nil, false
}

// TestBuildPeriodicJobs_OptimizeRunsOnStart guards optimize_assets against the
// same never-fires defect the tests above document (EPSS, KEV/OSV/SCC,
// enrich_sweep, malfeed). Its interval is optimizeInterval — 24h — against a
// spot-scheduled worker that restarts on deploys and evictions, so
// RunOnStart:false would make every tick a coin flip on whether the pod outlives
// its own schedule — and the job's whole purpose is the standing maintenance
// nobody watches, which is precisely the kind that can go dark unnoticed.
func TestBuildPeriodicJobs_OptimizeRunsOnStart(t *testing.T) {
	args, opts, runOnStart := periodicByKind(t, buildPeriodicJobs(PeriodicConfig{}), "optimize_assets")

	require.NotNil(t, args, "compaction must be scheduled unconditionally, not behind a feature toggle")
	require.True(t, runOnStart,
		"a 24h interval on a worker that restarts more often than that never elapses")
	require.NotNil(t, opts, "optimize must set explicit insert opts")
	require.Equal(t, queueMaintain, opts.Queue, "optimize must land on a consumed queue")
	require.False(t, opts.ScheduledAt.IsZero(),
		"a merge competing with the sync/correlate/rebuild boot storm is the worst possible timing")
}

// TestScannerSchedulesSameKindsAsWorker is the drift-lock that the comments in
// periodic.go and client.go refer to.
//
// Both the worker and the scanner are leader-electable and both register the full
// periodic schedule, but they derive its feature gates from different places: the
// worker from dep presence (Deps.periodicConfig), the scanner from env
// (PeriodicConfigFromEnv). Whichever one wins the election is the ONLY pod that
// enqueues anything.
//
// This matters because the heavy-scan lanes are split by pod-affinity, so
// "no pod consumes this queue" is reachable. Concretely: set
// IMAGE_SCAN_DISABLED=true on the worker alone and its ImageVuln dep is nil, so
// it registers no ImageVulnWorker and consumes no content_scan lane — while a
// scanner that still believed ImageVuln was on would enqueue a refresh_image_vuln
// every day onto a lane nobody works. It sits `available` forever and reads as
// queued.
//
// The property: for the same environment, the two derivations must schedule the
// same job KINDS. Reflection over the bool fields makes a new feature gate fail
// here until it is added to both sides and to this table.
func TestScannerSchedulesSameKindsAsWorker(t *testing.T) {
	// Each case is one environment plus the deps cmd/graph/worker.go builds FROM
	// that environment. Keep them in step: the whole point is that the two
	// derivations answer identically for the same env.
	cases := []struct {
		name string
		env  map[string]string
		deps Deps
	}{
		{
			name: "full: SCC + adjudicator on, image scanning on by default",
			env: map[string]string{
				"SCC_ORG_ID": "123", "ADJUDICATOR_ENABLED": "1",
				"SYNC_INTERVAL": "3h", "ENRICH_INTERVAL": "24h",
			},
			deps: withDefaultFeeds(Deps{
				SyncInterval: 3 * time.Hour, EnrichInterval: 24 * time.Hour,
				SCC: stubSCC{}, Adjudicator: &belief.Adjudicator{},
			}),
		},
		{
			name: "DRIFT_ANALYSIS_ENABLED: the drift sweep is scheduled on both pods",
			env:  map[string]string{"DRIFT_ANALYSIS_ENABLED": "true"},
			deps: withDefaultFeeds(Deps{DriftAnalysis: enabledDriftService()}),
		},
		{
			name: "DISK_SCAN_ENABLED: the plan and sweep are scheduled on both pods",
			env:  map[string]string{"DISK_SCAN_ENABLED": "true"},
			deps: withDefaultFeeds(Deps{DiskScan: &DiskScanDeps{}}),
		},
		{
			name: "bare: no SCC, no adjudicator",
			env:  map[string]string{},
			deps: withDefaultFeeds(Deps{}),
		},
		{
			// The failure mode named above, from the pod that has it disabled.
			name: "IMAGE_SCAN_DISABLED: the sweep must be off on BOTH pods",
			env:  map[string]string{"IMAGE_SCAN_DISABLED": "true"},
			deps: func() Deps { d := withDefaultFeeds(Deps{}); d.ImageVuln = nil; return d }(),
		},
		{
			// Every default-on outbound feed off at once; the image sweep goes with
			// OSV because every CVE match it makes is an OSV query.
			name: "OFFLINE_MODE: no outbound feed is scheduled on either pod",
			env:  map[string]string{"OFFLINE_MODE": "true", "SCC_ORG_ID": "123"},
			deps: Deps{
				SCC: stubSCC{}, SavedQueries: stubSavedQueries{},
			},
		},
		{
			name: "per-feed switches: KEV and EPSS off, the rest on",
			env:  map[string]string{"INTEL_KEV_DISABLED": "true", "INTEL_EPSS_DISABLED": "true"},
			deps: func() Deps {
				d := withDefaultFeeds(Deps{})
				d.KEVFetcher, d.EPSSFetcher, d.EPSSCache = nil, nil, nil
				return d
			}(),
		},
		{
			name: "INTEL_OSV_DISABLED takes the image sweep with it; malfeed and CT unaffected",
			env:  map[string]string{"INTEL_OSV_DISABLED": "true", "DOMAIN_MONITOR_DISABLED": "true"},
			deps: func() Deps {
				d := withDefaultFeeds(Deps{})
				d.OSV, d.ImageVuln, d.Intel = nil, nil, nil
				return d
			}(),
		},
		{
			name: "one distro feed off keeps the refresh; both off drop it",
			env:  map[string]string{"INTEL_ALAS_DISABLED": "true"},
			deps: func() Deps {
				d := withDefaultFeeds(Deps{})
				d.DistroAdvisorySources = Feeds{ELSA: true}.DistroAdvisorySources()
				return d
			}(),
		},
		{
			name: "INTEL_ALAS_DISABLED and INTEL_ELSA_DISABLED",
			env:  map[string]string{"INTEL_ALAS_DISABLED": "true", "INTEL_ELSA_DISABLED": "true"},
			deps: func() Deps {
				d := withDefaultFeeds(Deps{})
				d.DistroAdvisories, d.DistroAdvisorySources = nil, nil
				return d
			}(),
		},
		{
			name: "INTEL_MALFEED_DISABLED alone",
			env:  map[string]string{"INTEL_MALFEED_DISABLED": "true"},
			deps: func() Deps { d := withDefaultFeeds(Deps{}); d.MalFeed = nil; return d }(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			fromEnv, err := PeriodicConfigFromEnv(getenv)
			require.NoError(t, err)
			fromDeps := tc.deps.periodicConfig()

			require.Equal(t, fromDeps, fromEnv,
				"the scanner's env derivation and the worker's dep derivation disagree; "+
					"whichever pod wins the leader election decides what gets enqueued")
			require.Equal(t, scheduledKinds(t, fromDeps), scheduledKinds(t, fromEnv))
		})
	}

	// Every bool gate must be exercised by at least one case in BOTH states, or a
	// new feature could be added to one derivation and pinned by none.
	seen := map[string][2]bool{}
	for _, tc := range cases {
		fromEnv, err := PeriodicConfigFromEnv(func(k string) string { return tc.env[k] })
		require.NoError(t, err)
		cfg := reflect.ValueOf(fromEnv)
		for i := range cfg.NumField() {
			field := cfg.Type().Field(i)
			if field.Type.Kind() != reflect.Bool {
				continue
			}
			both := seen[field.Name]
			if cfg.Field(i).Bool() {
				both[0] = true
			} else {
				both[1] = true
			}
			seen[field.Name] = both
		}
	}
	for name, both := range seen {
		if name == "SavedQueries" {
			// Unconditionally on in both derivations — there is no off state to cover.
			require.Truef(t, both[0], "%s is documented as always-on but no case has it on", name)
			continue
		}
		require.Truef(t, both[0] && both[1],
			"gate %s is never exercised in both states — add a case, or the two derivations "+
				"can disagree about it undetected", name)
	}
}

// withDefaultFeeds adds what cmd/graph/worker.go wires when no switch is set:
// the default-on outbound feeds plus the always-wired schedulers.
func withDefaultFeeds(d Deps) Deps {
	d.KEVFetcher, d.OSV, d.MalFeed = stubKEV{}, stubOSV{}, stubMalFeed{}
	d.DistroAdvisories = stubDistroAdvisories{}
	d.DistroAdvisorySources = Feeds{ALAS: true, ELSA: true}.DistroAdvisorySources()
	d.EPSSFetcher, d.EPSSCache = stubEPSSFetcher{}, stubEPSSCache{}
	d.Intel, d.ImageVuln = &intel.Service{}, stubImageVuln{}
	d.SavedQueries = stubSavedQueries{}
	return d
}

// scheduledKinds is the observable output of a PeriodicConfig: which job kinds the
// leader will enqueue.
func scheduledKinds(t *testing.T, cfg PeriodicConfig) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, kind := range allJobArgs() {
		if args, _, _ := periodicByKind(t, buildPeriodicJobs(cfg), kind.Kind()); args != nil {
			out[kind.Kind()] = true
		}
	}
	return out
}
