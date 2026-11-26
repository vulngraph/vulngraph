package jobs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/intel"
)

// allJobArgs lives in routing.go — it drives the real queue derivation, not just
// these tests. TestAllJobArgsMatchesDeclaredKinds below pins it to the Kind()
// literals actually declared in this package's source.

// kindsWithNoProducer are job kinds that nothing in the codebase enqueues.
//
// A worker with no producer is an expensive, easily repeated defect: the code
// exists, the queue is registered, the design doc is written, `river_job` has no
// rows, and the capability reads as shipped while it has never once run. This
// allowlist makes each remaining instance a deliberate, commented decision
// instead of a silence.
//
// Adding an entry requires stating WHY the fan-out is absent. Removing a worker
// entirely is usually the better answer.
var kindsWithNoProducer = map[string]string{}

// enqueueSites scans the non-test sources of this package for the places a job
// is actually handed to River — a client.Insert/InsertTx call, or a periodic
// factory returning the args value. It returns the set of args TYPE NAMES found.
//
// Reading source rather than asserting a hand-maintained list is the point: a
// hand-maintained list of "things we enqueue" is exactly the artefact that goes
// stale and lets a producer quietly disappear.
func enqueueSites(t *testing.T) map[string]bool {
	t.Helper()

	// Producers live outside this package too (the HTTP server triggers a sync,
	// the MCP seam triggers work), so the scan covers the whole module.
	root := moduleRoot(t)

	// The three shapes a producer takes:
	//   client.Insert(ctx, RefreshKEVArgs{}, …)      — direct insert
	//   return EnrichSweepArgs{}, &river.InsertOpts… — periodic factory
	//   river.InsertManyParams{Args: ScanAssetArgs{… — batch insert
	call := regexp.MustCompile(
		`(?:Insert(?:Tx|Many)?\([^)]*?|return\s+|Args:\s*)([A-Z][A-Za-z0-9]*Args)\{`)

	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Hidden dirs hold copies of the tree (.git, nested worktrees): a
			// producer found there would hide a missing one here.
			if name := d.Name(); name == "vendor" || name == "third_party" || name == "node_modules" ||
				(path != root && strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range call.FindAllStringSubmatch(string(src), -1) {
			found[m[1]] = true
		}
		return nil
	})
	require.NoError(t, err)
	return found
}

// moduleRoot walks up from the test's working directory to the directory holding
// go.mod, so the source scan covers the whole module regardless of where the
// test is run from.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqualf(t, dir, parent, "go.mod not found above %s", dir)
		dir = parent
	}
}

// argsTypeName is the Go type name behind a JobArgs value, used to join the
// source scan above to the typed list in allJobArgs.
func argsTypeName(args river.JobArgs) string {
	return reflect.TypeOf(args).Name()
}

// pod is one deployed River client: the queues it consumes and the kinds it can
// actually work. Both are taken from the SAME registration path the real client
// uses, so a test pod cannot describe a topology the binary would not build.
type pod struct {
	name     string
	queues   map[string]river.QueueConfig
	realKind map[string]bool
}

// newPod takes the registry BEFORE the rescue-only fill-in, so realKind is read
// off the actual river.Workers rather than inferred from rescueRegistrations.
//
// The two used to be the same source, which made the queue guards dependent on a
// third list: delete an entry from rescueRegistrations and the kind vanished from
// rescueOnly, so realKind said "yes, this pod works it" for a kind no pod had
// registered — and both queue guards stayed green while only
// TestAllJobKindsRescuable failed. Reading the registry makes each guard stand
// alone.
func newPod(name string, workers *river.Workers) pod {
	real := registeredKinds(workers)
	// addRescueOnlyWorkers mutates workers, so it must run after the snapshot — it
	// is also exactly what the client does next.
	rescueOnly := addRescueOnlyWorkers(workers)
	return pod{name: name, queues: consumedQueues(rescueOnly), realKind: real}
}

// registeredKinds reads the kinds a river.Workers holds. River exposes no accessor
// (river@v0.39.0 worker.go:143 — workersMap is unexported), and probing it with
// AddWorkerSafely would mutate the registry AND re-derive the answer from
// rescueRegistrations, which is the coupling this exists to break. Reflection over
// the map keys is read-only and needs no unsafe: map keys are readable on a
// read-only Value.
func registeredKinds(workers *river.Workers) map[string]bool {
	field := reflect.ValueOf(workers).Elem().FieldByName("workersMap")
	out := make(map[string]bool, field.Len())
	for _, k := range field.MapKeys() {
		out[k.String()] = true
	}
	return out
}

// The optional Deps are interfaces, and the registration decisions this file
// exercises only ask whether one is present — never call it. Embedding the
// interface is therefore the whole stub. One type per interface rather than one
// type embedding all of them: profileRunner and assetDriftRunner share method
// names, so a combined struct would satisfy neither.
type (
	stubImageVuln        struct{ ImageVulnScanner }
	stubSCC              struct{ SCCFetcher }
	stubEPSSFetcher      struct{ EPSSFetcher }
	stubEPSSCache        struct{ EPSSCache }
	stubSavedQueries     struct{ SavedQueryScheduler }
	stubFullPass         struct{ fullPassMarker }
	stubLiveAWS          struct{ liveRoleGetter }
	stubKEV              struct{ KEVFetcher }
	stubOSV              struct{ OSVQuerier }
	stubMalFeed          struct{ MalFeedQuerier }
	stubDistroAdvisories struct{ DistroAdvisoryFetcher }
)

// workerPod builds the main worker client's registration for a FULLY wired
// deployment — every optional dependency present. Optional deps gate a worker and
// its producer together (no SCC dep means no SCC worker AND no SCC periodic), so
// a partially-wired pod cannot exhibit the "consumes a kind it can't work"
// defect; the fully-wired one is where the property has to hold.
func workerPod(t *testing.T, scanDisabled bool) pod {
	t.Helper()
	deps := Deps{
		Connectors: &connector.Service{}, Assets: &asset.Service{}, Findings: &finding.Service{},
		Intel: &intel.Service{}, Adjudicator: &belief.Adjudicator{}, DriftAnalysis: enabledDriftService(),
		ImageVuln: stubImageVuln{}, SCC: stubSCC{},
		EPSSFetcher: stubEPSSFetcher{}, EPSSCache: stubEPSSCache{},
		SavedQueries: stubSavedQueries{},
		FullPass:     stubFullPass{}, LiveAWS: stubLiveAWS{},
		KEVFetcher: stubKEV{}, OSV: stubOSV{}, MalFeed: stubMalFeed{},
		DistroAdvisories: stubDistroAdvisories{}, DistroAdvisorySources: Feeds{ALAS: true, ELSA: true}.DistroAdvisorySources(),
		DiskScan:           &DiskScanDeps{},
		ScanWorkerDisabled: scanDisabled,
	}
	workers := river.NewWorkers()
	registerRealWorkers(workers, nil, deps)
	name := "worker"
	if scanDisabled {
		name = "worker(SCAN_WORKER_DISABLED)"
	}
	return newPod(name, workers)
}

// scannerPod builds the isolated scanner client's registration from the SAME
// function NewScanClient uses, so it cannot describe a scanner the binary would
// not build. The concrete deps are zero-valued: registration only asks whether one
// is present, never calls it.
func scannerPod(t *testing.T) pod {
	t.Helper()
	workers := river.NewWorkers()
	registerScanWorkers(workers, ScanDeps{
		DiskScan: &DiskScanDeps{},
	})
	return newPod("scanner", workers)
}

// splitTopology is how the platform is actually deployed: a worker pod with
// SCAN_WORKER_DISABLED plus a dedicated scanner pod. singleTopology is the
// all-in-one worker, still supported.
func splitTopology(t *testing.T) []pod  { return []pod{workerPod(t, true), scannerPod(t)} }
func singleTopology(t *testing.T) []pod { return []pod{workerPod(t, false)} }

// The hand-written allJobArgs list is load-bearing — it is what queueOfKind and
// therefore consumedQueues are built from. An omission would silently drop a kind
// out of the routing table AND out of every guard below, so pin it to the Kind()
// literals parsed straight out of this package's source.
func TestAllJobArgsMatchesDeclaredKinds(t *testing.T) {
	declared := kindLiteralsInPackage(t)
	listed := map[string]bool{}
	for _, args := range allJobArgs() {
		listed[args.Kind()] = true
	}
	for kind := range declared {
		require.Truef(t, listed[kind], "job kind %q declares Kind() but is missing from allJobArgs", kind)
	}
	for kind := range listed {
		require.Truef(t, declared[kind], "allJobArgs lists %q but no Kind() method declares it", kind)
	}
}

// A pod must never consume a queue carrying a kind it cannot work.
//
// River's producer fetches by QUEUE alone (river@v0.39.0 producer.go:758 passes
// only Queue to JobGetAvailable), so consuming a queue means racing every other
// consumer for every kind on it. Win a race for a kind you have no worker for and
// River resolves it to rescueOnlyWorker, which errors immediately and burns an
// attempt; at MaxAttempts 1 the job is simply discarded, and the pod that COULD
// have run it never sees it. Failing fast even makes the wrong pod likely to win.
//
// A union-of-all-queues check structurally cannot see any of that: it asks
// whether SOME client consumes the queue, which stays true while kinds on it are
// being lost.
func TestEachPodOnlyConsumesQueuesItCanWork(t *testing.T) {
	for _, topology := range map[string][]pod{"split": splitTopology(t), "single": singleTopology(t)} {
		for _, p := range topology {
			for kind, queue := range queueOfKind() {
				if _, consumed := p.queues[queue]; !consumed {
					continue
				}
				assert.Truef(t, p.realKind[kind],
					"pod %s consumes queue %q, which carries kind %q — but it has no real worker for it, "+
						"so it will lock those jobs and error them instead of leaving them for the pod that can",
					p.name, queue, kind)
			}
		}
	}
}

// The mirror property: every kind must be consumed SOMEWHERE in the deployed
// topology, or its jobs sit `available` forever and read as "queued" while
// nothing will ever run them.
func TestEveryKindIsConsumedBySomePod(t *testing.T) {
	for topoName, topology := range map[string][]pod{"split": splitTopology(t), "single": singleTopology(t)} {
		for kind, queue := range queueOfKind() {
			consumed := false
			for _, p := range topology {
				if _, ok := p.queues[queue]; ok && p.realKind[kind] {
					consumed = true
				}
			}
			assert.Truef(t, consumed,
				"topology %s: nothing consumes queue %q with a real worker for kind %q — its jobs strand",
				topoName, queue, kind)
		}
	}
}

// Every job must name a queue that something actually consumes. River's default
// queue is literally "default", and NewClient does NOT register it — so a job
// whose InsertOpts leaves Queue empty is inserted, sits `available` forever, and
// reads as "scheduled" while nothing runs it.
//
// This is not hypothetical: orphans of removed code paths can leave rows exactly
// like this — available on `default`, stranded indefinitely — and nothing
// prevents the next one.
func TestEveryJobRoutesToARegisteredQueue(t *testing.T) {
	queues := map[string]bool{}
	for _, p := range append(splitTopology(t), singleTopology(t)...) {
		for q := range p.queues {
			queues[q] = true
		}
	}
	for _, args := range allJobArgs() {
		t.Run(args.Kind(), func(t *testing.T) {
			withOpts, ok := args.(river.JobArgsWithInsertOpts)
			require.Truef(t, ok,
				"%s declares no InsertOpts, so it lands on River's unregistered `default` queue and never runs",
				args.Kind())

			q := withOpts.InsertOpts().Queue
			require.NotEmptyf(t, q,
				"%s has an empty Queue, so it lands on River's unregistered `default` queue and never runs",
				args.Kind())
			require.Truef(t, queues[q],
				"%s routes to queue %q, which no client consumes", args.Kind(), q)
		})
	}
}

// The Ladybug rebuild and the per-minute scheduler ticks must NOT ride the
// correlate queue. It has one worker by design and runs near saturation, which
// lets a standing backlog build and makes the graph noticeably stale, turning "every minute" into "whenever correlate drains".
func TestLatencySensitiveJobsAreOffTheCorrelateQueue(t *testing.T) {
	for _, args := range []river.JobArgs{
		LadybugRebuildArgs{},
		RunSavedQueriesArgs{},
	} {
		t.Run(args.Kind(), func(t *testing.T) {
			opts := args.(river.JobArgsWithInsertOpts).InsertOpts()
			require.Equal(t, queueGraph, opts.Queue)
			require.NotEqual(t, queueCorrelate, opts.Queue)
		})
	}
}

// Everything on the shared graph lane must be unique-gated, or one slow rebuild
// lets the per-minute ticks stack up behind it.
func TestGraphQueueJobsAreUniqueGated(t *testing.T) {
	for _, args := range []river.JobArgs{
		LadybugRebuildArgs{},
		RunSavedQueriesArgs{},
	} {
		t.Run(args.Kind(), func(t *testing.T) {
			opts := args.(river.JobArgsWithInsertOpts).InsertOpts()
			require.NotEmpty(t, opts.UniqueOpts.ByState,
				"%s shares the graph lane and must dedupe", args.Kind())
		})
	}
}

// The graph lane needs more than one worker: ladybug_rebuild runs for 2-4 minutes
// and the ticks it shares the lane with fire every minute.
func TestGraphQueueHasRoomForTicksBesideARebuild(t *testing.T) {
	require.GreaterOrEqual(t, graphWorkers, 2)
}

// Every job kind must have something that enqueues it, or be a documented,
// deliberate exception.
//
// A worker with no producer is the platform's most expensive recurring defect
// class — see kindsWithNoProducer. This test is the cheap standing check for
// it: otherwise the code compiles, the queue is registered, and `river_job`
// never sees a single row.
func TestEveryJobKindHasAProducer(t *testing.T) {
	sites := enqueueSites(t)
	for _, args := range allJobArgs() {
		t.Run(args.Kind(), func(t *testing.T) {
			typeName := argsTypeName(args)
			reason, allowed := kindsWithNoProducer[args.Kind()]

			if sites[typeName] {
				require.Falsef(t, allowed,
					"%s IS enqueued (%s) but is still listed in kindsWithNoProducer as %q — drop the entry",
					args.Kind(), typeName, reason)
				return
			}
			require.Truef(t, allowed,
				"nothing enqueues %s (%s): the worker is registered and the queue is consumed, "+
					"so it reads as shipped while it can never run. Add a producer, delete the "+
					"worker, or record it in kindsWithNoProducer with the reason.",
				args.Kind(), typeName)
		})
	}
}

// The allowlist must not name a kind that no longer exists — a stale entry
// silently exempts nothing and hides the next real gap.
func TestNoProducerAllowlistHasNoStaleEntries(t *testing.T) {
	known := map[string]bool{}
	for _, args := range allJobArgs() {
		known[args.Kind()] = true
	}
	for kind := range kindsWithNoProducer {
		require.Truef(t, known[kind], "kindsWithNoProducer names unknown kind %q", kind)
	}
}

// depsNotWiredOnTheWorker are jobs.Deps fields cmd/graph/worker.go deliberately
// leaves unset. Every other field must be assigned there.
//
// The per-pod queue guards above check a FULLY wired deployment, because a dep
// gates a worker and its producer together — so they cannot see a dep the binary
// simply forgot to pass. An unwired dependency can leave enqueued jobs with
// only rescueOnlyWorker, which discards them at MaxAttempts 1.
var depsNotWiredOnTheWorker = map[string]string{}

func TestWorkerWiresEveryJobsDep(t *testing.T) {
	path := filepath.Join(moduleRoot(t), "cmd", "graph", "worker.go")
	src, err := os.ReadFile(path)
	require.NoError(t, err)

	file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	require.NoError(t, err)

	assigned := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Deps" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok {
				assigned[key.Name] = true
			}
		}
		return true
	})
	require.NotEmpty(t, assigned, "no jobs.Deps literal found in %s", path)

	depsType := reflect.TypeOf(Deps{})
	for i := range depsType.NumField() {
		field := depsType.Field(i).Name
		reason, exempt := depsNotWiredOnTheWorker[field]
		if assigned[field] {
			require.Falsef(t, exempt,
				"worker.go DOES set Deps.%s but it is still listed in depsNotWiredOnTheWorker as %q — drop the entry",
				field, reason)
			continue
		}
		require.Truef(t, exempt,
			"cmd/graph/worker.go never sets Deps.%s, so everything gated on it is silently off: "+
				"its worker is never registered and its jobs are discarded as unworkable. "+
				"Wire it, delete it, or record it in depsNotWiredOnTheWorker with the reason.",
			field)
	}
}

// recordCallSitesAllowedWithoutCarryForward are the only files in the whole
// module permitted to call a finding recorder's Record directly instead of
// RecordObserved. Keyed by path relative to the module root, not by bare
// filename — internal/jobs and internal/app/scan both have a file named
// service.go/kev.go-shaped names, and a bare-filename key would silently
// exempt the wrong one.
//
// Record does a full-row rewrite with no carry-forward-enrichment
// protection — correct ONLY for a caller that already holds the finding's
// prior enrichment in hand and is deliberately overwriting it (a
// score-writer), never for a producer re-observing a check/feed/scan result
// from scratch. Every producer that called Record directly built its
// finding.Finding{} with enrichment fields at Go zero, so a routine
// re-observation of an existing finding clobbered its score/must_fix_class/
// enriched_at back to blank (see RecordObserved's carry-forward in
// internal/app/finding/service.go). This allowlist is what makes the next
// new feed worker — in ANY package, not just internal/jobs — fail this test
// instead of silently reintroducing the bug: a guard that scanned only
// internal/jobs would miss internal/app/scan's own two call sites
// (RunScan/ImportFindings).
var recordCallSitesAllowedWithoutCarryForward = map[string]string{}

// TestOnlyScoreWritersCallRecordDirectly pins the fix for the "any producer
// can silently clobber enrichment" defect class: every finding producer in
// the WHOLE MODULE must call RecordObserved (which carries forward prior
// enrichment), not Record, unless its file is named in
// recordCallSitesAllowedWithoutCarryForward with a stated reason.
//
// Matches specifically on "findings.Record(" (the receiver field every
// finding-recording dependency in this codebase is actually named —
// w.findings/s.findings, see jobs.Deps.Findings, scan.Service.findings,
// enrich.Service.findings, KEVWorker.findings) rather than a bare ".Record("
// — the latter would false-positive on every OTHER type's own unrelated
// Record method (internal/app/memory, internal/app/respond,
// internal/app/govern's audit/outcome recorders are not finding recorders
// at all).
func TestOnlyScoreWritersCallRecordDirectly(t *testing.T) {
	root := moduleRoot(t)
	call := regexp.MustCompile(`findings\.Record\(`)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			// Dot-dirs are skipped like the go tool does — .git, and nested
			// checkouts (e.g. git worktrees under dot-directories) that hold
			// whole copies of the module and would be misreported as module files.
			if name := d.Name(); name == "vendor" || name == "third_party" || name == "node_modules" ||
				(path != root && strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !call.MatchString(string(src)) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		require.NoError(t, relErr)
		reason, allowed := recordCallSitesAllowedWithoutCarryForward[rel]
		require.Truef(t, allowed,
			"%s calls a finding recorder's Record directly — this bypasses carry-forward-enrichment "+
				"and will clobber score/must_fix_class/enriched_at on any re-observation. Use "+
				"RecordObserved instead, or add %q to recordCallSitesAllowedWithoutCarryForward "+
				"with a reason if this really is a deliberate score-write", rel, rel)
		_ = reason
		return nil
	})
	require.NoError(t, err)
}

// Splitting a queue must not change how much work runs at once.
//
// Routing and parallelism are separate concerns, and only routing was ever the
// reason to give a kind its own lane. Dedicated lanes (image_scan, profile_scan,
// drift_scan) each defaulting to MaxWorkers 1 multiplied the worker pod's
// concurrent heavy-scan capacity, silently, from the single slot the shared
// `scan` queue gave. That is not a tuning nit: the worker pod runs close to its
// memory limit, and a long-running registry-pulling image sweep beside another
// heavy scan is more resident memory, not less.
func TestHeavyScanLanesAreSerial(t *testing.T) {
	lanes := heavyScanLanes()
	require.Len(t, lanes, 2, "disk reads on the scanner, content on the worker")
	for lane := range lanes {
		require.Equalf(t, 1, queueWorkerCounts[lane],
			"heavy-scan lane %q must run one job at a time", lane)
	}

	// The deployed topology: the worker consumes one heavy lane and the scanner
	// two (nuclei and disk reads), each lane serial. A third on the scanner, or a
	// second on the worker, is more resident memory the pods were not sized for.
	budget := map[string]int{"worker(SCAN_WORKER_DISABLED)": 1, "scanner": 1}
	for _, p := range splitTopology(t) {
		consumed := 0
		for q := range p.queues {
			if lanes[q] {
				consumed++
			}
		}
		require.LessOrEqualf(t, consumed, budget[p.name],
			"pod %s consumes %d heavy-scan lanes, over its budget of %d", p.name, consumed, budget[p.name])
	}
}

// Every consumed queue must declare its concurrency explicitly.
//
// consumedQueues falls back to one worker for an unlisted queue, which reads as a
// safe default and is exactly how new lanes can multiply the worker's capacity
// without anyone choosing a number. Listing every queue makes the choice
// visible in the diff that adds the lane.
func TestEveryQueueDeclaresItsConcurrency(t *testing.T) {
	for kind, queue := range queueOfKind() {
		if queue == "" {
			continue
		}
		_, ok := queueWorkerCounts[queue]
		require.Truef(t, ok,
			"queue %q (carrying %q) is not in queueWorkerCounts, so it silently gets one worker — "+
				"state the number, even when it is 1", queue, kind)
	}
}

// Disk volume reads belong to the isolated scanner when delegation is enabled.
func TestScanWorkerDisabledDelegatesDiskReads(t *testing.T) {
	kind := DiskScanVolumeArgs{}.Kind()
	require.False(t, workerPod(t, true).realKind[kind])
	require.True(t, scannerPod(t).realKind[kind])
	require.True(t, workerPod(t, false).realKind[kind])
	for _, p := range append(splitTopology(t), singleTopology(t)...) {
		for _, retired := range []string{"scan", "scan_profile", "scan_asset", "run_scheduled_profiles"} {
			require.False(t, p.realKind[retired], "retired kind %s registered by %s", retired, p.name)
		}
	}
}
