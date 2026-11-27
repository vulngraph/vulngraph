package jobs

import (
	"time"

	"github.com/riverqueue/river"
)

// allJobArgs is every JobArgs type this package defines, and the single source
// of the kind → queue routing table used to decide which queues a client
// consumes (consumedQueues).
//
// It is a hand-written list, so TestAllJobArgsMatchesDeclaredKinds pins it
// against the Kind() literals parsed out of this package's source: an omission
// here would otherwise make every guard built on it pass vacuously, and the
// queue defects those guards exist to catch would ship unnoticed.
func allJobArgs() []river.JobArgs {
	return []river.JobArgs{
		AdjudicateArgs{},
		CorrelateArgs{},
		DanglingSweepArgs{},
		InventoryRetirementArgs{},
		DecideArgs{},
		DiscoverAWSOrgsArgs{},
		DiskScanPlanArgs{},
		DiskScanSweepArgs{},
		DiskScanVolumeArgs{},
		DomainMonitorArgs{},
		DriftAnalyzeArgs{},
		DriftSweepArgs{},
		EnqueueSyncsArgs{},
		EnrichArgs{},
		EnrichSweepArgs{},
		OptimizeAssetsArgs{},
		ReenrichAllArgs{},
		RefreshBaseImagesArgs{},
		RefreshDistroAdvisoriesArgs{},
		RefreshEPSSArgs{},
		RefreshImageVulnArgs{},
		RefreshKEVArgs{},
		RefreshMalFeedArgs{},
		RefreshOSVArgs{},
		RefreshSCCArgs{},
		RefreshVMVulnArgs{},
		RunSavedQueriesArgs{},
		SuppressionExpiryArgs{},
		SyncConnectorArgs{},
		VerifyCIRoleArgs{},
		LadybugRebuildArgs{},
	}
}

// queueOfKind maps every job kind to the queue its own InsertOpts routes it to.
// A kind that declares no queue maps to "" and is never registered anywhere —
// River's default queue is literally "default" and no client consumes it.
func queueOfKind() map[string]string {
	out := make(map[string]string, len(allJobArgs()))
	for _, args := range allJobArgs() {
		queue := ""
		if withOpts, ok := args.(river.JobArgsWithInsertOpts); ok {
			queue = withOpts.InsertOpts().Queue
		}
		out[args.Kind()] = queue
	}
	return out
}

// queueWorkerCounts is the per-queue concurrency. EVERY queue is listed, including
// the ones that take the default of 1, and TestEveryQueueDeclaresItsConcurrency
// enforces that.
//
// Relying on the absent-means-1 default here is how splitting a queue silently
// multiplies concurrency: routing and parallelism are separate concerns, and only
// routing was ever the reason to add a lane. The heavy-scan lanes are the case
// that matters — the worker pod is memory-bound, so one more concurrent
// long-running image sweep is a release blocker, not a tuning nit.
var queueWorkerCounts = map[string]int{
	queueSync:       syncWorkers,
	queueEnrich:     enrichWorkers,
	queueRespond:    respondWorkers,
	queueCorrelate:  correlateWorkers,
	queueDangling:   danglingWorkers,
	queueMaintain:   maintainWorkers,
	queueFeeds:      feedsWorkers,
	queueGraph:      graphWorkers,
	queueReenrich:   reenrichWorkers,
	queueAdjudicate: adjudicateWorkers,
	queueDrift:      driftWorkers,
	// The heavy-scan lanes, split by pod-affinity. One worker per lane, so a lane
	// runs at most one heavy scan at a time. See queueContentScan in client.go.
	queueContentScan: heavyScanWorkers,
	queueDiskScan:    diskScanWorkers,
}

// heavyScanKinds are the job kinds that do resource-heavy scanning:
// a registry pull-and-unpack or a VM disk read. Everything else on this platform is a
// database query with a timeout.
//
// The set is declared by KIND, and heavyScanLanes derives the queues from it, so
// giving one of them a new lane immediately shows up as a new heavy lane rather
// than as extra concurrency nobody chose.
var heavyScanKinds = map[string]bool{
	RefreshImageVulnArgs{}.Kind(): true,
	DiskScanVolumeArgs{}.Kind():   true,
}

// heavyScanLanes are the queues those kinds route to. A pod consumes more than one
// only in the all-in-one topology, where it is both the worker and the scanner; the
// deployed split topology gives each pod exactly one.
func heavyScanLanes() map[string]bool {
	out := map[string]bool{}
	for kind, queue := range queueOfKind() {
		if heavyScanKinds[kind] && queue != "" {
			out[queue] = true
		}
	}
	return out
}

// consumedQueues returns the queues a client may consume, derived from the kinds
// it registered a REAL worker for (everything not in rescueOnly).
//
// Deriving rather than hand-listing is the whole point. River's producer fetches
// by QUEUE and never by kind, so consuming a queue is a promise to work every
// kind routed there. A hand-maintained queue map cannot express that promise
// and has drifted from it before — a pod ended up stealing jobs on a shared
// queue that it had no worker for. Here a queue simply cannot be consumed
// unless a real worker for one of its kinds was registered on this client.
//
// A queue may still carry a kind this client cannot work when that kind's
// PRODUCER is gated by the same dependency as its worker — refresh_scc rides
// queueEnrich but is only ever enqueued when the SCC dep (and therefore the SCC
// worker) is wired. TestEachPodOnlyConsumesQueuesItCanWork checks the property
// against a fully-wired deployment, where that distinction disappears.
func consumedQueues(rescueOnly map[string]bool) map[string]river.QueueConfig {
	out := map[string]river.QueueConfig{}
	for kind, queue := range queueOfKind() {
		if queue == "" || rescueOnly[kind] {
			continue
		}
		out[queue] = queueConfig(queue)
	}
	return out
}

func queueConfig(queue string) river.QueueConfig {
	workers, ok := queueWorkerCounts[queue]
	if !ok {
		workers = 1
	}
	config := river.QueueConfig{MaxWorkers: workers}
	if queue == queueEnrich {
		// River's 100 ms default caps ten short-running workers at 100 jobs/s,
		// even when storage is idle. Refill sooner without increasing concurrent
		// jobs. The idle poll interval stays at River's one-second default.
		config.FetchCooldown = 10 * time.Millisecond
	}
	return config
}
