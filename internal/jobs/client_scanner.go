package jobs

// This file holds the isolated scanner pod's worker-registration wiring
// (ScanDeps, newScanWorkerRegistry, registerScanWorkers — the scanner-pod
// counterparts of registerRealWorkers/newWorkerRegistry in client.go) and the
// insert-only clients used by callers that only need to enqueue jobs, not run
// them: InsertClient (the HTTP server's on-demand-sync client) and Enqueuer
// (connector.Syncer's River-backed implementation). NewScanClient itself
// stays in client.go: TestEveryQueueConsumingClientDisablesTheReindexer and
// TestEveryElectableClientConfiguresSoftStopTimeout parse client.go's source
// text expecting to find both electable river.NewClient(...) calls — NewClient
// and NewScanClient — in that one file. Kept apart from client.go to stay
// under CLAUDE.md's 800-line ceiling.

import (
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/obs"
)

// ScanDeps are the isolated scanner pod's dependencies. Concrete types rather
// than interfaces because the interfaces the workers take are unexported
// (kept next to their consumer), and cmd/graph has to be able to fill this in.
type ScanDeps struct {
	// DiskScan runs the disk scan's volume jobs on this pod's own lane. Nil
	// leaves the lane unconsumed. This pod reads disks with the credentials a
	// plan sealed into the job and the narrow Postgres grants of
	// internal/migrate.scannerGrants — never the connectors themselves.
	DiskScan *DiskScanDeps
	// Metrics instruments every job with a span + run/duration metric via a
	// global River middleware, mirroring Deps.Metrics — nil disables job
	// instrumentation the same way.
	Metrics *obs.Metrics
}

// newScanWorkerRegistry registers the scanner pod's workers and returns the kinds
// it can NOT work, exactly as newWorkerRegistry does for the main worker — so the
// queue derivation and its guard test see the same decisions the binary makes.
func newScanWorkerRegistry(deps ScanDeps) (*river.Workers, map[string]bool) {
	workers := river.NewWorkers()
	registerScanWorkers(workers, deps)
	// The scanner's JobRescuer must know every job kind or it discards the main
	// worker's stuck jobs — see rescue.go. The rescue-only set it returns is also
	// what keeps this pod off every queue but queueDiskScan.
	return workers, addRescueOnlyWorkers(workers)
}

func registerScanWorkers(workers *river.Workers, deps ScanDeps) {
	addDiskScanVolumeWorker(workers, deps.DiskScan)
}
