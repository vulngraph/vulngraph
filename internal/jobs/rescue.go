package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
)

// rescueOnlyWorker teaches a client about a job kind whose queue it never
// consumes. River's leader-elected JobRescuer permanently DISCARDS any stuck
// job whose kind is missing from the leader's worker registry, and every
// queue-consuming client is electable — so a pod that doesn't know a kind can
// silently destroy another pod's jobs. Work is unreachable because this
// client doesn't consume the kind's queue; the error is a tripwire in case
// that ever changes.
//
// It embeds the kind's REAL worker (a zero value — only its Timeout and
// NextRetry are ever called) so the rescuer applies that worker's Timeout. The
// rescuer leaves a running job alone while it is younger than its kind's
// Timeout, and a zero Timeout (WorkerDefaults) means "stuck at
// RescueStuckJobsAfter", 1h. Without this, a worker-pod leader would declare a
// 4h nuclei scan running on the scanner pod stuck after 1h: `scan` would be
// retried from scratch (up to 25 attempts, its completion dropped) and
// `scan_profile` (MaxAttempts 1) discarded mid-run, freeing its uniqueness slot.
type rescueOnlyWorker[T river.JobArgs] struct {
	river.Worker[T]
}

func (rescueOnlyWorker[T]) Work(_ context.Context, job *river.Job[T]) error {
	return fmt.Errorf("rescueOnlyWorker: job kind %q is not workable on this pod", job.Args.Kind())
}

// rescueRegistration is one kind's rescue-only fill-in. timeout is what the
// registered worker reports to the rescuer, kept so a test can pin it.
type rescueRegistration struct {
	register func(*river.Workers) error
	timeout  time.Duration
}

// rescueEntry derives the kind string from the args type itself so a key can
// never point at the wrong worker; river.Worker[T] pins the real worker to the
// same args type.
func rescueEntry[T river.JobArgs](real river.Worker[T]) func() (string, rescueRegistration) {
	return func() (string, rescueRegistration) {
		var args T
		w := &rescueOnlyWorker[T]{Worker: real}
		return args.Kind(), rescueRegistration{
			register: func(workers *river.Workers) error { return river.AddWorkerSafely(workers, w) },
			timeout:  w.Timeout(&river.Job[T]{JobRow: &rivertype.JobRow{}}),
		}
	}
}

// rescueRegistrations covers every job kind the platform enqueues — one entry
// per Kind() method in this package. TestAllJobKindsRescuable locks the two
// sets together.
func rescueRegistrations() map[string]rescueRegistration {
	out := map[string]rescueRegistration{}
	for _, entry := range []func() (string, rescueRegistration){
		rescueEntry[SyncConnectorArgs](&SyncWorker{}),
		rescueEntry[EnqueueSyncsArgs](&EnqueueWorker{}),
		rescueEntry[ScanArgs](&ScanWorker{}),
		rescueEntry[EnrichArgs](&EnrichWorker{}),
		rescueEntry[EnrichSweepArgs](&EnrichSweepWorker{}),
		rescueEntry[DanglingSweepArgs](&DanglingSweepWorker{}),
		rescueEntry[DecideArgs](&RespondWorker{}),
		rescueEntry[RefreshKEVArgs](&KEVWorker{}),
		rescueEntry[RefreshOSVArgs](&OSVWorker{}),
		rescueEntry[RefreshVMVulnArgs](&VMVulnWorker{}),
		rescueEntry[RefreshBaseImagesArgs](&BaseImageWorker{}),
		rescueEntry[RefreshMalFeedArgs](&MalFeedWorker{}),
		rescueEntry[RefreshDistroAdvisoriesArgs](&DistroAdvisoryWorker{}),
		rescueEntry[RefreshEPSSArgs](&EPSSWorker{}),
		rescueEntry[RefreshSCCArgs](&SCCWorker{}),
		rescueEntry[CorrelateArgs](&CorrelateWorker{}),
		rescueEntry[LadybugRebuildArgs](&LadybugRebuildWorker{}),
		rescueEntry[ReenrichAllArgs](&ReenrichWorker{}),
		rescueEntry[ScanProfileJobArgs](&ScanProfileWorker{}),
		rescueEntry[ScanAssetArgs](&ScanAssetWorker{}),
		rescueEntry[DomainMonitorArgs](&DomainMonitorWorker{}),
		rescueEntry[RunSavedQueriesArgs](&SavedQueryWorker{}),
		rescueEntry[RunScheduledProfilesArgs](&ProfileScheduleWorker{}),
		rescueEntry[RefreshImageVulnArgs](&ImageVulnWorker{}),
		rescueEntry[AdjudicateArgs](&AdjudicateWorker{}),
		rescueEntry[DriftSweepArgs](&DriftSweepWorker{}),
		rescueEntry[DriftAnalyzeArgs](&DriftAnalyzeWorker{}),
		rescueEntry[VerifyCIRoleArgs](&VerifyCIRoleWorker{}),
		rescueEntry[OptimizeAssetsArgs](&OptimizeAssetsWorker{}),
		rescueEntry[SuppressionExpiryArgs](&SuppressionExpiryWorker{}),
		rescueEntry[DiscoverAWSOrgsArgs](&DiscoverAWSOrgsWorker{}),
		rescueEntry[DiskScanPlanArgs](&DiskScanPlanWorker{}),
		rescueEntry[DiskScanVolumeArgs](&DiskScanVolumeWorker{}),
		rescueEntry[DiskScanSweepArgs](&DiskScanSweepWorker{}),
	} {
		kind, reg := entry()
		out[kind] = reg
	}
	return out
}

// addRescueOnlyWorkers fills workers with rescue-only registrations for every
// job kind not already registered for real. AddWorkerSafely errors only on a
// duplicate kind, which is exactly the skip we want.
//
// It returns the kinds it actually filled in — i.e. the kinds this client CANNOT
// work. That set is the complement of the client's real registrations, so it is
// what consumedQueues derives the consumed queue set from: no second, hand-kept
// list of "what this pod can do" to drift out of sync with the AddWorker calls.
func addRescueOnlyWorkers(workers *river.Workers) map[string]bool {
	rescueOnly := map[string]bool{}
	for kind, reg := range rescueRegistrations() {
		if err := reg.register(workers); err == nil {
			rescueOnly[kind] = true
		}
	}
	return rescueOnly
}
