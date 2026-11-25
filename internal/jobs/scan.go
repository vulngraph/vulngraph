package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// scanPeriodicJobs returns the periodic scan schedule for the given interval, or
// nothing when interval <= 0 — active scanning stays off unless an operator opts
// in. There is no RunOnStart: a scan is heavy and should wait for the first tick
// rather than fire on every worker restart.
func scanPeriodicJobs(interval time.Duration) []*river.PeriodicJob {
	if interval <= 0 {
		return nil
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(
			river.PeriodicInterval(interval),
			func() (river.JobArgs, *river.InsertOpts) { return ScanArgs{}, nil },
			nil,
		),
	}
}

// ScanArgs runs one active scan over the current external-facing asset set.
type ScanArgs struct{}

func (ScanArgs) Kind() string { return "scan" }

// InsertOpts keeps scans on the dedicated scan queue, unique while running, so
// scans never overlap (nuclei is resource-heavy). queueScan is consumed only by
// the scanner pod (or the main worker when no scanner pod is deployed). 3
// attempts, not River's 25: each is up to 4h of nuclei, and a retryable scan
// holds the uniqueness slot through days of backoff, skipping every tick.
func (ScanArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueScan, 3)
}

// scanner is the slice of the scan service the worker needs (narrow consumer
// interface so Work is unit-testable; *scan.Service satisfies it).
type scanner interface {
	RunScan(ctx context.Context) (scan.Run, []finding.Finding, error)
}

// Stale-run reaping (failing runs orphaned in 'running' by a dead worker) is NOT
// a River job — it runs as a worker-owned ticker in cmd/graph/worker.go. A River
// periodic job is deduplicated by kind, so one stuck reaper row on an unconsumed
// queue would block every future enqueue; a plain ticker has no such failure
// mode. The reap logic itself lives in scan.Service.ReapStaleRuns.

// Timeout overrides River's default 1-minute timeout. Nuclei can take up to an
// hour for a few thousand internet-facing targets; 4 hours gives headroom as
// the asset inventory grows.
func (ScanWorker) Timeout(_ *river.Job[ScanArgs]) time.Duration {
	return 4 * time.Hour
}

// ScanWorker runs an active scan and records its findings.
type ScanWorker struct {
	river.WorkerDefaults[ScanArgs]
	scans scanner
}

func (w *ScanWorker) Work(ctx context.Context, _ *river.Job[ScanArgs]) error {
	start := time.Now()
	run, found, err := w.scans.RunScan(ctx)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	enqueueEnrich(ctx, found)
	log.FromContext(ctx).Info().
		Str("scan_run", run.ID).Int("targets", run.TargetCount).Int("findings", run.FindingCount).
		Dur("elapsed", time.Since(start)).
		Msg("scan completed")
	return nil
}
