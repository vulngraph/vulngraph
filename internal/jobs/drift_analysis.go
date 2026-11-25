package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	// driftSweepInterval is how often connectors are checked for new drift.
	driftSweepInterval = 5 * time.Minute
	// driftAnalyzeTimeout covers one LLM call plus fact lookups.
	driftAnalyzeTimeout = 5 * time.Minute
)

// DriftSweepArgs is the periodic tick of the drift analysis: it cuts batches of
// new inventory changes, re-enqueues batches whose analysis was lost, and
// prunes old ones. Only registered when drift analysis is switched on
// (DRIFT_ANALYSIS_ENABLED). It never starts a scan.
type DriftSweepArgs struct{}

func (DriftSweepArgs) Kind() string { return "drift_sweep" }

func (DriftSweepArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueDrift, 2)
}

// DriftAnalyzeArgs analyses one batch. BatchID is the deterministic batch id,
// so the unique opts dedupe a re-enqueue of the same batch.
type DriftAnalyzeArgs struct {
	BatchID string `json:"batch_id"`
}

func (DriftAnalyzeArgs) Kind() string { return "drift_analyze" }

func (DriftAnalyzeArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       queueDrift,
		MaxAttempts: 2,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// driftAnalysisOn is the single gate for the drift workers and their periodic:
// a nil or disabled service registers neither.
func (deps Deps) driftAnalysisOn() bool {
	return deps.DriftAnalysis != nil && deps.DriftAnalysis.Enabled()
}

// driftAnalysisService is the slice of *driftanalysis.Service the workers use.
type driftAnalysisService interface {
	DiscoverBatches(ctx context.Context, enqueue driftanalysis.EnqueueFunc) ([]driftanalysis.Batch, error)
	Analyze(ctx context.Context, batchID string) error
	Requeue(ctx context.Context) ([]driftanalysis.Batch, error)
	Prune(ctx context.Context) (int64, error)
}

// driftInserter inserts analyse jobs, inside a transaction or on its own.
type driftInserter interface {
	insertTx(ctx context.Context, tx pgx.Tx, batchID string) error
	insert(ctx context.Context, batchID string) error
}

type riverDriftInserter struct{}

func (riverDriftInserter) insertTx(ctx context.Context, tx pgx.Tx, batchID string) error {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return fmt.Errorf("insertTx: %w", err)
	}
	if _, err := client.InsertTx(ctx, tx, DriftAnalyzeArgs{BatchID: batchID}, nil); err != nil {
		return fmt.Errorf("insertTx: %w", err)
	}
	return nil
}

func (riverDriftInserter) insert(ctx context.Context, batchID string) error {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	if _, err := client.Insert(ctx, DriftAnalyzeArgs{BatchID: batchID}, nil); err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	return nil
}

// DriftSweepWorker runs the periodic drift sweep.
type DriftSweepWorker struct {
	river.WorkerDefaults[DriftSweepArgs]
	svc     driftAnalysisService
	inserts driftInserter
}

func (w *DriftSweepWorker) Work(ctx context.Context, _ *river.Job[DriftSweepArgs]) error {
	logger := log.FromContext(ctx)

	// A failing connector must not stop re-enqueue and prune, so errors are
	// collected and returned last.
	var errs []error
	enqueue := func(ctx context.Context, tx driftanalysis.Tx, b driftanalysis.Batch) error {
		pgxTx, ok := tx.(pgx.Tx)
		if !ok {
			return fmt.Errorf("enqueue: transaction is %T, want pgx.Tx", tx)
		}
		return w.inserts.insertTx(ctx, pgxTx, b.ID)
	}
	created, err := w.svc.DiscoverBatches(ctx, enqueue)
	if err != nil {
		errs = append(errs, fmt.Errorf("Work: discover: %w", err))
	}

	requeued, err := w.svc.Requeue(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("Work: requeue: %w", err))
	}
	for _, b := range requeued {
		if err := w.inserts.insert(ctx, b.ID); err != nil {
			errs = append(errs, fmt.Errorf("Work: requeue %s: %w", b.ID, err))
		}
	}

	pruned, err := w.svc.Prune(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("Work: prune: %w", err))
	}

	logger.Info().Int("created", len(created)).Int("requeued", len(requeued)).
		Int64("pruned", pruned).Msg("drift sweep complete")
	return errors.Join(errs...)
}

// DriftAnalyzeWorker analyses one batch. The service is idempotent: an
// analysed, pruned or baseline batch returns nil.
type DriftAnalyzeWorker struct {
	river.WorkerDefaults[DriftAnalyzeArgs]
	svc driftAnalysisService
}

func (w *DriftAnalyzeWorker) Timeout(*river.Job[DriftAnalyzeArgs]) time.Duration {
	return driftAnalyzeTimeout
}

func (w *DriftAnalyzeWorker) Work(ctx context.Context, job *river.Job[DriftAnalyzeArgs]) error {
	if err := w.svc.Analyze(ctx, job.Args.BatchID); err != nil {
		return fmt.Errorf("Work: analyze %s: %w", job.Args.BatchID, err)
	}
	return nil
}
