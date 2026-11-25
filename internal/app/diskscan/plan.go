package diskscan

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// Tx is the storage transaction a repo hands to an EnqueueFunc. The jobs
// package asserts it to its own transaction type.
type Tx any

// EnqueueFunc runs inside the transaction that inserts a run row, so the
// run's volume jobs commit or roll back with it.
type EnqueueFunc func(ctx context.Context, tx Tx, run DiskScanRun) error

// runEnqueuer is the optional repo capability behind PlanRun.
type runEnqueuer interface {
	InsertRunEnqueue(ctx context.Context, run DiskScanRun, enqueue EnqueueFunc) (DiskScanRun, error)
}

// PlanRun opens a run like StartRun and calls enqueue inside the transaction
// that stores it. A connector whose mode is off yields a persisted not_enabled
// run and enqueue is not called: callers MUST check run.Status.
func (s *Service) PlanRun(ctx context.Context, connectorID string, enqueue EnqueueFunc) (DiskScanRun, error) {
	set, err := s.conns.DiskScanSettings(ctx, connectorID)
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("PlanRun: %w", err)
	}
	if !set.Mode.Enabled() {
		return s.StartRun(ctx, connectorID)
	}
	repo, ok := s.repo.(runEnqueuer)
	if !ok {
		return DiskScanRun{}, fmt.Errorf("PlanRun: repository cannot enqueue in the run's transaction: %w", ErrInvalid)
	}
	run, err := repo.InsertRunEnqueue(ctx, DiskScanRun{ConnectorID: connectorID, Status: StatusRunning, StartedAt: s.utcNow()}, enqueue)
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("PlanRun: %w", err)
	}
	return run, nil
}

// InsertRunEnqueue stores the run and calls enqueue in one transaction.
func (r *PGRepo) InsertRunEnqueue(ctx context.Context, run DiskScanRun, enqueue EnqueueFunc) (DiskScanRun, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("InsertRunEnqueue: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	row, err := r.q.WithTx(tx).InsertDiskScanRun(ctx, sqlcgen.InsertDiskScanRunParams{
		ConnectorID: run.ConnectorID, Status: string(run.Status), StartedAt: run.StartedAt,
		FinishedAt: tsOrNull(run.FinishedAt), Err: run.Err,
	})
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("InsertRunEnqueue: %w", err)
	}
	stored := runFromRow(row)
	if err := enqueue(ctx, tx, stored); err != nil {
		return DiskScanRun{}, fmt.Errorf("InsertRunEnqueue: enqueue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return DiskScanRun{}, fmt.Errorf("InsertRunEnqueue: commit: %w", err)
	}
	return stored, nil
}

// Stale reports whether a run opened before cutoff is still running.
func (r DiskScanRun) Stale(cutoff time.Time) bool {
	return r.Status == StatusRunning && r.StartedAt.Before(cutoff)
}
