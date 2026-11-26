package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// The transaction publishes one complete observation. A failed chunk must not
// leave half a new absent set combined with half an old one.
func (r *PGRepo) ObserveDeletionCandidates(ctx context.Context, connectorID string, ids []string, at, confirmedBefore time.Time, limit int) ([]string, error) {
	if limit <= 0 || limit > 5000 {
		return nil, fmt.Errorf("ObserveDeletionCandidates: invalid limit")
	}
	// PostgreSQL timestamps have microsecond precision. Reject replayed sweeps,
	// including equal timestamps, even after an empty observation cleared all
	// candidates. Otherwise a replay with a different absent set can retain
	// rows from the previous observation and falsely confirm deletion.
	at = at.UTC().Truncate(time.Microsecond)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("ObserveDeletionCandidates: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := r.q.WithTx(tx)
	lastSync, err := q.LockDeletionObservation(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("ObserveDeletionCandidates: lock: %w", err)
	}
	if !at.After(lastSync) {
		return nil, fmt.Errorf("ObserveDeletionCandidates: stale sweep")
	}
	if err := q.SetDeletionObservation(ctx, sqlcgen.SetDeletionObservationParams{ConnectorID: connectorID, ObservedAt: at}); err != nil {
		return nil, fmt.Errorf("ObserveDeletionCandidates: watermark: %w", err)
	}
	if len(ids) == 0 {
		if err := q.ClearDeletionCandidates(ctx, connectorID); err != nil {
			return nil, fmt.Errorf("ObserveDeletionCandidates: clear: %w", err)
		}
	} else {
		const chunk = 5000
		for start := 0; start < len(ids); start += chunk {
			if err := q.ObserveDeletionCandidates(ctx, sqlcgen.ObserveDeletionCandidatesParams{
				ConnectorID: connectorID, AssetIds: ids[start:min(start+chunk, len(ids))], ObservedAt: at,
			}); err != nil {
				return nil, fmt.Errorf("ObserveDeletionCandidates: observe: %w", err)
			}
		}
		if err := q.ResetUnobservedDeletionCandidates(ctx, sqlcgen.ResetUnobservedDeletionCandidatesParams{
			ConnectorID: connectorID, ObservedAt: at,
		}); err != nil {
			return nil, fmt.Errorf("ObserveDeletionCandidates: reset: %w", err)
		}
	}
	confirmed, err := q.ConfirmedDeletionCandidates(ctx, sqlcgen.ConfirmedDeletionCandidatesParams{
		ConnectorID: connectorID, ObservedAt: at, ConfirmedBefore: confirmedBefore, BatchSize: int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("ObserveDeletionCandidates: confirmed: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("ObserveDeletionCandidates: commit: %w", err)
	}
	return confirmed, nil
}
