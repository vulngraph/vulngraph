package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type SweepProgressStore interface {
	GetSweepProgress(context.Context) (enrichcache.SweepProgress, error)
	AdvanceSweepProgress(context.Context, int64, enrichcache.SweepProgress) (bool, error)
}

type enrichmentCandidateLister interface {
	EnrichmentCandidates(context.Context, finding.Filter) (finding.EnrichmentPage, error)
}

// Each execution keeps the existing admission budget. An incomplete pass yields
// its worker slot and resumes the same durable job, rather than waiting for the
// next ordinary tick. EOF ends the pass; scoring can still be pending and updates
// behind the cursor belong to a later pass. Whole-pass work can exceed one slice.
const enrichSweepContinuationDelay = 2 * time.Second

func (w *EnrichSweepWorker) driftPassActive(ctx context.Context) (bool, error) {
	if w.progress == nil {
		return false, nil
	}
	progress, err := w.progress.GetSweepProgress(ctx)
	if err != nil {
		return false, fmt.Errorf("driftPassActive: read progress: %w", err)
	}
	return !progress.Before.IsZero(), nil
}

func (w *EnrichSweepWorker) drainDrift(ctx context.Context, budget int) (int, error) {
	if w.progress == nil {
		// With no change-gate cache, scoring updates enriched_at on each visit.
		return w.drain(ctx, finding.Filter{StaleFirst: true}, budget, enrichSweepPriority)
	}
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return 0, fmt.Errorf("drainDrift: client: %w", err)
	}
	return w.drainDriftWith(ctx, client, budget)
}

func (w *EnrichSweepWorker) drainDriftWith(ctx context.Context, client enrichBatchInserter, budget int) (int, error) {
	pager, ok := w.findings.(enrichmentCandidateLister)
	if !ok {
		return 0, fmt.Errorf("drainDrift: original-key candidate pager is unavailable")
	}
	p, err := w.progress.GetSweepProgress(ctx)
	if err != nil {
		return 0, fmt.Errorf("drainDrift: read progress: %w", err)
	}
	advance := func(next enrichcache.SweepProgress) error {
		ok, err := w.progress.AdvanceSweepProgress(ctx, p.Revision, next)
		if err != nil {
			return fmt.Errorf("drainDrift: advance: %w", err)
		}
		if !ok {
			return fmt.Errorf("drainDrift: %w", enrichcache.ErrSweepProgressConflict)
		}
		next.Revision = p.Revision + 1
		p = next
		return nil
	}
	if p.Before.IsZero() {
		if err := advance(enrichcache.SweepProgress{Before: time.Now().UTC().Truncate(time.Millisecond)}); err != nil {
			return 0, err
		}
	}
	total := 0
	for total < budget {
		limit := min(enrichSweepLimit, budget-total)
		page, err := pager.EnrichmentCandidates(ctx, finding.Filter{StaleFirst: true, EnrichedBefore: p.Before, Cursor: p.Cursor, Limit: limit})
		if err != nil {
			return total, fmt.Errorf("drainDrift: list: %w", err)
		}
		if len(page.IDs) > limit || (len(page.IDs) > 0 && (page.Cursor == "" || page.Cursor == p.Cursor)) {
			return total, fmt.Errorf("drainDrift: invalid candidate page")
		}
		batch := make([]finding.Finding, len(page.IDs))
		for i, id := range page.IDs {
			batch[i].ID = id
		}
		if err := insertEnrichBatches(ctx, client, batch, enrichSweepPriority); err != nil {
			return total, fmt.Errorf("drainDrift: enqueue: %w", err)
		}
		total += len(batch)
		if len(batch) < limit {
			return total, advance(enrichcache.SweepProgress{})
		}
		next := p
		next.Cursor = page.Cursor
		if err := advance(next); err != nil {
			return total, err
		}
	}
	return total, nil
}
