package enrichcache

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

func (r *PGRepo) GetSweepProgress(ctx context.Context) (SweepProgress, error) {
	row, err := r.q.GetEnrichmentSweepProgress(ctx)
	if err != nil {
		return SweepProgress{}, fmt.Errorf("GetSweepProgress: %w", err)
	}
	p := SweepProgress{Cursor: row.CursorValue, Revision: row.Revision}
	if row.PassBefore.Valid {
		p.Before = row.PassBefore.Time
	}
	return p, nil
}

func (r *PGRepo) AdvanceSweepProgress(ctx context.Context, revision int64, next SweepProgress) (bool, error) {
	n, err := r.q.AdvanceEnrichmentSweepProgress(ctx, sqlcgen.AdvanceEnrichmentSweepProgressParams{
		ExpectedRevision: revision,
		CursorValue:      next.Cursor,
		PassBefore:       pgtype.Timestamptz{Time: next.Before, Valid: !next.Before.IsZero()},
	})
	if err != nil {
		return false, fmt.Errorf("AdvanceSweepProgress: %w", err)
	}
	return n == 1, nil
}
