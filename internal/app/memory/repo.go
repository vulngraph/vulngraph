package memory

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

type PGRepo struct {
	q *sqlcgen.Queries
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool)} }

func (r *PGRepo) Record(ctx context.Context, o Outcome) error {
	err := r.q.RecordOutcome(ctx, sqlcgen.RecordOutcomeParams{
		ActionClass: o.ActionClass,
		AssetType:   o.AssetType,
		Environment: o.Environment,
		Success:     o.Success,
		DecidedBy:   o.DecidedBy,
		OccurredAt:  o.OccurredAt,
		DedupeKey:   pgtype.Text{String: o.DedupeKey, Valid: o.DedupeKey != ""},
	})
	if err != nil {
		return fmt.Errorf("Record: %w", err)
	}
	return nil
}

func (r *PGRepo) Recent(ctx context.Context, actionClass, assetType string, limit int) ([]Outcome, error) {
	rows, err := r.q.RecentOutcomes(ctx, sqlcgen.RecentOutcomesParams{
		ActionClass: actionClass,
		AssetType:   assetType,
		Limit:       int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("Recent: %w", err)
	}
	return toOutcomes(rows), nil
}

func (r *PGRepo) RecentByAsset(ctx context.Context, assetType string, limit int) ([]Outcome, error) {
	rows, err := r.q.RecentOutcomesByAsset(ctx, sqlcgen.RecentOutcomesByAssetParams{
		AssetType: assetType,
		Limit:     int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("RecentByAsset: %w", err)
	}
	return toOutcomes(rows), nil
}

// toOutcomes converts sqlc rows to domain outcomes. Both recent queries return
// the same row shape, so they share this converter.
func toOutcomes(rows []sqlcgen.ActionOutcome) []Outcome {
	out := make([]Outcome, len(rows))
	for i, row := range rows {
		out[i] = Outcome{
			ActionClass: row.ActionClass,
			AssetType:   row.AssetType,
			Environment: row.Environment,
			Success:     row.Success,
			DecidedBy:   row.DecidedBy,
			OccurredAt:  row.OccurredAt,
			DedupeKey:   row.DedupeKey.String,
		}
	}
	return out
}
