package llmusage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// PGRepo is the ledger on Postgres (llm_usage).
type PGRepo struct {
	q *sqlcgen.Queries
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool)} }

func (r *PGRepo) Insert(ctx context.Context, rec Record) error {
	err := r.q.InsertLLMUsage(ctx, sqlcgen.InsertLLMUsageParams{
		Purpose:          string(rec.Purpose),
		Interactive:      rec.Purpose.Interactive(),
		Provider:         rec.Provider,
		Model:            rec.Model,
		InputTokens:      rec.Usage.InputTokens,
		OutputTokens:     rec.Usage.OutputTokens,
		CacheReadTokens:  rec.Usage.CacheReadTokens,
		CacheWriteTokens: rec.Usage.CacheWriteTokens,
		UsageReported:    rec.Usage.Reported,
		Failed:           rec.Failed,
		CostMicroUsd:     rec.CostMicroUSD,
		UserID:           rec.UserID,
	})
	if err != nil {
		return fmt.Errorf("Insert: %w", err)
	}
	return nil
}

func (r *PGRepo) SpendSince(ctx context.Context, since time.Time) (Spend, error) {
	row, err := r.q.SumLLMSpendSince(ctx, since)
	if err != nil {
		return Spend{}, fmt.Errorf("SpendSince: %w", err)
	}
	return Spend{TotalMicroUSD: row.TotalMicroUsd, InteractiveMicroUSD: row.InteractiveMicroUsd}, nil
}

func (r *PGRepo) UserSpendSince(ctx context.Context, userID string, monthStart, dayStart time.Time) (UserSpend, error) {
	row, err := r.q.SumLLMUserSpend(ctx, sqlcgen.SumLLMUserSpendParams{
		UserID: userID, MonthStart: monthStart, DayStart: dayStart,
	})
	if err != nil {
		return UserSpend{}, fmt.Errorf("UserSpendSince: %w", err)
	}
	return UserSpend{MonthMicroUSD: row.MonthMicroUsd, DayMicroUSD: row.DayMicroUsd}, nil
}

func (r *PGRepo) Summarize(ctx context.Context, since, until time.Time) ([]Line, error) {
	rows, err := r.q.SummarizeLLMUsage(ctx, sqlcgen.SummarizeLLMUsageParams{Since: since, Until: until})
	if err != nil {
		return nil, fmt.Errorf("Summarize: %w", err)
	}
	out := make([]Line, len(rows))
	for i, row := range rows {
		out[i] = Line{
			Purpose:          Purpose(row.Purpose),
			Model:            row.Model,
			Interactive:      row.Interactive,
			Calls:            row.Calls,
			UnreportedCalls:  row.UnreportedCalls,
			FailedCalls:      row.FailedCalls,
			InputTokens:      row.InputTokens,
			OutputTokens:     row.OutputTokens,
			CacheReadTokens:  row.CacheReadTokens,
			CacheWriteTokens: row.CacheWriteTokens,
			CostMicroUSD:     row.CostMicroUsd,
		}
	}
	return out, nil
}
