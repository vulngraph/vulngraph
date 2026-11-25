//go:build integration

package llmusage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/llm"
)

const pgDSN = "postgres://graph:graph@localhost:5432/graph?sslmode=disable"

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_LedgerRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	repo := NewPGRepo(pool)
	// "chat" is interactive; the tag keeps this test's rows apart from others'.
	tag := Purpose("it-" + time.Now().Format("150405.000000"))
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM llm_usage WHERE purpose = $1 OR model = $1", string(tag))
		require.NoError(t, err)
	})
	month := MonthStart(time.Now())
	before, err := repo.SpendSince(ctx, month)
	require.NoError(t, err)

	require.NoError(t, repo.Insert(ctx, Record{
		Purpose: tag, Provider: "anthropic", Model: "m",
		Usage:        llm.Usage{InputTokens: 10, OutputTokens: 20, CacheReadTokens: 30, CacheWriteTokens: 40, Reported: true},
		CostMicroUSD: 1_000,
	}))
	require.NoError(t, repo.Insert(ctx, Record{
		Purpose: tag, Provider: "anthropic", Model: "m",
		Usage:  llm.Usage{InputTokens: 1, OutputTokens: 8192},
		Failed: true, CostMicroUSD: 2_000,
	}))
	require.NoError(t, repo.Insert(ctx, Record{
		Purpose: PurposeChat, Provider: "openai", Model: string(tag),
		Usage: llm.Usage{OutputTokens: 1, Reported: true}, CostMicroUSD: 500,
	}))

	after, err := repo.SpendSince(ctx, month)
	require.NoError(t, err)
	require.EqualValues(t, 3_500, after.TotalMicroUSD-before.TotalMicroUSD)
	require.EqualValues(t, 500, after.InteractiveMicroUSD-before.InteractiveMicroUSD)

	lines, err := repo.Summarize(ctx, month, month.AddDate(0, 1, 0))
	require.NoError(t, err)
	var mine *Line
	for i := range lines {
		if lines[i].Purpose == tag {
			mine = &lines[i]
		}
	}
	require.NotNil(t, mine)
	require.Equal(t, Line{
		Purpose: tag, Model: "m", Calls: 2, UnreportedCalls: 1, FailedCalls: 1,
		InputTokens: 11, OutputTokens: 8212, CacheReadTokens: 30, CacheWriteTokens: 40, CostMicroUSD: 3_000,
	}, *mine)

	// The previous month holds none of it.
	prev, err := repo.Summarize(ctx, month.AddDate(0, -1, 0), month)
	require.NoError(t, err)
	for _, l := range prev {
		require.NotEqual(t, tag, l.Purpose)
	}
}

// The per-user check sums only that user's rows, month and day separately.
func TestPGRepo_UserSpend(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool)

	user := "it-user-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM llm_usage WHERE user_id = $1", user)
		require.NoError(t, err)
	})
	require.NoError(t, repo.Insert(ctx, Record{Purpose: PurposeChat, UserID: user, Provider: "p", Model: "m", CostMicroUSD: 700}))
	require.NoError(t, repo.Insert(ctx, Record{Purpose: PurposeChat, UserID: user, Provider: "p", Model: "m", CostMicroUSD: 300}))
	require.NoError(t, repo.Insert(ctx, Record{Purpose: PurposeChat, UserID: user + "-other", Provider: "p", Model: "m", CostMicroUSD: 9}))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM llm_usage WHERE user_id = $1", user+"-other") })
	_, err = pool.Exec(ctx, "UPDATE llm_usage SET ts = now() - interval '2 days' WHERE user_id = $1 AND cost_micro_usd = 300", user)
	require.NoError(t, err)

	now := time.Now()
	got, err := repo.UserSpendSince(ctx, user, now.AddDate(0, 0, -10), DayStart(now))
	require.NoError(t, err)
	require.Equal(t, UserSpend{MonthMicroUSD: 1000, DayMicroUSD: 700}, got)
}
