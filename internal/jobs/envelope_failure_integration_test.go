//go:build integration

package jobs

import (
	"context"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/db"
)

// A deterministic capacity refusal cannot improve by retrying the same full
// inventory for an hour. Preserve the refusal and stored population, then fail
// this cohort without changing the production breaker or its retry policy.
func envelopeCheckCorrelationLimit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ch *db.CH, trace *envelopeTrace, report *envelopeReport) {
	t.Helper()
	var refused bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM river_job j, unnest(j.errors) e
		WHERE j.queue=$1 AND e->>'error' LIKE $2)`, queueCorrelate, "%"+correlate.ErrViewTruncated.Error()+"%").Scan(&refused))
	if !refused {
		return
	}
	message := "correlation refused its relevant population at the unchanged 600000-row breaker; cohort incomplete"
	report.Failures = append(report.Failures, message)
	counts := map[string]uint64{}
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var kind string
			var count uint64
			if err := rows.Scan(&kind, &count); err != nil {
				return err
			}
			counts[kind] = count
		}
		return rows.Err()
	}, "SELECT type,count() FROM assets FINAL GROUP BY type")
	trace.write(map[string]any{"event": "correlation_capacity_refusal", "message": message, "stored_current_rows_by_type": counts})
	require.NoError(t, err)
	t.Fatal(message)
}
