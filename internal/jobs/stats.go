package jobs

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// LogQueueStats queries River's job table and logs pending/running/scheduled
// counts per queue. Call from a periodic goroutine to detect backlog buildup.
// Best-effort — errors are silently swallowed so a flaky PG query never kills
// the worker process.
func LogQueueStats(ctx context.Context, pool *pgxpool.Pool) {
	rows, err := pool.Query(ctx, `
		SELECT queue, state, count(*) AS n
		FROM river_job
		WHERE state IN ('available', 'running', 'scheduled', 'retryable')
		GROUP BY queue, state
		ORDER BY queue, state
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	type qstat struct {
		Queue string `json:"queue"`
		State string `json:"state"`
		N     int    `json:"n"`
	}
	var stats []qstat
	for rows.Next() {
		var s qstat
		if err := rows.Scan(&s.Queue, &s.State, &s.N); err == nil {
			stats = append(stats, s)
		}
	}
	if err := rows.Err(); err != nil {
		// A mid-iteration error would otherwise silently under-report the very
		// backlog signal this function exists to surface — log it rather than
		// emit a partial count as if it were complete.
		log.FromContext(ctx).Warn().Err(err).Msg("river queue stats: row iteration error; counts may be partial")
	}
	if len(stats) == 0 {
		return
	}
	log.FromContext(ctx).Info().Any("queues", stats).Msg("river queue stats")
}
