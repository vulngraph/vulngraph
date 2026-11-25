package costdata

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PGRepo implements Repository on Postgres using raw pgx queries.
// costdata is too thin to warrant sqlcgen scaffolding; direct pgx is fine.
type PGRepo struct {
	pool *pgxpool.Pool
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{pool: pool} }

// SaveSnapshots upserts a batch of cost snapshots. Conflicts on
// (connector_id, service, period_date) are overwritten so re-runs are idempotent.
func (r *PGRepo) SaveSnapshots(ctx context.Context, snaps []CostSnapshot) error {
	if len(snaps) == 0 {
		return nil
	}
	const q = `
INSERT INTO cost_snapshots (connector_id, account_id, service, cost_usd, period_date)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (connector_id, service, period_date)
DO UPDATE SET cost_usd = EXCLUDED.cost_usd, account_id = EXCLUDED.account_id, collected_at = now()`

	for _, s := range snaps {
		if _, err := r.pool.Exec(ctx, q,
			s.ConnectorID, s.AccountID, s.Service, s.CostUSD, s.PeriodDate,
		); err != nil {
			return fmt.Errorf("SaveSnapshots: %w", err)
		}
	}
	return nil
}

// SnapshotCounts returns, per connector, how many cost snapshots are stored and
// when the newest was collected. Cheap aggregate over a small table; it is the
// durable half of the "is cost collection working" answer, so the UI can say
// "never collected" instead of "no anomalies".
func (r *PGRepo) SnapshotCounts(ctx context.Context) (map[string]SnapshotCount, error) {
	const q = `
SELECT connector_id, count(*)::bigint, max(collected_at)
FROM cost_snapshots
GROUP BY connector_id`

	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("SnapshotCounts: %w", err)
	}
	defer rows.Close()

	out := map[string]SnapshotCount{}
	for rows.Next() {
		var (
			connectorID string
			n           int64
			last        *time.Time
		)
		if err := rows.Scan(&connectorID, &n, &last); err != nil {
			return nil, fmt.Errorf("SnapshotCounts: scan: %w", err)
		}
		c := SnapshotCount{Rows: int(n)}
		if last != nil {
			c.LastCollectedAt = *last
		}
		out[connectorID] = c
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("SnapshotCounts: rows: %w", err)
	}
	return out, nil
}

// ListRecent returns snapshots for a connector from the last N days, newest first.
func (r *PGRepo) ListRecent(ctx context.Context, connectorID string, days int) ([]CostSnapshot, error) {
	const q = `
SELECT id, connector_id, account_id, service, cost_usd, period_date, collected_at
FROM cost_snapshots
WHERE connector_id = $1
  AND period_date >= (current_date - ($2::int * interval '1 day'))::date
ORDER BY period_date DESC, service`

	rows, err := r.pool.Query(ctx, q, connectorID, days)
	if err != nil {
		return nil, fmt.Errorf("ListRecent: %w", err)
	}
	defer rows.Close()

	var out []CostSnapshot
	for rows.Next() {
		var s CostSnapshot
		var costUSD float64
		var periodDate time.Time
		if err := rows.Scan(
			&s.ID, &s.ConnectorID, &s.AccountID, &s.Service,
			&costUSD, &periodDate, &s.CollectedAt,
		); err != nil {
			return nil, fmt.Errorf("ListRecent: scan: %w", err)
		}
		s.CostUSD = costUSD
		s.PeriodDate = periodDate
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListRecent: rows: %w", err)
	}
	return out, nil
}

// DetectAnomalies returns services where the most recent day's cost is more than
// 2× the 7-day rolling average AND the absolute delta exceeds $5.
func (r *PGRepo) DetectAnomalies(ctx context.Context, connectorID string) ([]CostAnomaly, error) {
	// Postgres does not allow window functions inside FILTER clauses of aggregates.
	// Fix: pre-compute max(period_date) per service in a CTE, then use plain
	// column comparison in FILTER instead of max(...) OVER (PARTITION BY ...).
	const q = `
WITH recent AS (
    SELECT service, period_date, cost_usd
    FROM cost_snapshots
    WHERE connector_id = $1
      AND period_date >= (current_date - interval '8 days')::date
),
max_dates AS (
    SELECT service, max(period_date) AS latest_date
    FROM recent
    GROUP BY service
),
rolling AS (
    SELECT
        r.service,
        m.latest_date,
        max(r.cost_usd) FILTER (WHERE r.period_date = m.latest_date) AS latest_cost,
        avg(r.cost_usd) FILTER (WHERE r.period_date < m.latest_date)  AS rolling_avg
    FROM recent r
    JOIN max_dates m ON m.service = r.service
    GROUP BY r.service, m.latest_date
)
SELECT service, latest_date, latest_cost, rolling_avg,
       (latest_cost - rolling_avg) AS delta
FROM rolling
WHERE rolling_avg > 0
  AND latest_cost > 2 * rolling_avg
  AND (latest_cost - rolling_avg) > 5
ORDER BY (latest_cost - rolling_avg) DESC`

	rows, err := r.pool.Query(ctx, q, connectorID)
	if err != nil {
		return nil, fmt.Errorf("DetectAnomalies: %w", err)
	}
	defer rows.Close()

	var out []CostAnomaly
	for rows.Next() {
		var a CostAnomaly
		var latestDate time.Time
		if err := rows.Scan(
			&a.Service, &latestDate, &a.LatestCostUSD, &a.RollingAvgUSD, &a.DeltaUSD,
		); err != nil {
			return nil, fmt.Errorf("DetectAnomalies: scan: %w", err)
		}
		a.ConnectorID = connectorID
		a.PeriodDate = latestDate
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("DetectAnomalies: rows: %w", err)
	}
	return out, nil
}
