package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

const firstObservationsByIDs = `SELECT id,min(discovered_at), ` + firstDiscoveredAtAgg + ` FROM assets WHERE id IN (%s) GROUP BY id`

// FirstObservationsByIDs uses ByIDs' timestamp aggregates and unknown-date
// rules, without selecting metadata, tags or enrichment outputs.
func (r *CHRepo) FirstObservationsByIDs(ctx context.Context, ids []string) (map[string]time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	batches, err := dbutil.CHStringBatches(ids)
	if err != nil {
		return nil, fmt.Errorf("FirstObservationsByIDs: %w", err)
	}
	dates := make(map[string]time.Time, len(ids))
	for _, batch := range batches {
		readCtx := ctx
		if len(batch) <= 64 {
			readCtx = r.ch.WithQuerySettings(ctx, map[string]any{"max_threads": 1})
		}
		keys, args := dbutil.CHIn(batch)
		if err := r.ch.Select(readCtx, func(rows driver.Rows) error {
			for rows.Next() {
				var id string
				var observed, first time.Time
				if err := rows.Scan(&id, &observed, &first); err != nil {
					return err
				}
				dates[id] = earliest(observed, first)
			}
			return rows.Err()
		}, fmt.Sprintf(firstObservationsByIDs, keys), args...); err != nil {
			return nil, fmt.Errorf("FirstObservationsByIDs: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("FirstObservationsByIDs: %w", err)
	}
	return dates, nil
}
