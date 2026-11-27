package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

const blastAccountsByIDs = `SELECT id, argMax(account_id, synced_at) FROM assets WHERE id IN (%s) GROUP BY id`

// AccountsByIDs preserves ByIDs' current-version and missing-ID semantics,
// without reading tags, metadata or other fields unused by account counting.
func (r *CHRepo) AccountsByIDs(ctx context.Context, ids []string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	batches, err := dbutil.CHStringBatches(ids)
	if err != nil {
		return nil, fmt.Errorf("AccountsByIDs: %w", err)
	}
	out := make(map[string]string, len(ids))
	for _, batch := range batches {
		readCtx := ctx
		if len(batch) <= 64 {
			readCtx = r.ch.WithQuerySettings(readCtx, map[string]any{"max_threads": 1})
		}
		keys, args := dbutil.CHIn(batch)
		if err := r.ch.Select(readCtx, func(rows driver.Rows) error {
			for rows.Next() {
				var id, account string
				if err := rows.Scan(&id, &account); err != nil {
					return err
				}
				out[id] = account
			}
			return rows.Err()
		}, fmt.Sprintf(blastAccountsByIDs, keys), args...); err != nil {
			return nil, fmt.Errorf("AccountsByIDs: %w", err)
		}
	}
	return out, nil
}
