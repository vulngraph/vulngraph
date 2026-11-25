package forget

import (
	"context"
	"fmt"
	"time"
)

const selectTombstones = `
	SELECT asset_id, believed_gone_at FROM forget_tombstones WHERE asset_id = ANY($1::text[])`

// Tombstones returns, for each of ids with a tombstone, when it was believed
// gone. Writers of derived data (the package-inventory ingest) use it to refuse
// an asset the platform has stopped believing in.
func (r *PGRepo) Tombstones(ctx context.Context, ids []string) (map[string]time.Time, error) {
	rows, err := r.pool.Query(ctx, selectTombstones, ids)
	if err != nil {
		return nil, fmt.Errorf("Tombstones: %w", err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var id string
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, fmt.Errorf("Tombstones: scan: %w", err)
		}
		out[id] = at
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("Tombstones: %w", err)
	}
	return out, nil
}
