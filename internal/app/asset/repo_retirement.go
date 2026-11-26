package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

const retirementLastSeen = "SELECT id, max(last_seen) FROM assets WHERE id IN (%s) GROUP BY id"
const retireAssetVersions = `DELETE FROM assets WHERE id IN (%s)
 AND last_seen < parseDateTimeBestEffort(mapFromArrays(?, ?)[id])
 SETTINGS lightweight_deletes_sync = 1`
const retireEdgeVersions = `DELETE FROM graph_edges WHERE
 (src_id IN (%s) AND synced_at < parseDateTimeBestEffort(mapFromArrays(?, ?)[src_id]))
 OR (dst_id IN (%s) AND synced_at < parseDateTimeBestEffort(mapFromArrays(?, ?)[dst_id]))
 SETTINGS lightweight_deletes_sync = 1`

// RetireAssets applies complete-enumeration proofs to every stored version,
// preserving observations at or after the proof's cutoff. The inventory table
// uses second precision, so equality is deliberately kept. Field-change and
// finding history live in separate tables and are unaffected.
func (r *CHRepo) RetireAssets(ctx context.Context, deletions map[string]time.Time) ([]string, error) {
	if len(deletions) == 0 {
		return nil, nil
	}
	if len(deletions) > 200 {
		return nil, fmt.Errorf("RetireAssets: batch exceeds 200 assets")
	}
	ids := make([]string, 0, len(deletions))
	cutoffs := make([]string, 0, len(deletions))
	for id, at := range deletions {
		if id == "" || at.IsZero() {
			return nil, fmt.Errorf("RetireAssets: empty identity or deletion time")
		}
		ids = append(ids, id)
		cutoffs = append(cutoffs, at.UTC().Truncate(time.Second).Format(time.RFC3339))
	}
	in, args := dbutil.CHIn(ids)
	qctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	eligible := make(map[string]bool, len(ids))
	for _, id := range ids {
		eligible[id] = true
	}
	err := r.ch.Select(qctx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			var lastSeen time.Time
			if err := rows.Scan(&id, &lastSeen); err != nil {
				return err
			}
			if !lastSeen.Before(deletions[id].Truncate(time.Second)) {
				delete(eligible, id)
			}
		}
		return rows.Err()
	}, fmt.Sprintf(retirementLastSeen, in), args...)
	if err != nil {
		return nil, fmt.Errorf("RetireAssets: observations: %w", err)
	}
	execCtx, execCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer execCancel()
	assetArgs := append(args, ids, cutoffs)
	if err := r.ch.Exec(execCtx, fmt.Sprintf(retireAssetVersions, in), assetArgs...); err != nil {
		return nil, fmt.Errorf("RetireAssets: inventory: %w", err)
	}
	edgeArgs := append([]any{}, args...)
	edgeArgs = append(edgeArgs, ids, cutoffs)
	edgeArgs = append(edgeArgs, args...)
	edgeArgs = append(edgeArgs, ids, cutoffs)
	if err := r.ch.Exec(execCtx, fmt.Sprintf(retireEdgeVersions, in, in), edgeArgs...); err != nil {
		return nil, fmt.Errorf("RetireAssets: edges: %w", err)
	}
	out := make([]string, 0, len(eligible))
	for _, id := range ids {
		if eligible[id] {
			out = append(out, id)
		}
	}
	return out, nil
}
