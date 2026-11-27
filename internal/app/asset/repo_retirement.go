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
 AND if(last_seen = toStartOfSecond(last_seen), last_seen + INTERVAL 999999999 NANOSECOND, last_seen)
 < parseDateTime64BestEffort(mapFromArrays(?, ?)[id], 9)
 SETTINGS lightweight_deletes_sync = 1`
const retireEdgeVersions = `DELETE FROM graph_edges WHERE
 (src_id IN (%s) AND if(synced_at = toStartOfSecond(synced_at), synced_at + INTERVAL 999999999 NANOSECOND, synced_at)
 < parseDateTime64BestEffort(mapFromArrays(?, ?)[src_id], 9))
 OR (dst_id IN (%s) AND if(synced_at = toStartOfSecond(synced_at), synced_at + INTERVAL 999999999 NANOSECOND, synced_at)
 < parseDateTime64BestEffort(mapFromArrays(?, ?)[dst_id], 9))
 SETTINGS lightweight_deletes_sync = 1`

// RetireAssets applies complete-enumeration proofs to every stored version,
// preserving observations at or after the proof's cutoff. A whole-second row
// may predate the precision migration: treat it as the end of that second so
// lost fractions cannot turn a resurfacing resource into a confirmed deletion.
// Apply this per row, including writes arriving after the eligibility read.
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
		cutoffs = append(cutoffs, at.UTC().Format(time.RFC3339Nano))
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
			if !observedBeforeDeletion(lastSeen, deletions[id]) {
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
