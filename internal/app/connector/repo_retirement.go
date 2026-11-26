package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

func (r *PGRepo) PendingAssetRetirements(ctx context.Context, limit int) (map[string]time.Time, error) {
	if limit <= 0 || limit > 1000 {
		return nil, fmt.Errorf("PendingAssetRetirements: invalid limit %d", limit)
	}
	rows, err := r.q.PendingAssetRetirements(ctx, int32(limit))
	if err != nil {
		return nil, fmt.Errorf("PendingAssetRetirements: %w", err)
	}
	out := make(map[string]time.Time, len(rows))
	for _, row := range rows {
		out[row.AssetID] = row.DeletedAt
	}
	return out, nil
}
func (r *PGRepo) CompleteAssetRetirements(ctx context.Context, deletions map[string]time.Time) error {
	ids := make([]string, 0, len(deletions))
	ats := make([]time.Time, 0, len(deletions))
	for id, at := range deletions {
		ids = append(ids, id)
		ats = append(ats, at)
	}
	if err := r.q.CompleteAssetRetirements(ctx, sqlcgen.CompleteAssetRetirementsParams{AssetIds: ids, DeletedAts: ats}); err != nil {
		return fmt.Errorf("CompleteAssetRetirements: %w", err)
	}
	return nil
}
