package diskscan

import (
	"context"
	"fmt"
)

// LatestAssetVolumes returns the newest result of each volume of one asset.
func (r *PGRepo) LatestAssetVolumes(ctx context.Context, assetID string) ([]VolumeResult, error) {
	rows, err := r.q.LatestDiskScanVolumesForAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("LatestAssetVolumes: %w", err)
	}
	out := make([]VolumeResult, len(rows))
	for i, row := range rows {
		out[i] = VolumeResult{
			RunID: row.RunID, AssetID: row.AssetID, VolumeRef: row.VolumeRef, SnapshotID: row.SnapshotID,
			SnapshotSource: SnapshotSource(row.SnapshotSource), Encrypted: row.Encrypted,
			InventoryKnown: row.InventoryKnown, CVEMatchableKnown: row.CveMatchableKnown, Gap: row.Gap,
			PackageCount: int(row.PackageCount), ObservedAt: row.ObservedAt,
		}
	}
	return out, nil
}
