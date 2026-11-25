package diskscan

import (
	"context"
	"errors"
	"fmt"
)

// assetVolumeStore is the optional repo capability behind AssetVolumes.
type assetVolumeStore interface {
	LatestAssetVolumes(ctx context.Context, assetID string) ([]VolumeResult, error)
}

// AssetVolumes returns the newest result of each volume of one asset, for the
// read API. An asset nothing has read yields an empty list, which callers must
// present as unknown.
func (s *Service) AssetVolumes(ctx context.Context, assetID string) ([]VolumeResult, error) {
	store, ok := s.repo.(assetVolumeStore)
	if !ok {
		return nil, errors.New("AssetVolumes: the repository does not store volume results")
	}
	vols, err := store.LatestAssetVolumes(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("AssetVolumes: %w", err)
	}
	for i := range vols {
		vols[i] = guardUnknown(vols[i])
	}
	return vols, nil
}
