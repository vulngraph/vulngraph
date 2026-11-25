package diskscan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type volumeRepo struct {
	Repository
	vols []VolumeResult
}

func (r volumeRepo) LatestAssetVolumes(context.Context, string) ([]VolumeResult, error) {
	return r.vols, nil
}

func TestAssetVolumes_NeverReadsAsClean(t *testing.T) {
	svc := NewService(volumeRepo{vols: []VolumeResult{{VolumeRef: "v", PackageCount: 7, CVEMatchableKnown: true}}}, nil)
	got, err := svc.AssetVolumes(context.Background(), "i-1")
	require.NoError(t, err)
	require.Equal(t, GapReadError, got[0].Gap)
	require.Zero(t, got[0].PackageCount)
	require.False(t, got[0].CVEMatchableKnown)
}

func TestAssetVolumes_RepoWithoutTheCapabilityIsAnError(t *testing.T) {
	_, err := NewService(nil, nil).AssetVolumes(context.Background(), "i-1")
	require.Error(t, err)
}
