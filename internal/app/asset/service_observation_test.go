package asset

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type projectedObservationRepo struct {
	*fakeRepo
	dates   map[string]time.Time
	err     error
	lookups int
}

func (r *projectedObservationRepo) FirstObservationsByIDs(context.Context, []string) (map[string]time.Time, error) {
	r.lookups++
	return r.dates, r.err
}
func (r *projectedObservationRepo) ByIDs(context.Context, []string) ([]Asset, error) {
	return nil, errors.New("unexpected full-row observation lookup")
}

func TestObservationProjectionPreservesHistoryAndErrors(t *testing.T) {
	old := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	t.Run("preserve earliest date and incoming fields", func(t *testing.T) {
		for _, incoming := range []time.Time{old.Add(time.Hour), old.Add(-time.Hour)} {
			repo := &projectedObservationRepo{fakeRepo: newFakeRepo(), dates: map[string]time.Time{"existing": old}}
			require.NoError(t, NewService(repo).IngestAssets(t.Context(), []Asset{{ID: "existing", DiscoveredAt: incoming}}))
			require.Equal(t, earliest(old, incoming), repo.assets["existing"].FirstDiscoveredAt)
			require.Equal(t, 1, repo.lookups)
		}
	})
	t.Run("lookup error preserves existing policy", func(t *testing.T) {
		failure := errors.New("history unavailable")
		repo := &projectedObservationRepo{fakeRepo: newFakeRepo(), err: failure}
		err := NewService(repo).IngestAssets(t.Context(), []Asset{{ID: "existing", DiscoveredAt: old}})
		require.NoError(t, err, "retain the asset history lookup's existing best-effort policy")
		require.Len(t, repo.assets, 1)
		require.Equal(t, 1, repo.lookups)
	})
}
