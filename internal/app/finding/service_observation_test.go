package finding

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
func (r *projectedObservationRepo) ByIDs(context.Context, []string) ([]Finding, error) {
	return nil, errors.New("unexpected full-row observation lookup")
}

func TestObservationProjectionPreservesHistoryAndErrors(t *testing.T) {
	old := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	t.Run("preserve earliest date and incoming fields", func(t *testing.T) {
		for _, incoming := range []time.Time{old.Add(time.Hour), old.Add(-time.Hour)} {
			repo := &projectedObservationRepo{fakeRepo: &fakeRepo{}, dates: map[string]time.Time{"existing": old}}
			require.NoError(t, NewService(repo).RecordObserved(t.Context(), []Finding{{ID: "existing", DetectedAt: incoming}}))
			require.Equal(t, earliest(old, incoming), repo.stored[0].FirstDetectedAt)
			require.Equal(t, 1, repo.lookups)
		}
	})
	t.Run("lookup error preserves existing policy", func(t *testing.T) {
		failure := errors.New("history unavailable")
		repo := &projectedObservationRepo{fakeRepo: &fakeRepo{}, err: failure}
		err := NewService(repo).RecordObserved(t.Context(), []Finding{{ID: "existing", DetectedAt: old}})
		require.ErrorIs(t, err, failure)
		require.Empty(t, repo.stored, "finding observations fail closed without history")
		require.Equal(t, 1, repo.lookups)
	})
}
