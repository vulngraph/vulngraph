package apikey

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// recordingRepo captures what the service asks the repo to persist and serves
// a fixed key from Verify/List.
type recordingRepo struct {
	createdExpiry *time.Time
	key           APIKey
}

func (r *recordingRepo) Create(_ context.Context, userID, name string, scope Scope, expiresAt *time.Time) (APIKey, string, error) {
	r.createdExpiry = expiresAt
	return APIKey{UserID: userID, Name: name, Scopes: scope, ExpiresAt: expiresAt}, "gph_x", nil
}
func (r *recordingRepo) List(context.Context, string) ([]APIKey, error) { return []APIKey{r.key}, nil }
func (r *recordingRepo) Delete(context.Context, string, string) error   { return nil }
func (r *recordingRepo) Verify(context.Context, string) (APIKey, error) { return r.key, nil }

func newLifetimeService(repo *recordingRepo, now time.Time) *Service {
	s := NewService(repo).WithMaxLifetime(90 * 24 * time.Hour)
	s.now = func() time.Time { return now }
	return s
}

func TestCreate_EnforcesMaxLifetime(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	maxExp := now.Add(90 * 24 * time.Hour)
	ctx := context.Background()
	tp := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	for _, tc := range []struct {
		name      string
		expiresAt *time.Time
		want      time.Time
		wantErr   error
	}{
		{"no expiry gets the maximum", nil, maxExp, nil},
		{"explicit within the maximum", tp(time.Hour), now.Add(time.Hour), nil},
		{"exactly the maximum", &maxExp, maxExp, nil},
		{"beyond the maximum is refused", tp(91 * 24 * time.Hour), time.Time{}, ErrBadExpiry},
		{"in the past is refused", tp(-time.Minute), time.Time{}, ErrBadExpiry},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &recordingRepo{}
			_, _, err := newLifetimeService(repo, now).Create(ctx, "u", "k", ScopeRead, tc.expiresAt)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				require.Nil(t, repo.createdExpiry, "nothing persisted")
				return
			}
			require.NoError(t, err)
			require.NotNil(t, repo.createdExpiry, "every key is stored with an expiry")
			require.True(t, tc.want.Equal(*repo.createdExpiry), "want %s got %s", tc.want, repo.createdExpiry)
		})
	}

	_, _, err := newLifetimeService(&recordingRepo{}, now).Create(ctx, "u", "", ScopeRead, nil)
	require.ErrorIs(t, err, ErrNameRequired)
}

// A key created before the cap with no expiry expires at created_at + max.
func TestVerify_LegacyNonExpiringKeyCappedAtCreatedPlusMax(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	ctx := context.Background()

	recent := &recordingRepo{key: APIKey{ID: "k", CreatedAt: now.Add(-10 * 24 * time.Hour)}}
	got, err := newLifetimeService(recent, now).Verify(ctx, "gph_x")
	require.NoError(t, err)
	require.True(t, now.Add(80*24*time.Hour).Equal(*got.ExpiresAt), "effective expiry is reported")

	old := &recordingRepo{key: APIKey{ID: "k", CreatedAt: now.Add(-91 * 24 * time.Hour)}}
	_, err = newLifetimeService(old, now).Verify(ctx, "gph_x")
	require.ErrorIs(t, err, ErrNotFound)

	far := now.Add(365 * 24 * time.Hour)
	longLived := &recordingRepo{key: APIKey{ID: "k", CreatedAt: now.Add(-91 * 24 * time.Hour), ExpiresAt: &far}}
	_, err = newLifetimeService(longLived, now).Verify(ctx, "gph_x")
	require.ErrorIs(t, err, ErrNotFound, "a stored expiry beyond the cap does not extend it")

	keys, err := newLifetimeService(recent, now).List(ctx, "u")
	require.NoError(t, err)
	require.True(t, now.Add(80*24*time.Hour).Equal(*keys[0].ExpiresAt), "List shows the effective expiry")
}
