package suppress

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCarryForward(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	newSvc := func(rows map[string]Suppression) (*Service, *fakeRepo) {
		repo := newFakeRepo()
		for k, v := range rows {
			repo.rows[k] = v
		}
		svc := NewService(repo)
		svc.now = func() time.Time { return now }
		return svc, repo
	}
	active := Suppression{FindingID: "old", Reason: "public website", SuppressedBy: "alice", ExpiresAt: now.Add(30 * 24 * time.Hour)}

	t.Run("an active suppression is carried with its reason, actor and expiry", func(t *testing.T) {
		svc, repo := newSvc(map[string]Suppression{"old": active})
		carried, err := svc.CarryForward(context.Background(), "new", "old")
		require.NoError(t, err)
		require.True(t, carried)
		require.Equal(t, "public website", repo.rows["new"].Reason)
		require.Equal(t, "alice", repo.rows["new"].SuppressedBy)
		require.Equal(t, active.ExpiresAt, repo.rows["new"].ExpiresAt)
	})
	t.Run("an expired suppression is not carried", func(t *testing.T) {
		expired := active
		expired.ExpiresAt = now.Add(-time.Hour)
		svc, repo := newSvc(map[string]Suppression{"old": expired})
		carried, err := svc.CarryForward(context.Background(), "new", "old")
		require.NoError(t, err)
		require.False(t, carried)
		require.NotContains(t, repo.rows, "new")
	})
	t.Run("nothing to carry", func(t *testing.T) {
		svc, _ := newSvc(nil)
		carried, err := svc.CarryForward(context.Background(), "new", "old")
		require.NoError(t, err)
		require.False(t, carried)
	})
	t.Run("the new finding's own suppression, even a lapsed one, wins", func(t *testing.T) {
		own := Suppression{FindingID: "new", Reason: "re-reviewed", SuppressedBy: "bob", ExpiresAt: now.Add(-time.Hour)}
		svc, repo := newSvc(map[string]Suppression{"old": active, "new": own})
		carried, err := svc.CarryForward(context.Background(), "new", "old")
		require.NoError(t, err)
		require.False(t, carried)
		require.Equal(t, "re-reviewed", repo.rows["new"].Reason)
	})
	t.Run("a failed read is an error", func(t *testing.T) {
		svc, repo := newSvc(map[string]Suppression{"old": active})
		repo.getErr = errors.New("pg down")
		_, err := svc.CarryForward(context.Background(), "new", "old")
		require.Error(t, err)
	})
}
