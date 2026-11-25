package suppress

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	repo.rows["active"] = Suppression{FindingID: "active", Reason: "accepted", ExpiresAt: testNow.Add(day)}
	repo.rows["lapsed"] = Suppression{FindingID: "lapsed", Reason: "old", ExpiresAt: testNow.Add(-day)}
	svc := clockedService(repo)

	st, err := svc.State(ctx, "active")
	require.NoError(t, err)
	require.True(t, st.Suppressed)
	require.False(t, st.Expired)
	require.Equal(t, "accepted", st.Suppression.Reason)

	st, err = svc.State(ctx, "lapsed")
	require.NoError(t, err)
	require.False(t, st.Suppressed)
	require.True(t, st.Expired)
	require.Equal(t, testNow.Add(-day), st.Suppression.ExpiresAt)

	st, err = svc.State(ctx, "never")
	require.NoError(t, err)
	require.Equal(t, State{}, st)

	repo.getErr = errors.New("pg down")
	_, err = svc.State(ctx, "active")
	require.Error(t, err, "a failed read must not masquerade as not-suppressed")
}
