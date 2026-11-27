package asset

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBlastDeletedMiddleCannotBridgeButUnknownCan(t *testing.T) {
	repo := newFakeRepo()
	repo.addAsset("a")
	repo.addAsset("c")
	repo.link("a", "b", "can_assume")
	repo.link("b", "c", "can_assume")
	at := time.Now().UTC()
	svc := NewService(repo).WithDeletionProofs(testDeletionProofs{proofs: map[string]time.Time{"b": at}})
	full, err := svc.BlastRadius(t.Context(), "a", 2)
	require.NoError(t, err)
	require.Len(t, full.Assets, 1)
	require.Empty(t, full.Edges)
	counts, err := svc.BlastRadiusAccounts(t.Context(), "a", 2)
	require.NoError(t, err)
	require.Zero(t, counts.Total)

	// An uncollected identity has no deletion proof. Keep its unknown stub and
	// observed relationships; absence alone cannot be evidence of deletion.
	svc.WithDeletionProofs(testDeletionProofs{})
	full, err = svc.BlastRadius(t.Context(), "a", 2)
	require.NoError(t, err)
	require.Len(t, full.Assets, 3)
	counts, err = svc.BlastRadiusAccounts(t.Context(), "a", 2)
	require.NoError(t, err)
	require.Equal(t, 2, counts.Total)

	svc.WithDeletionProofs(testDeletionProofs{proofs: map[string]time.Time{"b": at}})
	repo.assets["b"] = Asset{ID: "b", LastSeen: at.Add(time.Second)}
	full, err = svc.BlastRadius(t.Context(), "a", 2)
	require.NoError(t, err)
	require.Len(t, full.Assets, 3)

	svc.WithDeletionProofs(testDeletionProofs{err: errors.New("proof store unavailable")})
	_, err = svc.BlastRadius(t.Context(), "a", 2)
	require.ErrorContains(t, err, "proof store unavailable")
	_, err = svc.BlastRadiusAccounts(t.Context(), "a", 2)
	require.ErrorContains(t, err, "proof store unavailable")
}
