package asset

import (
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testDeletionProofs struct {
	proofs map[string]time.Time
	err    error
}

func (p testDeletionProofs) AssetDeletions(context.Context, []string) (map[string]time.Time, error) {
	return maps.Clone(p.proofs), p.err
}

func TestVerifyDepartedAssets_ProofAndNewerObservation(t *testing.T) {
	at := time.Now().Truncate(time.Second)
	repo := newFakeRepo()
	repo.assets["old"] = Asset{ID: "old", Type: "ec2_instance", LastSeen: at.Add(-time.Hour)}
	repo.assets["back"] = Asset{ID: "back", Type: "ec2_instance", LastSeen: at}
	svc := NewService(repo).WithDeletionProofs(testDeletionProofs{proofs: map[string]time.Time{"old": at, "back": at, "retired": at}})
	got, err := svc.VerifyDepartedAssets(context.Background(), []string{"old", "back", "retired", "never-seen"})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"old": true, "retired": true}, got)
	repo.byIDsErr = errors.New("inventory unavailable")
	_, err = svc.VerifyDepartedAssets(context.Background(), []string{"old"})
	require.ErrorContains(t, err, "observations")
	svc.WithDeletionProofs(testDeletionProofs{err: errors.New("proofs unavailable")})
	_, err = svc.VerifyDepartedAssets(context.Background(), []string{"old"})
	require.ErrorContains(t, err, "proofs")
}
