//go:build integration

package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

func TestPGRepo_UserAdministrationSerializesAndRollsBack(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, testPGDSN(), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	repo := NewPGRepo(pool, testCipher(t))
	user, err := repo.CreateUser(ctx, "admin-lock-"+time.Now().Format("150405.000000000")+"@example.com", "unused", RoleAnalyst)
	require.NoError(t, err)
	defer func() { require.NoError(t, repo.DeleteUser(ctx, user.ID)) }()
	rollback := errors.New("abort transaction")
	err = repo.WithUserAdministration(ctx, func(tx UserAdminRepo) error {
		_, err := tx.SetUserRole(ctx, user.ID, RoleViewer, false)
		require.NoError(t, err)
		deadline, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		called := false
		blocked := repo.WithUserAdministration(deadline, func(UserAdminRepo) error {
			called = true
			return nil
		})
		require.Error(t, blocked)
		require.False(t, called, "second transaction must not enter before lock release")
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	got, err := repo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, RoleAnalyst, got.Role, "failed operation must roll back its writes")
	require.NoError(t, repo.WithUserAdministration(ctx, func(tx UserAdminRepo) error {
		_, err := tx.SetUserRole(ctx, user.ID, RoleViewer, false)
		return err
	}))
	got, err = repo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, RoleViewer, got.Role)
}
