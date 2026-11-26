package executor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

func TestApproval_RevokedAuthorityCannotRedeem(t *testing.T) {
	a := testApprover(t)
	ledger := &memLedger{spent: map[string]bool{}, authority: map[string]int64{alice.ID: 1}}
	a.WithLedger(ledger)
	approval, err := a.Mint("c", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)
	// Demotion, disablement, reset, or explicit session revocation increments
	// the persisted version; re-enabling the account does not restore old grants.
	ledger.authority[alice.ID] = 3
	_, err = a.Redeem(context.Background(), approval.Token, "c", ActionEC2Stop, "plan", bob)
	require.ErrorIs(t, err, ErrApprovalInvalid)
	require.Empty(t, ledger.spent)
	fresh := alice
	fresh.AuthorityVersion = 3
	approval, err = a.Mint("c", ActionEC2Stop, "plan", fresh)
	require.NoError(t, err)
	_, err = a.Redeem(context.Background(), approval.Token, "c", ActionEC2Stop, "plan", bob)
	require.NoError(t, err)
}

func TestTwoPersonRequiresAdministratorTenure(t *testing.T) {
	now := time.Now()
	svc := &Service{now: func() time.Time { return now }, minApproverAge: 24 * time.Hour}
	oldAccount := now.Add(-365 * 24 * time.Hour)
	recentPromotion := now.Add(-time.Hour)
	ctx := auth.ContextWithUser(context.Background(), auth.User{
		ID: "old-user", Email: "admin@example.com", Role: auth.RoleAdmin,
		CreatedAt: oldAccount, AdminSince: recentPromotion, AuthorityVersion: 2,
	})
	require.ErrorContains(t, svc.checkAccountAge(principalFromContext(ctx), "approving"), "admin for 1h0m0s")
	p := principalFromContext(ctx)
	p.AdminSince = now.Add(-25 * time.Hour)
	require.NoError(t, svc.checkAccountAge(p, "approving"))
	p.AdminSince = time.Time{}
	require.Error(t, svc.checkAccountAge(p, "approving"))
}
