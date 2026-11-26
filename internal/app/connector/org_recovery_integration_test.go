//go:build integration

package connector

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

type failFirstAccountWrite struct {
	Repo
	failed bool
}

func (r *failFirstAccountWrite) UpsertOrgAccounts(ctx context.Context, rows []OrgAccount, at time.Time) error {
	if !r.failed {
		r.failed = true
		return context.DeadlineExceeded
	}
	return r.Repo.UpsertOrgAccounts(ctx, rows, at)
}

func TestOrgBatchWriteFailureRecoversExistingChildren(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated Postgres")
	}
	ctx := context.Background()
	pool, err := db.NewPool(ctx, dsn, db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	repo := &failFirstAccountWrite{Repo: NewPGRepo(pool)}
	svc := NewService(repo, cipher).WithOrgDiscoverer(&fakeDiscoverer{accounts: []DiscoveredAccount{active("918000000001"), active("918000000002"), active("918000000003")}})
	name := fmt.Sprintf("org-recovery-%d", time.Now().UnixNano())
	org, err := svc.Create(ctx, TypeAWSOrg, name, orgConfig(nil), "")
	require.NoError(t, err)
	defer func() {
		_, e := pool.Exec(ctx, "DELETE FROM connectors WHERE name LIKE $1", name+"%")
		require.NoError(t, e)
	}()
	first, err := svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, first.Created, 3)
	require.Equal(t, 3, first.Errors)
	rows, err := svc.OrgAccounts(ctx, org.ID)
	require.NoError(t, err)
	require.Empty(t, rows)
	retry, err := svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Zero(t, retry.Errors)
	require.Empty(t, retry.Created)
	rows, err = svc.OrgAccounts(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	var ids []string
	for _, row := range rows {
		require.NotNil(t, row.Child)
		require.True(t, row.Child.Enabled)
		ids = append(ids, row.ChildConnectorID)
	}
	require.ElementsMatch(t, first.Created, ids)
}
