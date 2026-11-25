//go:build integration

package connector

import (
	"cmp"
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// The whole org lifecycle against real Postgres: discovery creates children
// and rows, a suspension disables (not deletes) the child, a failed listing
// changes nothing, and deleting the org disables its children atomically.
func TestPGRepo_AWSOrgLifecycle(t *testing.T) {
	ctx := context.Background()
	dsn := cmp.Or(os.Getenv("GRAPH_TEST_PG_DSN"), "postgres://graph:graph@localhost:5432/graph?sslmode=disable")
	pool, err := db.NewPool(ctx, dsn, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	disc := &fakeDiscoverer{}
	svc := NewService(NewPGRepo(pool), cipher).WithOrgDiscoverer(disc)

	name := "it-org-" + time.Now().Format("150405.000000")
	org, err := svc.Create(ctx, TypeAWSOrg, name, orgConfig(map[string]string{
		OrgKeyHubAuth: HubAuthAccessKey, "aws_access_key_id": "AKIAHUB", "aws_secret_access_key": "hub-secret",
		OrgKeyHubRoleARN: testHubRole,
	}), "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE name LIKE $1", name+"%")
	})

	acctA, acctB := "910000000001", "910000000002"
	disc.accounts = []DiscoveredAccount{active(acctA), {ID: acctB, Name: "b", State: "SUSPENDED"}}
	res, err := svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, res.Created, 1)

	rows, err := svc.OrgAccounts(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	byID := map[string]OrgAccount{}
	for _, r := range rows {
		byID[r.AccountID] = r
	}
	childID := byID[acctA].ChildConnectorID
	require.NotEmpty(t, childID)
	require.NotNil(t, byID[acctA].Child)
	require.True(t, byID[acctA].Child.Enabled)
	require.Equal(t, SyncPending, byID[acctA].Child.SyncStatus)
	require.Equal(t, OrgAccountSuspended, byID[acctB].Status)
	require.Nil(t, byID[acctB].Child)

	// Stored child config: references only.
	var enc []byte
	require.NoError(t, pool.QueryRow(ctx, "SELECT config_enc FROM connectors WHERE id = $1", childID).Scan(&enc))
	stored, err := svc.getStored(ctx, childID)
	require.NoError(t, err)
	require.NotContains(t, stored.Config, "aws_access_key_id")
	require.NotContains(t, stored.Config, "external_id")
	resolved, err := svc.Get(ctx, childID)
	require.NoError(t, err)
	require.Equal(t, "AKIAHUB", resolved.Config["aws_access_key_id"])

	// A failed listing changes nothing.
	disc.err = context.DeadlineExceeded
	_, err = svc.ReconcileOrg(ctx, org.ID)
	require.Error(t, err)
	disc.err = nil
	child, err := svc.getStored(ctx, childID)
	require.NoError(t, err)
	require.True(t, child.Enabled)

	// Suspension disables, keeps.
	before := byID[acctA].StatusChangedAt
	disc.accounts = []DiscoveredAccount{{ID: acctA, State: "SUSPENDED"}}
	_, err = svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	rows, err = svc.OrgAccounts(ctx, org.ID)
	require.NoError(t, err)
	for _, r := range rows {
		if r.AccountID == acctA {
			require.Equal(t, OrgAccountSuspended, r.Status)
			require.Equal(t, childID, r.ChildConnectorID)
			require.False(t, r.Child.Enabled)
			require.True(t, r.StatusChangedAt.After(before) || r.StatusChangedAt.Equal(before))
		}
	}

	// Deleting the org disables (keeps) the child and drops the rows.
	disc.accounts = []DiscoveredAccount{active(acctA)}
	_, err = svc.ReconcileOrg(ctx, org.ID)
	require.NoError(t, err)
	require.NoError(t, svc.Delete(ctx, org.ID))
	child, err = svc.getStored(ctx, childID)
	require.NoError(t, err)
	require.False(t, child.Enabled)
	var n int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM aws_org_accounts WHERE org_connector_id = $1", org.ID).Scan(&n))
	require.Zero(t, n)
	_, err = svc.Get(ctx, childID)
	require.ErrorIs(t, err, ErrOrgParentMissing)
}
