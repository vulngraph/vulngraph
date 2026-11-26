package connector

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrgReconciliationDoesNotReloadEveryChild(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	for i := range 1000 {
		disc.accounts = append(disc.accounts, active(fmt.Sprintf("%012d", 900000000000+i)))
	}
	first, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Len(t, first.Created, 1000)
	repo.getCalls = 0
	repo.orgBatchCalls = 0
	next, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Zero(t, next.Errors)
	require.Empty(t, next.Created)
	require.Equal(t, 2, repo.orgBatchCalls)
	require.LessOrEqual(t, repo.getCalls, 2, "use the connector snapshot rather than two reads per child")
}

func TestOrgBatchFailureIsRecordedAndRetryRecovers(t *testing.T) {
	svc, repo, disc, org := newOrgFixture(t, nil)
	disc.accounts = []DiscoveredAccount{active("900000000001")}
	first, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Zero(t, first.Errors)
	repo.orgBatchErr = context.DeadlineExceeded
	failed, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Positive(t, failed.Errors)
	require.NotEmpty(t, repo.rows[org.ID].SyncError)
	repo.orgBatchErr = nil
	retry, err := svc.ReconcileOrg(context.Background(), org.ID)
	require.NoError(t, err)
	require.Zero(t, retry.Errors)
	require.Empty(t, retry.Created)
}
