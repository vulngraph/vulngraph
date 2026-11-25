package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
)

type fakeOrgReconciler struct {
	created []string
	err     error
	calls   int
}

func (f *fakeOrgReconciler) ReconcileAllOrgs(context.Context) ([]string, error) {
	f.calls++
	return f.created, f.err
}

func TestDiscoverAWSOrgsWorker_ReturnsDiscoveryError(t *testing.T) {
	f := &fakeOrgReconciler{err: errors.New("org o-1: AccessDenied")}
	err := (&DiscoverAWSOrgsWorker{orgs: f}).Work(context.Background(), &river.Job[DiscoverAWSOrgsArgs]{})
	require.Error(t, err, "a failed discovery fails the job so it is retried and visible")
	require.Equal(t, 1, f.calls)
}

func TestDiscoverAWSOrgsWorker_NothingCreated(t *testing.T) {
	f := &fakeOrgReconciler{}
	require.NoError(t, (&DiscoverAWSOrgsWorker{orgs: f}).Work(context.Background(), &river.Job[DiscoverAWSOrgsArgs]{}))
}
