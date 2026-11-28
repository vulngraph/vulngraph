package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type sweepCacheWithPruner struct{ *fakeEnrichCache }

func (*sweepCacheWithPruner) PruneAlertStates(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func TestEnrichSweepConstructorPreservesCacheDependencies(t *testing.T) {
	cache := &sweepCacheWithPruner{newFakeEnrichCache()}
	worker := newEnrichSweepWorker(fakeLister{}, cache)
	require.Same(t, cache, worker.progress)
	require.Same(t, cache, worker.alerts)
	require.NotNil(t, worker.findings)
	uncached := newEnrichSweepWorker(fakeLister{}, nil)
	require.Nil(t, uncached.progress)
	require.Nil(t, uncached.alerts)
}
