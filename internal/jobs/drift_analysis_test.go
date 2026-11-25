package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
)

type stubDriftAnalyst struct{}

func (stubDriftAnalyst) AnalyzeDrift(context.Context, driftanalysis.AnalysisInput) (driftanalysis.Verdict, error) {
	return driftanalysis.Verdict{}, nil
}

// enabledDriftService is a service whose Enabled() is true; the jobs tests that
// use it never call into storage.
func enabledDriftService() *driftanalysis.Service {
	return driftanalysis.New(nil, stubDriftAnalyst{}, nil)
}

// fakeDriftSvc records calls and, in DiscoverBatches, runs the enqueue func the
// way the repo does: once per created batch, inside its transaction.
type fakeDriftSvc struct {
	tx          any
	discovered  []driftanalysis.Batch
	discoverErr error
	requeue     []driftanalysis.Batch
	requeueErr  error
	pruneErr    error
	enqueueErr  error
	analyzed    []string
	analyzeErr  error
	pruned      bool
}

func (f *fakeDriftSvc) DiscoverBatches(ctx context.Context, enqueue driftanalysis.EnqueueFunc) ([]driftanalysis.Batch, error) {
	for _, b := range f.discovered {
		if err := enqueue(ctx, f.tx, b); err != nil {
			f.enqueueErr = err
		}
	}
	return f.discovered, f.discoverErr
}

func (f *fakeDriftSvc) Analyze(_ context.Context, id string) error {
	f.analyzed = append(f.analyzed, id)
	return f.analyzeErr
}

func (f *fakeDriftSvc) Requeue(context.Context) ([]driftanalysis.Batch, error) {
	return f.requeue, f.requeueErr
}

func (f *fakeDriftSvc) Prune(context.Context) (int64, error) {
	f.pruned = true
	return 3, f.pruneErr
}

type fakeInserter struct {
	inTx    []string
	outOfTx []string
	txErr   error
}

func (f *fakeInserter) insertTx(_ context.Context, _ pgx.Tx, id string) error {
	f.inTx = append(f.inTx, id)
	return f.txErr
}

func (f *fakeInserter) insert(_ context.Context, id string) error {
	f.outOfTx = append(f.outOfTx, id)
	return nil
}

// fakeTx satisfies pgx.Tx only by embedding; no method is called.
type fakeTx struct{ pgx.Tx }

func TestDriftSweep_DiscoversEnqueuesInTxRequeuesAndPrunes(t *testing.T) {
	svc := &fakeDriftSvc{
		tx:         fakeTx{},
		discovered: []driftanalysis.Batch{{ID: "new1"}, {ID: "new2"}},
		requeue:    []driftanalysis.Batch{{ID: "old1"}},
	}
	ins := &fakeInserter{}
	w := &DriftSweepWorker{svc: svc, inserts: ins}

	require.NoError(t, w.Work(t.Context(), &river.Job[DriftSweepArgs]{}))

	assert.Equal(t, []string{"new1", "new2"}, ins.inTx, "new batches are enqueued in the discovery transaction")
	assert.Equal(t, []string{"old1"}, ins.outOfTx, "lost batches are re-enqueued on their own")
	assert.True(t, svc.pruned)
	require.NoError(t, svc.enqueueErr)
}

func TestDriftSweep_NonPgxTxFailsTheEnqueue(t *testing.T) {
	svc := &fakeDriftSvc{tx: "not a tx", discovered: []driftanalysis.Batch{{ID: "b"}}}
	ins := &fakeInserter{}
	w := &DriftSweepWorker{svc: svc, inserts: ins}

	require.NoError(t, w.Work(t.Context(), &river.Job[DriftSweepArgs]{}))

	require.ErrorContains(t, svc.enqueueErr, "want pgx.Tx")
	assert.Empty(t, ins.inTx, "no job is inserted without a pgx transaction")
}

func TestDriftSweep_OneFailureDoesNotSkipTheRest(t *testing.T) {
	boom := errors.New("boom")
	svc := &fakeDriftSvc{
		discoverErr: boom,
		requeue:     []driftanalysis.Batch{{ID: "old1"}},
	}
	ins := &fakeInserter{}
	w := &DriftSweepWorker{svc: svc, inserts: ins}

	err := w.Work(t.Context(), &river.Job[DriftSweepArgs]{})

	require.ErrorIs(t, err, boom, "the failure is reported so River retries")
	assert.Equal(t, []string{"old1"}, ins.outOfTx, "requeue still runs")
	assert.True(t, svc.pruned, "prune still runs")
}

func TestDriftAnalyze_CallsServiceWithTheBatchID(t *testing.T) {
	svc := &fakeDriftSvc{}
	w := &DriftAnalyzeWorker{svc: svc}
	job := &river.Job[DriftAnalyzeArgs]{Args: DriftAnalyzeArgs{BatchID: "b1"}}

	require.NoError(t, w.Work(t.Context(), job))
	require.NoError(t, w.Work(t.Context(), job), "a second run of the same batch is harmless")

	assert.Equal(t, []string{"b1", "b1"}, svc.analyzed)
}

func TestDriftAnalyze_ReturnsServiceError(t *testing.T) {
	boom := errors.New("boom")
	w := &DriftAnalyzeWorker{svc: &fakeDriftSvc{analyzeErr: boom}}

	err := w.Work(t.Context(), &river.Job[DriftAnalyzeArgs]{Args: DriftAnalyzeArgs{BatchID: "b1"}})

	require.ErrorIs(t, err, boom)
}

func TestDriftAnalyzeArgs_UniqueByBatch(t *testing.T) {
	opts := DriftAnalyzeArgs{BatchID: "b"}.InsertOpts()
	assert.Equal(t, queueDrift, opts.Queue)
	assert.Equal(t, 2, opts.MaxAttempts)
	assert.True(t, opts.UniqueOpts.ByArgs)
	assert.Equal(t, uniqueStates, opts.UniqueOpts.ByState)
	assert.Equal(t, driftAnalyzeTimeout, (&DriftAnalyzeWorker{}).Timeout(nil))
}

func TestDriftAnalysisOff_NoWorkerAndNoPeriodic(t *testing.T) {
	for name, deps := range map[string]Deps{
		"nil service":      {},
		"disabled service": {DriftAnalysis: driftanalysis.New(nil, nil, nil)},
	} {
		t.Run(name, func(t *testing.T) {
			assert.False(t, deps.driftAnalysisOn())
			assert.False(t, deps.periodicConfig().DriftAnalysis)
		})
	}
	assert.True(t, Deps{DriftAnalysis: enabledDriftService()}.driftAnalysisOn())
}

func TestDriftSweepIsScheduledEveryFiveMinutesWithoutRunOnStart(t *testing.T) {
	args, _, runOnStart := periodicByKind(t, buildPeriodicJobs(PeriodicConfig{DriftAnalysis: true}), DriftSweepArgs{}.Kind())
	require.NotNil(t, args)
	assert.False(t, runOnStart)
	assert.Equal(t, 5*time.Minute, driftSweepInterval)

	off, _, _ := periodicByKind(t, buildPeriodicJobs(PeriodicConfig{}), DriftSweepArgs{}.Kind())
	assert.Nil(t, off, "switched off means no periodic")
}
