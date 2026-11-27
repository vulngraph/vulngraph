package db

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSingleBatcherWaitsForCommitAndBoundsBatches(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, commit := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var rows, calls, biggest, returned atomic.Int64
	g := &singleBatcher{wake: make(chan struct{}), write: func(_ context.Context, writes []*singleWrite) error {
		once.Do(func() { close(entered) })
		<-commit
		rows.Add(int64(len(writes)))
		calls.Add(1)
		for prior := biggest.Load(); int64(len(writes)) > prior; prior = biggest.Load() {
			if biggest.CompareAndSwap(prior, int64(len(writes))) {
				break
			}
		}
		return nil
	}}
	const total = 200
	results := make(chan error, total)
	for range total {
		go func() {
			defer func() {
				if p := recover(); p != nil {
					results <- errors.New("writer panic")
				}
			}()
			err := g.submit(ctx, 1, nil)
			returned.Add(1)
			results <- err
		}()
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Zero(t, returned.Load(), "queued writes cannot report success before commit")
	close(commit)
	for range total {
		require.NoError(t, <-results)
	}
	require.EqualValues(t, total, rows.Load())
	require.Less(t, calls.Load(), int64(total), "concurrent rows should share native inserts")
	require.LessOrEqual(t, biggest.Load(), int64(singleBatchLimit))
}

func TestSingleBatcherFailureAndCancellationRecover(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	failure := errors.New("database write failed")
	g := &singleBatcher{wake: make(chan struct{}), write: func(context.Context, []*singleWrite) error { return failure }}
	require.ErrorIs(t, g.submit(ctx, 1, nil), failure)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	require.ErrorIs(t, g.submit(cancelled, 1, nil), context.Canceled)
	// A recovered backend and a prior panic must leave the next caller usable.
	g.write = func(context.Context, []*singleWrite) error { panic("broken append") }
	require.ErrorContains(t, g.submit(ctx, 1, nil), "coalesced insert panic")
	g.write = func(context.Context, []*singleWrite) error { return nil }
	require.NoError(t, g.submit(ctx, 1, nil))
}

func TestSingleBatcherReclaimsCancelledFullQueue(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	dead, stop := context.WithCancel(ctx)
	stop()
	g := &singleBatcher{wake: make(chan struct{}), write: func(_ context.Context, rows []*singleWrite) error {
		require.Len(t, rows, 1, "cancelled queued rows must not be written")
		return nil
	}}
	for range singleBatchLimit {
		g.pending = append(g.pending, &singleWrite{ctx: dead, done: make(chan struct{})})
	}
	g.bytes = singleBatchBytes
	require.NoError(t, g.submit(ctx, 1, nil), "a new caller must reclaim a full abandoned queue")
}

func TestSingleBatcherBoundsWidePayloadsAndFansOutFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	failure := errors.New("send failed")
	var rows atomic.Int64
	g := &singleBatcher{wake: make(chan struct{}), write: func(_ context.Context, writes []*singleWrite) error {
		total := 0
		for _, w := range writes {
			total += w.bytes
		}
		if total > singleBatchBytes {
			return errors.New("byte limit exceeded")
		}
		rows.Add(int64(len(writes)))
		return failure
	}}
	const total = 40
	results := make(chan error, total)
	for range total {
		go func() {
			defer func() {
				if recover() != nil {
					results <- errors.New("writer panic")
				}
			}()
			results <- g.submit(ctx, 1<<20+1, nil)
		}()
	}
	for range total {
		require.ErrorIs(t, <-results, failure)
	}
	require.EqualValues(t, total, rows.Load(), "every failed row must receive the backend error")
}
