package aws

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoizedRunsOncePerSweep(t *testing.T) {
	ctx := withConfigCache(context.Background())
	var calls atomic.Int32
	fn := func() ([]string, error) {
		calls.Add(1)
		return []string{"a"}, nil
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := memoized(ctx, "k", fn)
			require.NoError(t, err)
			require.Equal(t, []string{"a"}, got)
		}()
	}
	wg.Wait()
	require.Equal(t, int32(1), calls.Load(), "concurrent consumers share one listing")

	_, _ = memoized(ctx, "other", fn)
	require.Equal(t, int32(2), calls.Load(), "a different key is a different listing")

	_, _ = memoized(withConfigCache(context.Background()), "k", fn)
	require.Equal(t, int32(3), calls.Load(), "a new sweep starts empty")

	_, _ = memoized(context.Background(), "k", fn)
	_, _ = memoized(context.Background(), "k", fn)
	require.Equal(t, int32(5), calls.Load(), "without a sweep memo every call runs")
}

func TestMemoizedSharesFailures(t *testing.T) {
	ctx := withConfigCache(context.Background())
	_, err := memoized(ctx, "k", func() ([]string, error) { return nil, errors.New("throttled") })
	require.Error(t, err)
	got, err := memoized(ctx, "k", func() ([]string, error) { return []string{"late"}, nil })
	require.Error(t, err, "every consumer of a failed listing fails the same way")
	require.Nil(t, got)

	_, err = memoized(ctx, "boom", func() ([]string, error) { panic("bad page") })
	require.Error(t, err)
	got, err = memoized(ctx, "boom", func() ([]string, error) { return []string{"x"}, nil })
	require.Error(t, err, "a panicked listing must not read as an empty one")
	require.Nil(t, got)
}
