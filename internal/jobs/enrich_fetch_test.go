package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type batchFindingReader struct {
	read func(context.Context, []string) ([]finding.Finding, error)
}

func (r batchFindingReader) ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error) {
	return r.read(ctx, ids)
}
func (r batchFindingReader) Get(ctx context.Context, id string) (finding.Finding, error) {
	rows, err := r.read(ctx, []string{id})
	if err != nil {
		return finding.Finding{}, err
	}
	if len(rows) == 0 {
		return finding.Finding{}, finding.ErrNotFound
	}
	return rows[0], nil
}

func TestEnrichFetchBatchesBoundedReadsWithoutCaching(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls, biggest, version atomic.Int64
	version.Store(1)
	g := newEnrichFindingFetcher(batchFindingReader{read: func(_ context.Context, ids []string) ([]finding.Finding, error) {
		once.Do(func() { close(entered) })
		<-release
		calls.Add(1)
		for old := biggest.Load(); int64(len(ids)) > old; old = biggest.Load() {
			if biggest.CompareAndSwap(old, int64(len(ids))) {
				break
			}
		}
		var rows []finding.Finding
		for _, id := range ids {
			if id != "missing" {
				rows = append(rows, finding.Finding{ID: id, Title: fmt.Sprint(version.Load()), Metadata: map[string]string{"value": "original"}})
			}
		}
		return rows, nil
	}})
	const total = 80
	results := make(chan error, total)
	for i := range total {
		go func() {
			defer func() {
				if recover() != nil {
					results <- errors.New("reader panic")
				}
			}()
			id := fmt.Sprint(i)
			if i == 0 {
				id = "missing"
			}
			row, err := g.Get(ctx, id)
			if i == 0 && errors.Is(err, finding.ErrNotFound) {
				results <- nil
				return
			}
			if err == nil && (row.ID != id || row.Title != "1") {
				err = errors.New("wrong finding returned")
			}
			results <- err
		}()
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Empty(t, results, "a read must wait for the query result")
	close(release)
	for range total {
		require.NoError(t, <-results)
	}
	require.LessOrEqual(t, biggest.Load(), int64(enrichFetchBatchSize))
	require.Less(t, calls.Load(), int64(total))
	version.Store(2)
	fresh, err := g.Get(ctx, "1")
	require.NoError(t, err)
	require.Equal(t, "2", fresh.Title, "later reads must not reuse a prior result")
}

func TestEnrichFetchDuplicateIDsDoNotShareMetadata(t *testing.T) {
	g := newEnrichFindingFetcher(batchFindingReader{read: func(context.Context, []string) ([]finding.Finding, error) {
		return []finding.Finding{{ID: "same", Metadata: map[string]string{"value": "original"}}}, nil
	}})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	first := &enrichFetchRequest{ctx: ctx, id: "same", done: make(chan struct{})}
	second := &enrichFetchRequest{ctx: ctx, id: "same", done: make(chan struct{})}
	g.pending, g.running = []*enrichFetchRequest{first, second}, true
	g.flush()
	require.NoError(t, first.err)
	require.NoError(t, second.err)
	first.value.Metadata["value"] = "changed"
	require.Equal(t, "original", second.value.Metadata["value"])
}

func TestEnrichFetchRecoversAfterFailureCancellationAndPanic(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	failure := errors.New("read failed")
	reader := batchFindingReader{read: func(context.Context, []string) ([]finding.Finding, error) { return nil, failure }}
	g := newEnrichFindingFetcher(reader)
	_, err := g.Get(ctx, "one")
	require.ErrorIs(t, err, failure)
	dead, stop := context.WithCancel(ctx)
	stop()
	_, err = g.Get(dead, "one")
	require.ErrorIs(t, err, context.Canceled)
	for range enrichFetchQueueSize {
		g.pending = append(g.pending, &enrichFetchRequest{ctx: dead, done: make(chan struct{})})
	}
	reader.read = func(context.Context, []string) ([]finding.Finding, error) { panic("reader failed") }
	g.reader = reader
	_, err = g.Get(ctx, "one")
	require.ErrorContains(t, err, "enrichment finding read panic")
	reader.read = func(context.Context, []string) ([]finding.Finding, error) { return []finding.Finding{{ID: "one"}}, nil }
	g.reader = reader
	row, err := g.Get(ctx, "one")
	require.NoError(t, err)
	require.Equal(t, "one", row.ID)
}
