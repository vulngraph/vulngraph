package jobs

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const enrichFetchBatchSize = enrichWorkers
const enrichFetchQueueSize = 64

type enrichmentFindingReader interface {
	Get(context.Context, string) (finding.Finding, error)
	ByIDs(context.Context, []string) ([]finding.Finding, error)
}

type enrichFetchRequest struct {
	ctx   context.Context
	id    string
	done  chan struct{}
	value finding.Finding
	err   error
}

// enrichFindingFetcher coalesces only worker point reads. It does not cache:
// every caller joins a query that starts after that caller arrived. A waiting
// caller runs the query; there is no background goroutine or shutdown state.
// A batch stays within the existing worker concurrency envelope.
type enrichFindingFetcher struct {
	reader  enrichmentFindingReader
	mu      sync.Mutex
	pending []*enrichFetchRequest
	running bool
	wake    chan struct{}
}

func newEnrichFindingFetcher(reader enrichmentFindingReader) *enrichFindingFetcher {
	return &enrichFindingFetcher{reader: reader, wake: make(chan struct{})}
}

func (g *enrichFindingFetcher) Get(ctx context.Context, id string) (finding.Finding, error) {
	r := &enrichFetchRequest{ctx: ctx, id: id, done: make(chan struct{})}
	queued := false
	for {
		select {
		case <-r.done:
			return r.value, r.err
		default:
		}
		if err := ctx.Err(); err != nil {
			return finding.Finding{}, err
		}
		g.mu.Lock()
		if !queued && len(g.pending) < enrichFetchQueueSize {
			g.pending = append(g.pending, r)
			queued = true
		}
		if len(g.pending) > 0 && !g.running {
			g.running = true
			g.mu.Unlock()
			g.flush()
			continue
		}
		wake := g.wake
		g.mu.Unlock()
		select {
		case <-r.done:
			return r.value, r.err
		case <-ctx.Done():
			return finding.Finding{}, ctx.Err()
		case <-wake:
		}
	}
}

func (g *enrichFindingFetcher) flush() {
	timer := time.NewTimer(2 * time.Millisecond)
	<-timer.C
	g.mu.Lock()
	count := min(len(g.pending), enrichFetchBatchSize)
	requests := g.pending[:count]
	// Copy the remaining slice so later appends cannot overwrite active requests.
	g.pending = append([]*enrichFetchRequest(nil), g.pending[count:]...)
	g.mu.Unlock()
	var active []*enrichFetchRequest
	var ids []string
	for _, r := range requests {
		r.err = r.ctx.Err()
		if r.err == nil {
			active = append(active, r)
			ids = append(ids, r.id)
		}
	}
	if len(active) > 0 {
		values, err := g.read(active[0].ctx, ids)
		for _, r := range active {
			r.err = err
			if err == nil {
				value, found := values[r.id]
				if !found {
					r.err = finding.ErrNotFound
				} else {
					// Duplicate IDs must not share mutable metadata between jobs.
					value.Metadata = maps.Clone(value.Metadata)
					r.value = value
				}
			}
		}
	}
	g.mu.Lock()
	for _, r := range requests {
		close(r.done)
	}
	g.running = false
	close(g.wake)
	g.wake = make(chan struct{})
	g.mu.Unlock()
}

func (g *enrichFindingFetcher) read(ctx context.Context, ids []string) (values map[string]finding.Finding, err error) {
	// Preserve the ordinary finding Get's deadline for grouped reads too.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("enrichment finding read panic: %v", p)
		}
	}()
	if len(ids) == 1 {
		value, err := g.reader.Get(ctx, ids[0])
		if err != nil {
			return nil, fmt.Errorf("enrichment finding: %w", err)
		}
		return map[string]finding.Finding{value.ID: value}, nil
	}
	rows, err := g.reader.ByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("enrichment findings: %w", err)
	}
	values = make(map[string]finding.Finding, len(rows))
	for _, value := range rows {
		values[value.ID] = value
	}
	return values, nil
}
