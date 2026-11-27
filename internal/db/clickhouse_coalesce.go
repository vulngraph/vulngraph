package db

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const singleBatchLimit = 64
const singleBatchBytes = 4 << 20

type singleWrite struct {
	ctx    context.Context
	bytes  int
	append func(driver.Batch) error
	done   chan struct{}
	err    error
}

// singleBatcher has no background goroutine. A waiting caller flushes one batch,
// then wakes the others to elect the next caller. Both pending work and the
// coalescing window are bounded; callers return success only after Batch.Send.
type singleBatcher struct {
	mu      sync.Mutex
	pending []*singleWrite
	bytes   int
	running bool
	wake    chan struct{}
	write   func(context.Context, []*singleWrite) error
}

// BatchSingle coalesces concurrent single-row writes to the same INSERT query.
// append must add exactly one row. Larger writes must use Batch directly.
// Cancellation before flushing skips that row; an already-prepared batch has
// Batch's usual bounded completion semantics. There is no asynchronous success.
func (c *CH) BatchSingle(ctx context.Context, query string, estimatedBytes int, appendRow func(driver.Batch) error) error {
	if estimatedBytes > singleBatchBytes {
		return c.Batch(ctx, query, appendRow)
	}
	c.singleMu.Lock()
	if c.single == nil {
		c.single = map[string]*singleBatcher{}
	}
	g := c.single[query]
	if g == nil {
		g = &singleBatcher{wake: make(chan struct{}), write: func(ctx context.Context, writes []*singleWrite) error {
			return c.Batch(ctx, query, func(b driver.Batch) error {
				for _, w := range writes {
					if err := w.append(b); err != nil {
						return err
					}
				}
				return nil
			})
		}}
		c.single[query] = g
	}
	c.singleMu.Unlock()
	return g.submit(ctx, max(estimatedBytes, 1), appendRow)
}

func (g *singleBatcher) submit(ctx context.Context, bytes int, appendRow func(driver.Batch) error) error {
	r := &singleWrite{ctx: ctx, bytes: bytes, append: appendRow, done: make(chan struct{})}
	queued := false
	for {
		select {
		case <-r.done:
			return r.err
		default:
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		g.mu.Lock()
		if !queued && len(g.pending) < singleBatchLimit && g.bytes+bytes <= singleBatchBytes {
			g.pending = append(g.pending, r)
			g.bytes += bytes
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
			return r.err
		case <-ctx.Done():
			return ctx.Err()
		case <-wake:
		}
	}
}

func (g *singleBatcher) flush() {
	timer := time.NewTimer(2 * time.Millisecond)
	<-timer.C
	g.mu.Lock()
	writes := g.pending
	g.pending = nil
	g.bytes = 0
	g.mu.Unlock()
	active := make([]*singleWrite, 0, len(writes))
	for _, w := range writes {
		w.err = w.ctx.Err()
		if w.err == nil {
			active = append(active, w)
		}
	}
	var err error
	if len(active) > 0 {
		err = func() (err error) {
			defer func() {
				if p := recover(); p != nil {
					err = fmt.Errorf("coalesced insert panic: %v", p)
				}
			}()
			return g.write(active[0].ctx, active)
		}()
	}
	for _, w := range active {
		w.err = err
	}
	g.mu.Lock()
	for _, w := range writes {
		close(w.done)
	}
	g.running = false
	close(g.wake)
	g.wake = make(chan struct{})
	g.mu.Unlock()
}
