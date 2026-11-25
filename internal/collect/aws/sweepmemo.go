package aws

import (
	"context"
	"fmt"
	"sync"
)

// sweepMemoKey carries a sweep's *sweepMemo on the context.
type sweepMemoKey struct{}

// sweepMemo shares one listing between the collectors of a sweep that each
// need it — the REST and HTTP API lists feed both the API and the stage
// collectors, the Auto Scaling group list feeds both the group and the
// launch-template collectors — so each listing is fetched once per region
// rather than once per consumer. It lives on the Collect call's context
// (withConfigCache), so nothing outlives the sweep.
type sweepMemo struct {
	mu      sync.Mutex
	entries map[string]*memoEntry
}

type memoEntry struct {
	once sync.Once
	val  any
	err  error
}

// memoized returns fn's result for key, running fn once per sweep however
// many collectors ask concurrently. The error is shared too: every consumer
// of a failed listing fails the same way, rather than one retrying into a
// different answer. Without a sweep memo on ctx (unit tests) fn simply runs.
func memoized[T any](ctx context.Context, key string, fn func() (T, error)) (T, error) {
	m, _ := ctx.Value(sweepMemoKey{}).(*sweepMemo)
	if m == nil {
		return fn()
	}
	m.mu.Lock()
	if m.entries == nil {
		m.entries = map[string]*memoEntry{}
	}
	e, ok := m.entries[key]
	if !ok {
		e = &memoEntry{}
		m.entries[key] = e
	}
	m.mu.Unlock()
	e.once.Do(func() {
		// A panic still marks the Once done; record it as the listing's
		// error so no later consumer reads the zero value as an empty list.
		defer func() {
			if rec := recover(); rec != nil {
				e.err = fmt.Errorf("memoized %s: panic: %v", key, rec)
			}
		}()
		e.val, e.err = fn()
	})
	v, _ := e.val.(T)
	return v, e.err
}
