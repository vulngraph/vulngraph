package aws

import (
	"context"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	// eachBoundedConcurrency bounds the per-resource describe calls in flight
	// at once inside one regional collector (the rds_snapshots.go bound, for
	// the same reason).
	eachBoundedConcurrency = 8
	// eachBoundedTimeout bounds one resource's single-page reads, so a hung
	// describe costs that resource's keys rather than the region's budget.
	eachBoundedTimeout = 20 * time.Second
)

// eachBounded calls fn(ctx, i) for i in [0, n) with at most
// eachBoundedConcurrency in flight, each under its own timeout. fn writes
// only state owned by index i, so no lock is needed. A panicking call is
// logged and leaves that index as fn left it: the keys it did not write stay
// absent, which every caller reads as "not observed".
func eachBounded(ctx context.Context, n int, timeout time.Duration, what string, fn func(ctx context.Context, i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, eachBoundedConcurrency)
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Any("panic", rec).Str("call", what).Int("index", i).
						Msg("per-resource read panicked; that resource's settings are unknown this sweep")
				}
			}()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			fn(cctx, i)
		}()
	}
	wg.Wait()
}
