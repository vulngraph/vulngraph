package gcp

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// fanOutLimit bounds concurrent per-resource reads (per location, per key
// ring, per dataset) within one collection family.
const fanOutLimit = 8

// fanOut runs fn for every item with at most fanOutLimit in flight and joins
// their errors. A panicking item is logged and reported as an error, so the
// family is flagged partial rather than crashing the sweep. fn must guard
// any state it shares with other items.
func fanOut[T any](ctx context.Context, what string, items []T, fn func(T) error) error {
	var (
		wg   sync.WaitGroup
		sem  = make(chan struct{}, fanOutLimit)
		mu   sync.Mutex
		errs []error
	)
	for _, item := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(item T) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Any("panic", rec).Msg(what + " read panicked; item omitted")
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s: panic: %v", what, rec))
					mu.Unlock()
				}
			}()
			if err := fn(item); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(item)
	}
	wg.Wait()
	return errors.Join(errs...)
}
