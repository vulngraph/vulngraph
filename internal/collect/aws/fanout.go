package aws

import (
	"errors"
	"fmt"
	"sync"
)

// forEachBounded runs fn(i) for every i in [0, n) with at most limit calls in
// flight, and returns every error they reported (a panic is converted to one).
// It is the per-resource fan-out shape the regional collectors use for
// describe-per-item APIs: bounded so one region's describes never exceed the
// limit, and complete — the caller learns about every item that failed, not
// only the first.
func forEachBounded(n, limit int, fn func(i int) error) error {
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
		sem  = make(chan struct{}, max(limit, 1))
	)
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					mu.Lock()
					errs = append(errs, fmt.Errorf("forEachBounded: item %d panicked: %v", i, rec))
					mu.Unlock()
				}
			}()
			if err := fn(i); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	return errors.Join(errs...)
}
