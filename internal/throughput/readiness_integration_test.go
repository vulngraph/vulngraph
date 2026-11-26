//go:build integration

package throughput

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Container-local probes can see an entrypoint's temporary initialization
// server. Require the same authenticated, host-published connections migrations
// use; retry readiness only, never a partially executed migration.
func waitForStores(ctx context.Context, pgDSN, chDSN string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var lastErr error
	for ctx.Err() == nil {
		probe, stop := context.WithTimeout(ctx, 2*time.Second)
		pool, err := db.NewPool(probe, pgDSN, db.MaxConnsWorker)
		if err == nil {
			pool.Close()
			ch, chErr := db.NewCH(probe, chDSN, 1)
			err = chErr
			if err == nil {
				_ = ch.Close()
				stop()
				return nil
			}
		}
		stop()
		lastErr = err
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("database readiness: %w (last probe: %v)", ctx.Err(), lastErr)
}
