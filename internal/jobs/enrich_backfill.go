package jobs

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Snoozing releases the worker slot and persists the next check in River.
// One singleton can keep a deferred backlog moving without waiting for the
// periodic drift sweep, spawning a goroutine or removing queue backpressure.
const enrichBackfillDelay = 2 * time.Second

func enqueueDeferredBackfill(ctx context.Context) {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return
	}
	if _, err := client.Insert(ctx, EnrichSweepArgs{BackfillOnly: true}, nil); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("deferred enrichment wake-up failed; periodic sweep will retry")
	}
}
