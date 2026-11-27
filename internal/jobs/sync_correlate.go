// Partial-correlate enqueueing for the sync worker: after a sweep writes
// changed assets, this triggers a targeted correlate instead of waiting for the
// 30-min full sweep, backpressured against the correlate queue's own depth.
// Kept out of sync.go, under the file-length ceiling, as its own cohesive unit
// alongside the deletion-scoping code in sync_deletion_scope.go.
//
// The enqueue itself is a buffer merge, not an Insert — see
// correlate_coalescer.go, which owns the flush.
package jobs

import (
	"context"
	"fmt"

	"github.com/riverqueue/river"
)

// An analysis work unit can share one complete context across many changes.
// The repository separately limits each seed query to 200 IDs. The byte bound
// is a conservative JSON-escaped argument charge, not decoded asset memory.
const maxPartialCorrelateIDs = 10_000
const maxPartialCorrelateBytes = 1 << 20

// correlateQueueMax caps queued jobs, not proportional work. Refused or lost
// enqueues require a successful later full sweep; elapsed time is not coverage.
const correlateQueueMax = 500

// correlateQueueDepth measures the correlate backlog, capped at
// correlateQueueMax+1 (deeper than the cap all reads the same).
func correlateQueueDepth(ctx context.Context, client jobLister) (int, error) {
	list, err := client.JobList(ctx, river.NewJobListParams().Queues(queueCorrelate).
		States(uniqueStates...).First(correlateQueueMax+1))
	if err != nil {
		return 0, fmt.Errorf("correlateQueueDepth: %w", err)
	}
	return len(list.Jobs), nil
}

// enqueuePartialCorrelate feeds the given changed asset IDs into the
// process-wide partial-correlate coalescer (correlate_coalescer.go) instead of
// enqueueing a River job directly. A burst of connector syncs completing
// together each call this; the coalescer batches all of them into one or more
// CorrelateArgs jobs — chunked at maxPartialCorrelateIDs each — covering the
// union of changed IDs per correlateCoalesceInterval, rather than one job per
// sync completion landing on the single-worker correlate queue.
//
// Takes no context: Add() is a pure in-memory buffer merge (correlateBuffer).
// Any I/O this batch eventually causes happens later inside flush(), on its
// own context detached from whichever sync happened to trigger it (see
// RunCorrelateCoalescer) — a context accepted here would describe the wrong
// operation's lifetime. flush()'s own logging carries the per-chunk detail
// (chunk index, size, total coalesced IDs).
//
// Best-effort across process crashes. Failed enqueues retain a bounded full
// request for retry; recovery still requires a successful sweep.
func enqueuePartialCorrelate(changedIDs []string) {
	partialCorrelateCoalescer.Add(changedIDs)
}
