package jobs

import (
	"context"
	"sync"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// correlateCoalesceInterval bounds how long a changed-ID can sit in the
// buffer before it goes out. Sync completions arrive in bursts — syncWorkers
// (20) each finish their own connector sweep independently, so up to 20 calls
// to enqueuePartialCorrelate can land within the same second or two. 5s is
// short enough that "immediately after a sync" still reads as immediate, but
// long enough that a whole burst reliably lands inside one window rather than
// spilling across two ticks.
const correlateCoalesceInterval = 5 * time.Second

// correlateCoalesceFlushTimeout bounds one flush's queue-depth check plus its
// Insert, on a context detached from whatever triggered the flush (a tick, a
// size threshold, or shutdown) — same reasoning as recordSyncTimeout: the
// flush must survive outliving the sync job whose completion happened to
// trigger it, and must still complete promptly during the shutdown drain.
const correlateCoalesceFlushTimeout = 10 * time.Second

// correlateBuffer is the pure accumulate/drain half of the coalescer: no
// River, no context, no time — so it gets exhaustive table + concurrency
// tests without faking any infra. Every method is mutex-guarded and safe for
// concurrent use.
type correlateBuffer struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

func newCorrelateBuffer() *correlateBuffer {
	return &correlateBuffer{ids: make(map[string]struct{})}
}

// add merges changedIDs into the buffer (deduplicating, same as the map the
// old per-call code built from changedAssetIDs) and returns the buffer's size
// AFTER the merge, so the caller can decide whether the size-threshold flush
// trigger has been crossed. add never loses an ID; it stays in the buffer
// until drain empties it.
func (b *correlateBuffer) add(changedIDs []string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, id := range changedIDs {
		b.ids[id] = struct{}{}
	}
	return len(b.ids)
}

// drain empties the buffer and returns everything it held, in no particular
// order. nil (not an error) is the correct "nothing to flush" signal here —
// this is a size on an in-process map with no failure path, not evidence
// a decision depends on (the known-ness rule for evidence doesn't apply).
func (b *correlateBuffer) drain() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(b.ids))
	for id := range b.ids {
		out = append(out, id)
	}
	b.ids = make(map[string]struct{})
	return out
}

// jobInserter is the one river.Client method flush needs beyond jobLister —
// narrowed the same way jobLister itself is, so flush is unit-testable
// without a live Postgres pool.
type jobInserter interface {
	Insert(ctx context.Context, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

// correlateClient is jobInserter+jobLister together — exactly what
// RunCorrelateCoalescer's flush loop needs, narrowed so the loop itself is
// unit-testable with a fake rather than requiring a live *river.Client (which
// needs a real Postgres pool to construct). *river.Client[pgx.Tx] satisfies
// this structurally.
type correlateClient interface {
	jobInserter
	jobLister
}

// correlateCoalescer batches enqueuePartialCorrelate calls across a short
// window so a burst of sync completions produces a small number of
// partial-correlate jobs covering the union of their changed IDs, instead of
// one job per completion.
//
// Best-effort: an accepted ID goes out on the next tick, an earlier
// size-triggered flush, or the shutdown drain. It is dropped under
// correlateQueueMax backpressure, when a chunk's Insert fails (logged at
// Error), or if the process dies before a flush. The periodic full correlate
// (defaultCorrelateInterval) and the boot sweep cover all three. flush() also
// chunks the drained set at maxPartialCorrelateIDs
// so a large burst produces multiple smaller jobs rather than one oversized
// IN-clause.
type correlateCoalescer struct {
	buf      *correlateBuffer
	flushNow chan struct{}
}

func newCorrelateCoalescer() *correlateCoalescer {
	return &correlateCoalescer{buf: newCorrelateBuffer(), flushNow: make(chan struct{}, 1)}
}

// partialCorrelateCoalescer is the process-wide buffer enqueuePartialCorrelate
// feeds. A package-level singleton (in the style of uniqueStates,
// reindexerSchedule) rather than a field threaded through SyncWorker: up to
// syncWorkers (20) concurrent SyncWorker.Work calls need to share exactly one
// buffer, and the flush loop that drains it (RunCorrelateCoalescer) is
// started exactly once per process from cmd/graph/worker.go, which has the
// *river.Client[pgx.Tx] this package's own worker construction does not yet
// have at the point SyncWorker is registered (see NewClient: workers are
// built before the client that would wrap them exists).
var partialCorrelateCoalescer = newCorrelateCoalescer()

// Add accumulates changedIDs and, if the buffer has now crossed
// maxPartialCorrelateIDs, nudges the flush loop to drain immediately instead
// of waiting out the rest of the tick — otherwise a large burst could grow
// the buffer unboundedly between ticks. The nudge is best-effort-non-blocking
// (buffered size 1, dropped if already pending): a dropped nudge never loses
// an ID, it only means the next regular tick (at most correlateCoalesceInterval
// away) does the flush instead of it happening a few seconds sooner.
func (c *correlateCoalescer) Add(changedIDs []string) {
	if c.buf.add(changedIDs) >= maxPartialCorrelateIDs {
		select {
		case c.flushNow <- struct{}{}:
		default:
		}
	}
}

// flush drains the buffer and, if it held anything, enqueues one
// CorrelateArgs job per maxPartialCorrelateIDs-sized chunk of the union —
// after checking the same correlateQueueMax backpressure
// enqueuePartialCorrelate always checked (see the type doc).
//
// The backpressure check runs ONCE per flush, not once per chunk: at or over
// correlateQueueMax the whole drained batch is dropped (not partially
// enqueued), the same "drop under backpressure, the full sweep is the
// backstop" semantics as an uncoalesced enqueue — coalescing only changes how
// big a batch one drop covers. Chunking drops no ID: it is pure slicing of
// an already-drained slice. A chunk whose Insert fails is logged and not
// re-queued.
func (c *correlateCoalescer) flush(ctx context.Context, client jobInserter, lister jobLister) {
	ids := c.buf.drain()
	if len(ids) == 0 {
		return
	}
	logger := log.FromContext(ctx)
	if depth, err := correlateQueueDepth(ctx, lister); err == nil && depth >= correlateQueueMax {
		logger.Warn().Int("queue_depth", depth).Int("coalesced_ids", len(ids)).
			Msg("coalesced partial correlate skipped — correlate queue at capacity; full sweep will cover")
		return
	}
	chunks := chunkIDs(ids, maxPartialCorrelateIDs)
	for i, chunk := range chunks {
		if _, err := client.Insert(ctx, CorrelateArgs{ChangedIDs: chunk}, nil); err != nil {
			logger.Error().Err(err).
				Int("chunk", i+1).Int("chunks_total", len(chunks)).
				Int("chunk_ids", len(chunk)).Int("total_coalesced_ids", len(ids)).
				Msg("coalesced partial correlate chunk enqueue failed")
		}
	}
}

// chunkIDs splits ids into slices of at most size elements each, preserving
// every element (the last chunk holds the remainder). size <= 0 is treated
// as "no splitting" — one chunk holding everything — since flush always
// calls this with the positive maxPartialCorrelateIDs constant; the guard
// only exists so a future caller with a bad size fails obviously instead of
// looping forever.
func chunkIDs(ids []string, size int) [][]string {
	if size <= 0 || len(ids) <= size {
		return [][]string{ids}
	}
	chunks := make([][]string, 0, (len(ids)+size-1)/size)
	for i := 0; i < len(ids); i += size {
		end := i + size
		if end > len(ids) {
			end = len(ids)
		}
		chunks = append(chunks, ids[i:end])
	}
	return chunks
}

// RunCorrelateCoalescer drives the package-level partial-correlate
// coalescer's flush loop until stop is closed. It ticks every
// correlateCoalesceInterval, or sooner when Add signals a size-threshold
// crossing, draining whatever enqueuePartialCorrelate has accumulated into
// one or more CorrelateArgs jobs per flush.
//
// stop is deliberately NOT the root shutdown ctx: River's SoftStopTimeout
// keeps an in-flight SyncWorker.Work call running on a detached context for
// a grace period after the root ctx is cancelled, and it can still call Add
// during that window. If this loop stopped on the root ctx instead, it would
// flush and return before that grace window even starts, and any later Add
// would write into a buffer nobody ever drains again. stop must only close
// AFTER the caller has waited for every in-flight job to finish (i.e. after
// client.Stop returns) — see cmd/graph/worker.go's shutdown sequence.
//
// On stop closing, this performs exactly one more synchronous flush (on a
// context derived from ctx, used only for logging/query context here) so a
// batch buffered during the shutdown grace window still reaches the
// correlate queue, then returns. Start it with safego like other
// worker-owned background loops; it does not manage its own panic recovery.
//
// client is the SAME *river.Client[pgx.Tx] the worker runs job execution
// through, passed explicitly rather than pulled from ctx, since this loop is
// not itself a job invocation.
func RunCorrelateCoalescer(ctx context.Context, stop <-chan struct{}, client correlateClient) {
	c := partialCorrelateCoalescer
	ticker := time.NewTicker(correlateCoalesceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), correlateCoalesceFlushTimeout)
			c.flush(flushCtx, client, client)
			cancel()
			return
		case <-ticker.C:
			flushOnTick(ctx, c, client)
		case <-c.flushNow:
			flushOnTick(ctx, c, client)
		}
	}
}

// flushOnTick bounds one non-final flush with its own timeout, on a context
// detached from ctx (context.WithoutCancel) — same as the final, stop-
// triggered flush, and for the same reason: ctx is cancelled immediately at
// SIGTERM, but this loop keeps ticking/flushNow-ing for up to
// workerSoftStopTimeout afterwards (stop hasn't closed yet — see
// RunCorrelateCoalescer's doc). A tick or size-threshold flush landing inside
// that window must not hand the already-cancelled ctx to correlateQueueDepth
// / Insert: flush() drains the buffer BEFORE inserting, so a doomed,
// cancelled-context Insert would lose those IDs outright rather than merely
// deferring them to the final flush.
func flushOnTick(ctx context.Context, c *correlateCoalescer, client correlateClient) {
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), correlateCoalesceFlushTimeout)
	defer cancel()
	c.flush(flushCtx, client, client)
}
