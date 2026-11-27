package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Inspect buffered invalidations every five seconds. While the analysis lane
// is busy, share one bounded union instead of queuing another global replay.
const correlateCoalesceInterval = 5 * time.Second

// Persist even a low-rate partial after one minute of busy-lane buffering.
// This bounds admission delay, not queue completion or source freshness.
const correlateCoalesceMaxWait = time.Minute

// correlateCoalesceFlushTimeout bounds one flush's queue-depth check plus its
// Insert, on a context detached from whatever triggered the flush (a tick, a
// size threshold, or shutdown) — same reasoning as recordSyncTimeout: the
// flush must survive outliving the sync job whose completion happened to
// trigger it, and must still complete promptly during the shutdown drain.
const correlateCoalesceFlushTimeout = 10 * time.Second

// Buffer invalidations only until the next flush. A large union promotes to a
// full follow-up request instead of retaining unbounded IDs or creating many
// jobs that each reload the same global context.
type correlateBuffer struct {
	mu     sync.Mutex
	ids    map[string]struct{}
	bytes  int
	full   bool
	oldest time.Time
}

func newCorrelateBuffer() *correlateBuffer { return &correlateBuffer{ids: make(map[string]struct{})} }
func (b *correlateBuffer) add(ids []string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.addLocked(ids)
}
func (b *correlateBuffer) addLocked(ids []string) int {
	if len(ids) > 0 && b.oldest.IsZero() {
		b.oldest = time.Now()
	}
	for _, id := range ids {
		if b.full {
			return maxPartialCorrelateIDs
		}
		if _, ok := b.ids[id]; ok {
			continue
		}
		if len(b.ids) >= maxPartialCorrelateIDs || b.bytes+correlateIDBytes(id)+32 > maxPartialCorrelateBytes {
			b.full = true
			b.ids = make(map[string]struct{})
			b.bytes = 0
			return maxPartialCorrelateIDs
		}
		b.ids[id] = struct{}{}
		b.bytes += correlateIDBytes(id)
	}
	return len(b.ids)
}
func (b *correlateBuffer) restore(ids []string, full bool, oldest time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !oldest.IsZero() && (b.oldest.IsZero() || oldest.Before(b.oldest)) {
		b.oldest = oldest
	}
	if full {
		b.full = true
		b.ids = make(map[string]struct{})
		b.bytes = 0
	} else {
		b.addLocked(ids)
	}
}
func (b *correlateBuffer) drain() ([]string, bool, time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var ids []string
	for id := range b.ids {
		ids = append(ids, id)
	}
	full, oldest := b.full, b.oldest
	b.full = false
	b.oldest = time.Time{}
	b.bytes = 0
	b.ids = make(map[string]struct{})
	return ids, full, oldest
}
func (b *correlateBuffer) state() (int, bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var age time.Duration
	if !b.oldest.IsZero() {
		age = time.Since(b.oldest)
	}
	return len(b.ids), b.full, age
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

// correlateCoalescer shares complete analysis across a short burst of changes.
// Enqueue failures retain a bounded full-needed flag for the next flush. Process
// death can still lose buffered invalidations; a successful boot/periodic sweep
// is the recovery path, not a promise that the next sweep will succeed.
type correlateCoalescer struct {
	buf      *correlateBuffer
	flushNow chan struct{}
	flushing atomic.Int32
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

// flush schedules one bounded partial, or a full follow-up for a large union.
// A pending full job can cover writes committed before this lookup; a RUNNING
// full job may already have captured its source and must never absorb them.
func (c *correlateCoalescer) flush(ctx context.Context, client jobInserter, lister jobLister) {
	c.flushWithAdmission(ctx, client, lister, false)
}
func (c *correlateCoalescer) flushWithAdmission(ctx context.Context, client jobInserter, lister jobLister, force bool) {
	c.flushing.Add(1)
	defer c.flushing.Add(-1)
	ids, full, oldest := c.buf.drain()
	if len(ids) == 0 && !full {
		return
	}
	logger := log.FromContext(ctx)
	if !full {
		depth, err := correlateQueueDepth(ctx, lister)
		if err != nil {
			c.buf.restore(nil, true, oldest)
			logger.Error().Err(err).Msg("correlate depth unknown; full follow-up retained")
			return
		}
		full = depth >= correlateQueueMax
		if depth > 0 && !full && !force {
			covered, err := pendingFullCorrelate(ctx, lister)
			if err != nil {
				c.buf.restore(nil, true, oldest)
				logger.Error().Err(err).Msg("pending full coverage unknown; retained")
				return
			}
			if covered {
				return
			}
			if time.Since(oldest) < correlateCoalesceMaxWait {
				c.buf.restore(ids, false, oldest)
				return
			}
		}
	}
	if full {
		if err := enqueueCorrelateFollowup(ctx, client, lister); err != nil {
			c.buf.restore(nil, true, oldest)
			logger.Error().Err(err).Msg("correlate full follow-up enqueue failed; retained for retry")
		}
		return
	}
	sort.Strings(ids)
	if _, err := client.Insert(ctx, CorrelateArgs{ChangedIDs: ids}, nil); err != nil {
		c.buf.restore(nil, true, oldest)
		logger.Error().Err(err).Int("changed_ids", len(ids)).Msg("partial correlate enqueue failed; full follow-up retained")
	}
}

func enqueueCorrelateFollowup(ctx context.Context, client jobInserter, lister jobLister) error {
	covered, err := pendingFullCorrelate(ctx, lister)
	if err != nil {
		return err
	}
	if covered {
		return nil
	}
	// River cannot exclude running from uniqueness. Competing replicas may
	// enqueue duplicate follow-ups, but never lose a post-snapshot invalidation.
	if _, err := client.Insert(ctx, CorrelateArgs{}, nil); err != nil {
		return fmt.Errorf("enqueue correlate follow-up: %w", err)
	}
	return nil
}
func pendingFullCorrelate(ctx context.Context, lister jobLister) (bool, error) {

	pending := []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateScheduled, rivertype.JobStateRetryable}
	jobs, err := lister.JobList(ctx, river.NewJobListParams().Queues(queueCorrelate).Kinds(CorrelateArgs{}.Kind()).States(pending...).First(correlateQueueMax+1))
	if err != nil {
		return false, fmt.Errorf("find pending correlate follow-up: %w", err)
	}
	for _, job := range jobs.Jobs {
		// Recheck even for adapters that return more states than requested.
		if job == nil {
			return false, fmt.Errorf("find pending correlate: nil job")
		}
		if job.State == rivertype.JobStateRunning {
			continue
		}
		var args CorrelateArgs
		if err := json.Unmarshal(job.EncodedArgs, &args); err != nil {
			return false, fmt.Errorf("decode pending correlate: %w", err)
		}
		if len(args.ChangedIDs) == 0 {
			return true, nil
		}
	}
	return false, nil
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
			c.flushWithAdmission(flushCtx, client, client, true)
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

// Conservative upper bound for JSON argument escaping and separators.
func correlateIDBytes(id string) int { return 6*len(id) + 3 }

func validateCorrelateIDs(ids []string) error {
	if len(ids) > maxPartialCorrelateIDs {
		return fmt.Errorf("partial correlate: %d IDs exceed work unit limit", len(ids))
	}
	bytes := 32
	for _, id := range ids {
		bytes += correlateIDBytes(id)
	}
	if bytes > maxPartialCorrelateBytes {
		return fmt.Errorf("partial correlate: escaped argument charge %d exceeds limit", bytes)
	}
	return nil
}
