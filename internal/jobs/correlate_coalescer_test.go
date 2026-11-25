package jobs

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"
)

// fakeJobInserter records every CorrelateArgs Insert call it receives.
type fakeJobInserter struct {
	mu    sync.Mutex
	calls []CorrelateArgs
	err   error
}

func (f *fakeJobInserter) Insert(_ context.Context, args river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.calls = append(f.calls, args.(CorrelateArgs))
	return &rivertype.JobInsertResult{}, nil
}

func (f *fakeJobInserter) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeJobInserter) lastArgs() CorrelateArgs {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func sortedCopy(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

// --- correlateBuffer: pure accumulate/drain logic ---

func TestCorrelateBuffer_AddDedupesAndUnions(t *testing.T) {
	b := newCorrelateBuffer()
	b.add([]string{"a", "b"})
	size := b.add([]string{"b", "c"})
	require.Equal(t, 3, size, "b deduped, union of {a,b} and {b,c} is size 3")

	got := b.drain()
	require.ElementsMatch(t, []string{"a", "b", "c"}, got)
}

func TestCorrelateBuffer_DrainEmptiesAndReturnsNilWhenEmpty(t *testing.T) {
	b := newCorrelateBuffer()
	require.Nil(t, b.drain(), "nothing accumulated yet")

	b.add([]string{"a"})
	got := b.drain()
	require.Equal(t, []string{"a"}, got)

	require.Nil(t, b.drain(), "second drain in a row sees an empty buffer")
}

func TestCorrelateBuffer_AddReturnsRunningSize(t *testing.T) {
	b := newCorrelateBuffer()
	require.Equal(t, 2, b.add([]string{"a", "b"}))
	require.Equal(t, 2, b.add([]string{"a"}), "re-adding an existing id doesn't grow the size")
	require.Equal(t, 3, b.add([]string{"c"}))
}

// TestCorrelateBuffer_ConcurrentAddNeverLosesAnID is the correctness-critical
// test: many goroutines calling add() concurrently, racing a drain, must
// still account for every ID exactly once across the drains — no loss, no
// spurious duplication beyond the dedup the map already guarantees.
func TestCorrelateBuffer_ConcurrentAddNeverLosesAnID(t *testing.T) {
	b := newCorrelateBuffer()
	const goroutines = 50
	const perGoroutine = 20

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				b.add([]string{fmt.Sprintf("g%d-id%d", g, i)})
			}
		}(g)
	}
	wg.Wait()

	got := b.drain()
	require.Len(t, got, goroutines*perGoroutine)

	want := make([]string, 0, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		for i := 0; i < perGoroutine; i++ {
			want = append(want, fmt.Sprintf("g%d-id%d", g, i))
		}
	}
	require.ElementsMatch(t, want, got)
	require.Nil(t, b.drain(), "drain emptied the buffer")
}

// TestCorrelateBuffer_ConcurrentAddRacingDrain proves the same no-loss
// property when adds and drains interleave: every ID handed to add(), across
// however many drains happen to land, is accounted for exactly once in the
// union of all drained batches.
func TestCorrelateBuffer_ConcurrentAddRacingDrain(t *testing.T) {
	b := newCorrelateBuffer()
	const goroutines = 30
	const perGoroutine = 40

	var mu sync.Mutex
	var drained []string
	stopDraining := make(chan struct{})
	var drainWG sync.WaitGroup
	drainWG.Add(1)
	go func() {
		defer drainWG.Done()
		for {
			select {
			case <-stopDraining:
				return
			default:
				batch := b.drain()
				if len(batch) > 0 {
					mu.Lock()
					drained = append(drained, batch...)
					mu.Unlock()
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				b.add([]string{fmt.Sprintf("g%d-id%d", g, i)})
			}
		}(g)
	}
	wg.Wait()
	close(stopDraining)
	drainWG.Wait()

	// Whatever is left in the buffer after the drainer stops is also owed.
	drained = append(drained, b.drain()...)

	want := make([]string, 0, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		for i := 0; i < perGoroutine; i++ {
			want = append(want, fmt.Sprintf("g%d-id%d", g, i))
		}
	}
	require.ElementsMatch(t, want, sortedCopy(drained))
}

// --- correlateCoalescer.flush: backpressure + insert ---

func TestCorrelateCoalescer_FlushWithNothingBufferedNoOps(t *testing.T) {
	c := newCorrelateCoalescer()
	ins := &fakeJobInserter{}
	c.flush(context.Background(), ins, fakeJobLister{jobs: 0})
	require.Equal(t, 0, ins.callCount())
}

func TestCorrelateCoalescer_FlushEnqueuesUnionWhenUnderCapacity(t *testing.T) {
	c := newCorrelateCoalescer()
	c.Add([]string{"a", "b"})
	c.Add([]string{"b", "c"})

	ins := &fakeJobInserter{}
	c.flush(context.Background(), ins, fakeJobLister{jobs: 3})

	require.Equal(t, 1, ins.callCount(), "one job for the whole burst")
	require.ElementsMatch(t, []string{"a", "b", "c"}, ins.lastArgs().ChangedIDs)
}

// TestCorrelateCoalescer_FlushRespectsBackpressure proves the backpressure gate: at
// or over correlateQueueMax, flush must not enqueue — same gate
// enqueuePartialCorrelate always had, now checked at flush time.
func TestCorrelateCoalescer_FlushRespectsBackpressure(t *testing.T) {
	c := newCorrelateCoalescer()
	c.Add([]string{"a", "b"})

	ins := &fakeJobInserter{}
	c.flush(context.Background(), ins, fakeJobLister{jobs: correlateQueueMax})

	require.Equal(t, 0, ins.callCount(), "at capacity, the coalesced flush is skipped")
	// The buffer was already drained before the backpressure check ran, so a
	// dropped-under-backpressure batch does not stick around to be retried by
	// the very next tick with stale data; the full sweep is the documented
	// backstop for this path, same as before coalescing existed.
	require.Nil(t, c.buf.drain())
}

func TestCorrelateCoalescer_FlushUnderCapacityStillEnqueues(t *testing.T) {
	c := newCorrelateCoalescer()
	c.Add([]string{"a"})

	ins := &fakeJobInserter{}
	c.flush(context.Background(), ins, fakeJobLister{jobs: correlateQueueMax - 1})

	require.Equal(t, 1, ins.callCount())
}

// --- correlateCoalescer.Add: size-threshold flush trigger ---

func TestCorrelateCoalescer_AddSignalsFlushAtSizeThreshold(t *testing.T) {
	c := newCorrelateCoalescer()

	ids := make([]string, 0, maxPartialCorrelateIDs-1)
	for i := 0; i < maxPartialCorrelateIDs-1; i++ {
		ids = append(ids, fmt.Sprintf("id-%d", i))
	}
	c.Add(ids)
	select {
	case <-c.flushNow:
		t.Fatal("should not signal below the threshold")
	default:
	}

	c.Add([]string{"one-more"}) // crosses maxPartialCorrelateIDs
	select {
	case <-c.flushNow:
		// expected
	default:
		t.Fatal("expected a flush-now signal once the threshold is crossed")
	}
}

func TestCorrelateCoalescer_AddSignalIsNonBlockingWhenAlreadyPending(t *testing.T) {
	c := newCorrelateCoalescer()
	ids := make([]string, maxPartialCorrelateIDs)
	for i := range ids {
		ids[i] = fmt.Sprintf("id-%d", i)
	}
	c.Add(ids) // crosses threshold once, fills the buffered channel

	done := make(chan struct{})
	go func() {
		c.Add([]string{"another-batch-crossing-threshold-again"})
		close(done)
	}()
	select {
	case <-done:
		// Add returned promptly even with flushNow already full — it must
		// never block a sync worker's own Work() call on the flush loop.
	case <-time.After(time.Second):
		t.Fatal("Add blocked despite flushNow already having a pending signal")
	}
}

// --- RunCorrelateCoalescer: ticker-based flush + shutdown drain ---

// fakeCorrelateClient satisfies correlateClient with fakeJobInserter's
// recording Insert and a fixed queue depth for JobList, so
// RunCorrelateCoalescer's real loop — ticker, flushNow, shutdown drain — runs
// against a fake instead of a live Postgres-backed *river.Client.
type fakeCorrelateClient struct {
	*fakeJobInserter
	depth int
}

func (f fakeCorrelateClient) JobList(_ context.Context, _ *river.JobListParams) (*river.JobListResult, error) {
	return &river.JobListResult{Jobs: make([]*rivertype.JobRow, f.depth)}, nil
}

// TestRunCorrelateCoalescer_TickerFlushesAccumulatedBatch proves the
// ticker-based trigger: a batch added well under the size threshold still
// goes out once correlateCoalesceInterval elapses, without any shutdown.
func TestRunCorrelateCoalescer_TickerFlushesAccumulatedBatch(t *testing.T) {
	partialCorrelateCoalescer = newCorrelateCoalescer() // isolate from other tests sharing the package singleton
	defer func() { partialCorrelateCoalescer = newCorrelateCoalescer() }()

	ins := &fakeJobInserter{}
	client := fakeCorrelateClient{fakeJobInserter: ins}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		RunCorrelateCoalescer(ctx, stop, client)
	}()

	enqueuePartialCorrelate([]string{"a", "b"})

	require.Eventually(t, func() bool { return ins.callCount() == 1 }, 3*correlateCoalesceInterval, 50*time.Millisecond,
		"ticker should have flushed the accumulated batch")
	require.ElementsMatch(t, []string{"a", "b"}, ins.lastArgs().ChangedIDs)

	close(stop)
	<-runDone
}

// TestRunCorrelateCoalescer_FlushesOnStop proves the shutdown drain: a batch
// still sitting in the buffer when stop is closed is drained and enqueued by
// the loop's own final-flush branch before it returns — not left behind.
func TestRunCorrelateCoalescer_FlushesOnStop(t *testing.T) {
	partialCorrelateCoalescer = newCorrelateCoalescer()
	defer func() { partialCorrelateCoalescer = newCorrelateCoalescer() }()

	ins := &fakeJobInserter{}
	client := fakeCorrelateClient{fakeJobInserter: ins}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		RunCorrelateCoalescer(ctx, stop, client)
	}()

	enqueuePartialCorrelate([]string{"pending-at-shutdown"})
	close(stop) // shut down before the ticker would have fired on its own
	<-runDone

	require.Equal(t, 1, ins.callCount(), "the pre-shutdown batch must still go out")
	require.Equal(t, []string{"pending-at-shutdown"}, ins.lastArgs().ChangedIDs)
}

// TestRunCorrelateCoalescer_SurvivesCtxCancelUntilStopCloses is the
// regression test for a shutdown-ordering bug: under the OLD code the
// loop selected on ctx.Done() directly, so an enqueuePartialCorrelate → Add
// call happening after the root ctx fired (simulating a sync job finishing
// inside River's SoftStopTimeout grace window, on its own
// context.WithoutCancel-detached context) but before the caller was actually
// done draining in-flight work landed in a buffer nobody would ever flush
// again. The reproduction: call enqueuePartialCorrelate after a "done"
// signal (here, ctx cancellation) and confirm the ID is NOT lost, because the
// loop's stop signal is independent of ctx and has not fired yet.
func TestRunCorrelateCoalescer_SurvivesCtxCancelUntilStopCloses(t *testing.T) {
	partialCorrelateCoalescer = newCorrelateCoalescer()
	defer func() { partialCorrelateCoalescer = newCorrelateCoalescer() }()

	ins := &fakeJobInserter{}
	client := fakeCorrelateClient{fakeJobInserter: ins}

	ctx, cancel := context.WithCancel(context.Background())
	stop := make(chan struct{})
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		RunCorrelateCoalescer(ctx, stop, client)
	}()

	// Simulate SIGTERM: the root ctx fires immediately...
	cancel()

	// ...but a sync job is still finishing inside River's SoftStopTimeout
	// grace window and only now gets around to calling enqueuePartialCorrelate.
	// Under the old ctx.Done()-gated loop this would race the loop's own
	// shutdown flush and could easily lose the ID; under the fixed loop the
	// stop signal has not fired yet, so the loop is still very much alive.
	enqueuePartialCorrelate([]string{"landed-after-ctx-cancel"})

	// Give the (still-running) loop a moment to prove it hasn't exited on
	// ctx.Done() alone.
	select {
	case <-runDone:
		t.Fatal("loop must not exit on ctx cancellation alone — only on stop closing")
	case <-time.After(100 * time.Millisecond):
	}

	// Only now does the caller finish draining in-flight work and tell the
	// coalescer it's safe to do its final flush.
	close(stop)
	<-runDone

	require.Equal(t, 1, ins.callCount(), "an Add landing after ctx cancel but before stop must still be flushed")
	require.Equal(t, []string{"landed-after-ctx-cancel"}, ins.lastArgs().ChangedIDs)
}

// TestRunCorrelateCoalescer_SizeThresholdFlushesBeforeTick proves the
// size-threshold trigger inside the real loop: crossing maxPartialCorrelateIDs
// flushes promptly, well inside one correlateCoalesceInterval tick.
func TestRunCorrelateCoalescer_SizeThresholdFlushesBeforeTick(t *testing.T) {
	partialCorrelateCoalescer = newCorrelateCoalescer()
	defer func() { partialCorrelateCoalescer = newCorrelateCoalescer() }()

	ins := &fakeJobInserter{}
	client := fakeCorrelateClient{fakeJobInserter: ins}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		RunCorrelateCoalescer(ctx, stop, client)
	}()

	ids := make([]string, maxPartialCorrelateIDs)
	for i := range ids {
		ids[i] = fmt.Sprintf("id-%d", i)
	}
	enqueuePartialCorrelate(ids)

	require.Eventually(t, func() bool { return ins.callCount() == 1 }, correlateCoalesceInterval-time.Second, 10*time.Millisecond,
		"size threshold should flush well before the next tick")
	require.Len(t, ins.lastArgs().ChangedIDs, maxPartialCorrelateIDs)

	close(stop)
	<-runDone
}

// TestCorrelateCoalescer_FlushChunksLargeUnion proves chunking: a
// drained batch bigger than maxPartialCorrelateIDs is split into multiple
// CorrelateArgs jobs, each capped at maxPartialCorrelateIDs, never one job
// carrying the whole union — this is what keeps the coalesced flush inside
// the ClickHouse IN-clause query-size ceiling maxPartialCorrelateIDs exists
// to protect, under a burst big enough to cross it (e.g. syncWorkers=20
// concurrent 200-ID batches landing in one coalesce window).
func TestCorrelateCoalescer_FlushChunksLargeUnion(t *testing.T) {
	c := newCorrelateCoalescer()

	const total = maxPartialCorrelateIDs*4 + 37 // 4 full chunks + 1 partial
	ids := make([]string, total)
	for i := range ids {
		ids[i] = fmt.Sprintf("id-%d", i)
	}
	c.Add(ids)

	ins := &fakeJobInserter{}
	c.flush(context.Background(), ins, fakeJobLister{jobs: 0})

	require.Equal(t, 5, ins.callCount(), "4 full-size chunks plus 1 remainder chunk")

	var gotIDs []string
	seenChunkSizes := map[int]int{}
	ins.mu.Lock()
	for _, call := range ins.calls {
		require.LessOrEqual(t, len(call.ChangedIDs), maxPartialCorrelateIDs,
			"no single job may exceed maxPartialCorrelateIDs — that is the whole point of chunking")
		seenChunkSizes[len(call.ChangedIDs)]++
		gotIDs = append(gotIDs, call.ChangedIDs...)
	}
	ins.mu.Unlock()

	require.Equal(t, 4, seenChunkSizes[maxPartialCorrelateIDs], "4 chunks at exactly the cap")
	require.Equal(t, 1, seenChunkSizes[37], "1 remainder chunk")
	require.ElementsMatch(t, ids, gotIDs, "no id lost or duplicated across the chunk split")
}

// TestCorrelateCoalescer_FlushChunkInsertFailureDoesNotBlockOtherChunks
// proves a failing Insert for one chunk doesn't stop the remaining chunks
// from going out — chunking must not turn one bad chunk into a lost flush.
func TestCorrelateCoalescer_FlushChunkInsertFailureDoesNotBlockOtherChunks(t *testing.T) {
	c := newCorrelateCoalescer()

	const total = maxPartialCorrelateIDs*2 + 5
	ids := make([]string, total)
	for i := range ids {
		ids[i] = fmt.Sprintf("id-%d", i)
	}
	c.Add(ids)

	failing := &failNInserter{failFirst: 1}
	c.flush(context.Background(), failing, fakeJobLister{jobs: 0})

	require.Equal(t, 3, failing.attempts, "all 3 chunks must be attempted even though the first failed")
	require.Equal(t, 2, failing.succeeded, "the 2 chunks after the failing one still go out")
}

// failNInserter fails the first failFirst Insert calls, then succeeds.
type failNInserter struct {
	mu        sync.Mutex
	attempts  int
	succeeded int
	failFirst int
}

func (f *failNInserter) Insert(_ context.Context, _ river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.attempts <= f.failFirst {
		return nil, fmt.Errorf("simulated insert failure")
	}
	f.succeeded++
	return &rivertype.JobInsertResult{}, nil
}
