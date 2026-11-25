package jobs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
)

// fakePager serves canned pages of finding IDs and records the cutoffs, limits and
// cursors it was asked about.
type fakePager struct {
	pages    [][]string
	cutoffs  []time.Time
	limits   []int
	afterIDs []string
	err      error
	calls    int
}

func (f *fakePager) OpenIDsBehindCutoff(_ context.Context, cutoff time.Time, afterID string, limit int) ([]string, error) {
	f.cutoffs = append(f.cutoffs, cutoff)
	f.limits = append(f.limits, limit)
	f.afterIDs = append(f.afterIDs, afterID)
	if f.err != nil {
		return nil, f.err
	}
	i := f.calls
	f.calls++
	if i < len(f.pages) {
		return f.pages[i], nil
	}
	return nil, nil
}

type fakeMarker struct {
	marked int
	err    error
}

func (f *fakeMarker) MarkFullPassComplete(context.Context) error {
	f.marked++
	return f.err
}

// reenrichJob builds a continuation of an in-progress pass — Version matches
// the currently-deployed LogicVersion, so Work treats it as "continue", not
// "the version moved on, restart". Tests of the restart behavior itself
// construct ReenrichAllArgs directly with a mismatched Version.
func reenrichJob(round int, cutoff int64) *river.Job[ReenrichAllArgs] {
	return &river.Job[ReenrichAllArgs]{
		Args: ReenrichAllArgs{Round: round, Cutoff: cutoff, Version: enrichcache.LogicVersion},
	}
}

// An empty page means every open finding has been enriched at or after the cutoff,
// so the corpus has converged and the version watermark may advance.
func TestReenrichWorker_EmptyPageMeansConvergedAndMarks(t *testing.T) {
	pager := &fakePager{}
	marker := &fakeMarker{}
	w := &ReenrichWorker{findings: pager, cache: marker}

	require.NoError(t, w.Work(context.Background(), reenrichJob(3, time.Now().Unix())))
	require.Equal(t, 1, marker.marked)
}

// The cutoff must be stamped once and carried across rounds. Re-deriving "now" every
// round would chase its own tail: findings enriched by round 1 would qualify again in
// round 2 and the pass would never terminate.
func TestReenrichWorker_CutoffIsStampedOnceThenCarried(t *testing.T) {
	fixed := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)

	t.Run("round 0 with no cutoff stamps now", func(t *testing.T) {
		pager := &fakePager{}
		w := &ReenrichWorker{findings: pager, cache: &fakeMarker{}, clock: func() time.Time { return fixed }}
		require.NoError(t, w.Work(context.Background(), reenrichJob(0, 0)))
		require.Equal(t, []time.Time{fixed}, pager.cutoffs)
	})

	t.Run("later rounds reuse the carried cutoff", func(t *testing.T) {
		carried := fixed.Add(-2 * time.Hour)
		pager := &fakePager{}
		w := &ReenrichWorker{findings: pager, cache: &fakeMarker{}, clock: func() time.Time { return fixed }}
		require.NoError(t, w.Work(context.Background(), reenrichJob(5, carried.Unix())))
		require.Len(t, pager.cutoffs, 1)
		require.True(t, pager.cutoffs[0].Equal(carried),
			"a later round must target the corpus as of the pass start, not now")
	})
}

// The page size is what paces the pass against enrich throughput. A page far
// larger than the drain rate would rebuild a backlog large enough to exhaust the
// worker's memory.
func TestReenrichWorker_PageSizeIsTheChunk(t *testing.T) {
	pager := &fakePager{}
	w := &ReenrichWorker{findings: pager, cache: &fakeMarker{}}
	require.NoError(t, w.Work(context.Background(), reenrichJob(0, 0)))
	require.Equal(t, []int{reenrichChunk}, pager.limits)
	require.Less(t, reenrichChunk, reenrichQueueCeiling,
		"one round must never be able to exceed the queue ceiling on its own")
}

// A read failure must fail the round so River retries it, NOT report convergence.
func TestReenrichWorker_PageErrorFailsTheRound(t *testing.T) {
	pager := &fakePager{err: errors.New("clickhouse down")}
	marker := &fakeMarker{}
	w := &ReenrichWorker{findings: pager, cache: marker}

	require.Error(t, w.Work(context.Background(), reenrichJob(0, 0)))
	require.Zero(t, marker.marked, "a failed page must never record the corpus as converged")
}

// The backstop exists because rounds terminate on "nothing older than the cutoff": a
// finding that never stamps enriched_at (permanently failing enrich) would otherwise
// loop forever. Critically it must NOT mark the pass complete — the corpus genuinely
// has not converged, and claiming otherwise is the exact silent-success failure this
// mechanism exists to prevent.
func TestReenrichWorker_RoundBackstopStopsWithoutMarking(t *testing.T) {
	pager := &fakePager{pages: [][]string{{"f1"}}}
	marker := &fakeMarker{}
	w := &ReenrichWorker{findings: pager, cache: marker}

	require.NoError(t, w.Work(context.Background(), reenrichJob(reenrichMaxRounds, 0)))
	require.Zero(t, marker.marked, "hitting the backstop is not convergence")
	require.Zero(t, pager.calls, "the backstop must trip before doing more work")
}

// The corpus IS converged; only the bookkeeping failed. Replaying the whole pass for
// that would be a poor trade — worst case is one redundant pass on the next boot.
func TestReenrichWorker_MarkerErrorDoesNotFailTheJob(t *testing.T) {
	pager := &fakePager{}
	marker := &fakeMarker{err: errors.New("pg down")}
	w := &ReenrichWorker{findings: pager, cache: marker}

	require.NoError(t, w.Work(context.Background(), reenrichJob(1, time.Now().Unix())))
	require.Equal(t, 1, marker.marked)
}

// Pods that must not drive a corpus-wide re-enrichment (serve, scanner) no-op.
func TestReenrichWorker_NilPagerNoOps(t *testing.T) {
	marker := &fakeMarker{}
	w := &ReenrichWorker{findings: nil, cache: marker}

	require.NoError(t, w.Work(context.Background(), reenrichJob(0, 0)))
	require.Zero(t, marker.marked)
}

// Each continuation must carry distinct args. With identical args River's UniqueOpts
// would refuse to insert the next round while this one is still running, and the pass
// would silently stop after a single chunk having converged nothing.
func TestReenrichAllArgs_RoundMakesContinuationsDistinct(t *testing.T) {
	a := ReenrichAllArgs{Round: 1, Cutoff: 100}
	b := ReenrichAllArgs{Round: 2, Cutoff: 100}
	require.NotEqual(t, a, b)

	opts := ReenrichAllArgs{}.InsertOpts()
	require.Equal(t, queueReenrich, opts.Queue, "the pass must not occupy an enrich slot")
	require.True(t, opts.UniqueOpts.ByArgs)
	require.Equal(t, uniqueStates, opts.UniqueOpts.ByState)
	require.Equal(t, "reenrich_all", ReenrichAllArgs{}.Kind())
}

// One round is a page read plus a batched insert, so its budget is small and unrelated
// to the multi-hour total — that separation is what keeps the pass from being one
// long-running job babysitting a drain.
func TestReenrichWorker_RoundTimeoutIsShort(t *testing.T) {
	got := (&ReenrichWorker{}).Timeout(reenrichJob(0, 0))
	require.Equal(t, reenrichTimeout, got)
	require.Greater(t, got, time.Minute, "River's 1-minute default is too tight for a page plus insert")
	require.LessOrEqual(t, got, 10*time.Minute, "a round should be short; the pacing lives between rounds")
}

// The pacing arithmetic is load-bearing, so it is asserted rather than left in a
// comment. It must hold against the PESSIMISTIC drain rate: during a full pass the
// version bump defeats the change-gate, so every job does real work at the
// p90 latency, not the lower average that includes gate skips. Pacing against
// the average — or against stale latency numbers — is exactly the mistake this
// test exists to catch: it grows the enrich backlog for the whole pass.
func TestReenrichPacingDrainsEachRoundAndFinishesWithinADay(t *testing.T) {
	// 10 enrich workers / a pessimistic ~2.5s p90 = 4 findings per second.
	const pessimisticDrainPerSec = 4
	drainPerRound := int(reenrichRoundDelay.Seconds()) * pessimisticDrainPerSec
	require.GreaterOrEqual(t, drainPerRound, reenrichChunk,
		"a round enqueues more than the workers can drain before the next round — depth would grow without bound")

	// And the whole corpus must still finish inside a day: that is the entire point
	// of the pass, and the daily periodic cadence is the outer bound.
	rounds := roundsForCorpus(reenrichCorpusHigh)
	total := time.Duration(rounds) * reenrichRoundDelay
	require.Less(t, total, 24*time.Hour, "a full pass must complete within a day")
}

// roundsForCorpus is how many rounds a corpus of n open findings needs.
func roundsForCorpus(n int) int { return (n + reenrichChunk - 1) / reenrichChunk }

// The round budget is what decides whether a full pass finishes. Sized wrong it
// aborts mid-corpus and silently leaves the new enrichcache.LogicVersion applied to
// only part of the standing findings, which reads exactly like "the scoring change
// did not work".
//
// A round count and headroom multiple written in a comment go stale as soon as the
// corpus ceiling or the chunk size is re-paced (see
// TestReenrichPacingDrainsEachRoundAndFinishesWithinADay), so the headroom is
// asserted instead: the NEXT time either number drifts, this fails loudly instead
// of silently aborting a pass.
func TestReenrichBudgetHasThreefoldHeadroomOverTheCorpusCeiling(t *testing.T) {
	rounds := roundsForCorpus(reenrichCorpusHigh)
	want := int(math.Ceil(float64(reenrichCorpusHigh) / float64(reenrichChunk)))
	require.Equal(t, want, rounds, "design-ceiling corpus size / page size per round, rounded up")
	require.GreaterOrEqual(t, reenrichMaxRounds, 3*rounds,
		"the round backstop must leave 3x headroom over the sized corpus")
}

// A round skipped for backpressure enqueues nothing, so it must not consume the
// round budget. It used to: the skip path returned scheduleNextRound, which
// incremented Round, so a few hours of a deep enrich queue pushed the pass past its
// backstop and abandoned the corpus half-processed.
func TestReenrichSkippedRoundSpendsASkipNotARound(t *testing.T) {
	cutoff := time.Date(2026, 8, 2, 9, 0, 0, 0, time.UTC)
	cur := ReenrichAllArgs{
		Round: 7, Skips: 2, Cutoff: cutoff.Unix(),
		Version: enrichcache.LogicVersion, AfterID: "id-500",
	}

	skipped := nextRound(cur, cutoff, true, "")
	require.Equal(t, 7, skipped.Round, "a skipped round did no work and must not advance the round budget")
	require.Equal(t, 3, skipped.Skips)
	require.Equal(t, enrichcache.LogicVersion, skipped.Version, "the version this chain targets must carry forward")
	require.Equal(t, "id-500", skipped.AfterID,
		"a skipped round enqueued nothing, so advancing the walk cursor would silently skip a whole page")
	require.NotEqual(t, cur, skipped, "the continuation must differ from its parent or ByArgs dedup drops it")

	productive := nextRound(cur, cutoff, false, "id-1650")
	require.Equal(t, 8, productive.Round)
	require.Zero(t, productive.Skips, "a round that drained resets the skip budget")
	require.Equal(t, cutoff.Unix(), productive.Cutoff)
	require.Equal(t, enrichcache.LogicVersion, productive.Version, "the version this chain targets must carry forward")
	require.Equal(t, "id-1650", productive.AfterID, "a productive round advances the walk past its last id")
}

// TestReenrichPassTerminatesOverAnAllZeroCorpus is the regression test for a
// pass that never advanced. Every finding sits at enriched_at=0, which is exactly
// the shape that defeated the old `ORDER BY enriched_at ASC` paging: the page
// filled from the epoch-stamped head every round, so the same ids came back
// forever, and the pass enqueued work every round until it hit its
// reenrichMaxRounds backstop having advanced nothing.
//
// The fake honours afterID, so it can only pass if the walk actually advances.
func TestReenrichPassTerminatesOverAnAllZeroCorpus(t *testing.T) {
	const corpus = 3000
	all := make([]string, corpus)
	for i := range all {
		all[i] = fmt.Sprintf("id-%05d", i) // sorted, as ORDER BY id returns them
	}

	page := func(afterID string, limit int) []string {
		start := 0
		for start < len(all) && all[start] <= afterID {
			start++
		}
		end := min(start+limit, len(all))
		return all[start:end]
	}

	seen := map[string]int{}
	cursor := ""
	rounds := 0
	for {
		rounds++
		require.LessOrEqual(t, rounds, corpus/reenrichChunk+2,
			"the walk did not converge — it is re-serving the same page (the pre-fix bug)")
		ids := page(cursor, reenrichChunk)
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			seen[id]++
		}
		cursor = nextRound(ReenrichAllArgs{}, time.Now(), false, ids[len(ids)-1]).AfterID
	}

	require.Len(t, seen, corpus, "every finding must be visited exactly once")
	for id, n := range seen {
		require.Equal(t, 1, n, "%s was enqueued %d times", id, n)
	}
}

// Skips get their own backstop: without one, "don't burn the round budget" would
// turn a permanently saturated enrich queue into an immortal job pair.
func TestReenrichSkipBackstopStopsWithoutMarking(t *testing.T) {
	pager := &fakePager{pages: [][]string{{"f1"}}}
	marker := &fakeMarker{}
	w := &ReenrichWorker{findings: pager, cache: marker}

	job := &river.Job[ReenrichAllArgs]{Args: ReenrichAllArgs{Round: 3, Skips: reenrichMaxSkips, Version: enrichcache.LogicVersion}}
	require.NoError(t, w.Work(context.Background(), job))
	require.Zero(t, marker.marked, "abandoning the pass is not convergence")
	require.Zero(t, pager.calls, "the backstop must trip before doing more work")

	require.Greater(t, time.Duration(reenrichMaxSkips)*reenrichRoundDelay, 6*time.Hour,
		"the skip budget must outlast any transient enrich backlog")
}

// TestReenrichWorker_VersionChangeMidPassRestarts is the regression guard for
// the stuck-watermark bug (repeated LogicVersion bumps, none of which got its own
// full pass, leaving enrich_logic_version frozen). A chain that started under an old version must not keep
// chasing its own stale cutoff forever once the deployed version moves on:
// the very next round has to notice and restart against the current version,
// or insertReenrichIfIdle's "a pass already exists" guard means no later
// bump ever gets a pass of its own while the stale chain is still alive.
func TestReenrichWorker_VersionChangeMidPassRestarts(t *testing.T) {
	fixed := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	staleCutoff := fixed.Add(-5 * 24 * time.Hour)

	pager := &fakePager{}
	w := &ReenrichWorker{findings: pager, cache: &fakeMarker{}, clock: func() time.Time { return fixed }}

	// Round 253 of a chain that started under an old (or unstamped, pre-fix)
	// version, still carrying a 5-day-old cutoff.
	job := &river.Job[ReenrichAllArgs]{Args: ReenrichAllArgs{
		Round: 253, Skips: 0, Cutoff: staleCutoff.Unix(), Version: "v12",
	}}
	require.NoError(t, w.Work(context.Background(), job))

	require.Len(t, pager.cutoffs, 1)
	require.True(t, pager.cutoffs[0].Equal(fixed),
		"a version change must restart the cutoff at now, not keep chasing the stale one")
}

// TestReenrichWorker_UnstampedVersionRestarts covers every round already
// scheduled before this fix shipped — Version is the Go zero value (""),
// which must be treated exactly like a mismatch (restart), not like "no
// version was ever requested, so don't check". Otherwise every pre-fix
// in-flight round keeps running exactly as stuck as before.
func TestReenrichWorker_UnstampedVersionRestarts(t *testing.T) {
	fixed := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	staleCutoff := fixed.Add(-5 * 24 * time.Hour)

	pager := &fakePager{}
	w := &ReenrichWorker{findings: pager, cache: &fakeMarker{}, clock: func() time.Time { return fixed }}

	job := &river.Job[ReenrichAllArgs]{Args: ReenrichAllArgs{Round: 253, Cutoff: staleCutoff.Unix()}}
	require.NoError(t, w.Work(context.Background(), job))

	require.Len(t, pager.cutoffs, 1)
	require.True(t, pager.cutoffs[0].Equal(fixed), "an unstamped Version must restart just like a mismatched one")
}

// TestReenrichWorker_MatchingVersionCarriesCutoffForward is the inverse: a
// chain converging under the CURRENT version must not be reset every round —
// only a real mismatch triggers a restart.
func TestReenrichWorker_MatchingVersionCarriesCutoffForward(t *testing.T) {
	fixed := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	carried := fixed.Add(-2 * time.Hour)

	pager := &fakePager{}
	w := &ReenrichWorker{findings: pager, cache: &fakeMarker{}, clock: func() time.Time { return fixed }}

	job := &river.Job[ReenrichAllArgs]{Args: ReenrichAllArgs{
		Round: 5, Cutoff: carried.Unix(), Version: enrichcache.LogicVersion,
	}}
	require.NoError(t, w.Work(context.Background(), job))

	require.Len(t, pager.cutoffs, 1)
	require.True(t, pager.cutoffs[0].Equal(carried), "a matching version must keep converging toward its own cutoff")
}

// TestReenrichInsertParams_DemotesPriority is the regression guard for the
// mistargeted priority demotion: EnrichSweepWorker.drain got the
// enrichSweepPriority treatment, but every enqueued enrich job still landed at
// priority 1 — because it's
// ReenrichWorker.enqueue, not EnrichSweepWorker.drain, that has been the
// actual dominant, continuously-running contributor to the backlog
// (reenrich_all fires every 5 minutes and was never gated by
// sweepHasCapacity at all). Each finding this pass enqueues must carry the
// same demoted priority so routine full-corpus convergence never competes
// with ingest-time enrich or a KEV escalation for a worker slot.
func TestReenrichInsertParams_DemotesPriority(t *testing.T) {
	ids := []string{"f1", "f2", "f3"}
	params := reenrichInsertParams(ids)
	require.Len(t, params, len(ids))
	for i, p := range params {
		require.Equal(t, enrichSweepPriority, p.InsertOpts.Priority,
			"reenrich-enqueued findings must be demoted off priority 1, or this pass keeps starving ingest-time enrich")
		args, ok := p.Args.(EnrichArgs)
		require.True(t, ok, "reenrich must enqueue EnrichArgs")
		require.Equal(t, ids[i], args.FindingID, "ids must map to params in order")
	}
}
