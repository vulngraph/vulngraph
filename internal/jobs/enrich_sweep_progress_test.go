package jobs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type progressMemoryStore struct {
	state    enrichcache.SweepProgress
	readErr  error
	failSave int
	saves    int
}

func (s *progressMemoryStore) GetSweepProgress(context.Context) (enrichcache.SweepProgress, error) {
	return s.state, s.readErr
}
func (s *progressMemoryStore) AdvanceSweepProgress(_ context.Context, revision int64, next enrichcache.SweepProgress) (bool, error) {
	s.saves++
	if s.saves == s.failSave {
		return false, errors.New("checkpoint unavailable")
	}
	if revision != s.state.Revision {
		return false, nil
	}
	next.Revision = revision + 1
	s.state = next
	return true, nil
}

type progressFindingLister struct {
	list func(finding.Filter) ([]finding.Finding, error)
}

func (s progressFindingLister) List(_ context.Context, f finding.Filter) ([]finding.Finding, error) {
	return s.list(f)
}

func (s progressFindingLister) EnrichmentCandidates(ctx context.Context, f finding.Filter) (finding.EnrichmentPage, error) {
	rows, err := s.List(ctx, f)
	var page finding.EnrichmentPage
	for _, row := range rows {
		page.IDs = append(page.IDs, row.ID)
		page.Cursor = finding.EncodeStaleCursor(row)
	}
	return page, err
}

type progressInserter struct {
	ids   []string
	fail  bool
	after func()
}

func (s *progressInserter) InsertMany(_ context.Context, batch []river.InsertManyParams) ([]*rivertype.JobInsertResult, error) {
	if s.fail {
		return nil, errors.New("queue unavailable")
	}
	for _, p := range batch {
		s.ids = append(s.ids, p.Args.(EnrichArgs).FindingID)
	}
	if s.after != nil {
		s.after()
	}
	return nil, nil
}
func progressPage(n int) []finding.Finding {
	out := make([]finding.Finding, n)
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	for i := range out {
		out[i] = finding.Finding{ID: fmt.Sprintf("progress-%05d", i), EnrichedAt: at}
	}
	return out
}
func TestEnrichSweepProgressResumesAcrossWorkersAndWraps(t *testing.T) {
	for _, tail := range []bool{false, true} {
		t.Run(fmt.Sprint(tail), func(t *testing.T) {
			page := progressPage(enrichSweepLimit)
			store := &progressMemoryStore{}
			queue := &progressInserter{}
			first := &EnrichSweepWorker{progress: store, findings: progressFindingLister{func(f finding.Filter) ([]finding.Finding, error) {
				require.True(t, f.StaleFirst)
				require.Empty(t, f.Cursor)
				require.Equal(t, enrichSweepLimit, f.Limit)
				require.False(t, f.EnrichedBefore.IsZero())
				require.Equal(t, f.EnrichedBefore.Truncate(time.Millisecond), f.EnrichedBefore)
				return page, nil
			}}}
			n, err := first.drainDriftWith(t.Context(), queue, enrichSweepLimit)
			require.NoError(t, err)
			require.Equal(t, enrichSweepLimit, n)
			cutoff := store.state.Before
			cursor := finding.EncodeStaleCursor(page[len(page)-1])
			require.Equal(t, cursor, store.state.Cursor)
			second := &EnrichSweepWorker{progress: store, findings: progressFindingLister{func(f finding.Filter) ([]finding.Finding, error) {
				require.Equal(t, cutoff, f.EnrichedBefore)
				require.Equal(t, cursor, f.Cursor)
				// The cursor row need not exist in the next source snapshot.
				if tail {
					return []finding.Finding{{ID: "tail", EnrichedAt: page[0].EnrichedAt.Add(time.Millisecond)}}, nil
				}
				return nil, nil
			}}}
			n, err = second.drainDriftWith(t.Context(), queue, enrichSweepLimit)
			require.NoError(t, err)
			if tail {
				require.Equal(t, 1, n)
			} else {
				require.Zero(t, n)
			}
			require.Empty(t, store.state.Cursor)
			require.True(t, store.state.Before.IsZero())
			third := &EnrichSweepWorker{progress: store, findings: progressFindingLister{func(f finding.Filter) ([]finding.Finding, error) {
				require.Empty(t, f.Cursor)
				require.False(t, f.EnrichedBefore.IsZero())
				return nil, nil
			}}}
			n, err = third.drainDriftWith(t.Context(), queue, enrichSweepLimit)
			require.NoError(t, err)
			require.Zero(t, n)
			require.True(t, store.state.Before.IsZero())
		})
	}
}
func TestEnrichSweepProgressFailuresDoNotSkipAdmission(t *testing.T) {
	for _, failure := range []string{"read", "list", "enqueue", "checkpoint", "conflict", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			page := progressPage(enrichSweepLimit)
			initial := enrichcache.SweepProgress{Before: time.Now().UTC().Truncate(time.Millisecond), Revision: 7}
			store := &progressMemoryStore{state: initial}
			queue := &progressInserter{}
			if failure == "read" {
				store.readErr = errors.New("read unavailable")
			}
			if failure == "enqueue" {
				queue.fail = true
			}
			if failure == "checkpoint" {
				store.failSave = 1
			}
			if failure == "conflict" {
				queue.after = func() { store.state.Revision++; store.state.Cursor = "newer-checkpoint" }
			}
			worker := &EnrichSweepWorker{progress: store, findings: progressFindingLister{func(f finding.Filter) ([]finding.Finding, error) {
				require.Empty(t, f.Cursor)
				require.Equal(t, initial.Before, f.EnrichedBefore)
				if failure == "list" {
					return nil, errors.New("list unavailable")
				}
				return page, nil
			}}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if failure == "cancel" {
				cancel()
			}
			_, err := worker.drainDriftWith(ctx, queue, enrichSweepLimit)
			require.Error(t, err)
			if failure == "conflict" {
				require.ErrorIs(t, err, enrichcache.ErrSweepProgressConflict)
				require.Equal(t, "newer-checkpoint", store.state.Cursor)
				return
			}
			require.Equal(t, initial, store.state, "no page can advance on failed admission/checkpoint")
			committed := len(queue.ids)
			store.readErr = nil
			store.failSave = 0
			queue.fail = false
			retry := &EnrichSweepWorker{progress: store, findings: progressFindingLister{func(f finding.Filter) ([]finding.Finding, error) { require.Empty(t, f.Cursor); return page, nil }}}
			n, err := retry.drainDriftWith(t.Context(), queue, enrichSweepLimit)
			require.NoError(t, err)
			require.Equal(t, enrichSweepLimit, n)
			require.Len(t, queue.ids, committed+enrichSweepLimit)
			require.Equal(t, finding.EncodeStaleCursor(page[len(page)-1]), store.state.Cursor)
			if failure == "checkpoint" {
				require.Equal(t, enrichSweepLimit, committed, "enqueue committed before lost checkpoint; retry must replay")
			}
		})
	}
}

func TestEnrichSweepUnreadableProgressCannotCompletePass(t *testing.T) {
	want := errors.New("progress unavailable")
	worker := &EnrichSweepWorker{progress: &progressMemoryStore{readErr: want}}
	_, err := worker.driftPassActive(t.Context())
	require.ErrorIs(t, err, want,
		"an unreadable checkpoint is not evidence that the enumeration finished")
}

func TestEnrichSweepContinuationSkipsRepeatedMaintenance(t *testing.T) {
	pruner := &backfillPruner{}
	lister := &recordingLister{}
	worker := &EnrichSweepWorker{progress: &progressMemoryStore{state: enrichcache.SweepProgress{Before: time.Now()}}, findings: lister, alerts: pruner}
	// With no River client, drift cannot enqueue; maintenance must still have
	// been skipped rather than repeating before that error.
	require.ErrorContains(t, worker.Work(t.Context(), &river.Job[EnrichSweepArgs]{}), "drainDrift: client")
	require.Zero(t, pruner.calls)
	require.Empty(t, lister.seen)
}
