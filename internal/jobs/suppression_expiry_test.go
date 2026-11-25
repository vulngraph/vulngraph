package jobs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
)

type fakeExpiring struct {
	due     []suppress.Suppression
	dueErr  error
	markErr error
	marked  []string
}

func (f *fakeExpiring) ExpiryNoticesDue(context.Context) ([]suppress.Suppression, error) {
	return f.due, f.dueErr
}

func (f *fakeExpiring) MarkExpiryNoticesSent(_ context.Context, ids []string) error {
	f.marked = append(f.marked, ids...)
	return f.markErr
}

// recordingDispatcher delivers to `channels` channels (default 1) or fails.
type recordingDispatcher struct {
	sent     []notify.Notification
	channels int
	none     bool
	err      error
}

func (r *recordingDispatcher) Deliver(_ context.Context, n notify.Notification) (int, error) {
	r.sent = append(r.sent, n)
	if r.err != nil {
		return 0, r.err
	}
	if r.none {
		return 0, nil
	}
	return max(r.channels, 1), nil
}

var expiryJob = &river.Job[SuppressionExpiryArgs]{}

func TestSuppressionExpiryWorker_DispatchesOnceAndMarks(t *testing.T) {
	at := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	src := &fakeExpiring{due: []suppress.Suppression{
		{FindingID: "f1", Reason: "accepted risk", ExpiresAt: at},
		{FindingID: "f2", Reason: "false positive", ExpiresAt: at.Add(24 * time.Hour)},
	}}
	disp := &recordingDispatcher{}
	w := &SuppressionExpiryWorker{suppressions: src, notify: disp}

	require.NoError(t, w.Work(context.Background(), expiryJob))
	require.Len(t, disp.sent, 1, "one digest per run, not one notification per suppression")
	n := disp.sent[0]
	require.Equal(t, notify.EventSuppressionExpiry, n.EventType)
	require.Equal(t, notify.SeverityMedium, n.Severity, "a set severity, so a severity-filtered channel can route it")
	require.Equal(t, "2 finding suppressions expire within 14 days", n.Title)
	require.Len(t, n.Fields, 2)
	require.Equal(t, "f1", n.Fields[0].Label)
	require.Equal(t, "expires 2026-10-15 — accepted risk", n.Fields[0].Value)
	require.Equal(t, []string{"f1", "f2"}, src.marked)
}

func TestSuppressionExpiryWorker_NothingDueSendsNothing(t *testing.T) {
	src := &fakeExpiring{}
	disp := &recordingDispatcher{}
	require.NoError(t, (&SuppressionExpiryWorker{suppressions: src, notify: disp}).Work(context.Background(), expiryJob))
	require.Empty(t, disp.sent)
	require.Empty(t, src.marked)
}

// Without a dispatcher nothing is marked sent: wiring one later must still
// announce what is about to expire.
func TestSuppressionExpiryWorker_UnwiredIsANoOp(t *testing.T) {
	src := &fakeExpiring{due: []suppress.Suppression{{FindingID: "f1"}}}
	require.NoError(t, (&SuppressionExpiryWorker{suppressions: src}).Work(context.Background(), expiryJob))
	require.Empty(t, src.marked)
	require.NoError(t, (&SuppressionExpiryWorker{notify: &recordingDispatcher{}}).Work(context.Background(), expiryJob))
	require.Nil(t, expiringSuppressions(nil), "a nil service must stay a nil interface")
}

func TestSuppressionExpiryWorker_Errors(t *testing.T) {
	boom := errors.New("pg down")
	disp := &recordingDispatcher{}
	err := (&SuppressionExpiryWorker{suppressions: &fakeExpiring{dueErr: boom}, notify: disp}).Work(context.Background(), expiryJob)
	require.ErrorIs(t, err, boom)
	require.Empty(t, disp.sent)

	src := &fakeExpiring{due: []suppress.Suppression{{FindingID: "f1"}}, markErr: boom}
	err = (&SuppressionExpiryWorker{suppressions: src, notify: disp}).Work(context.Background(), expiryJob)
	require.ErrorIs(t, err, boom, "a failed mark surfaces, so the retry re-announces rather than going silent")
}

func TestSuppressionExpiryNotification_CapsListedEntries(t *testing.T) {
	due := make([]suppress.Suppression, suppressionNoticeMaxListed+3)
	for i := range due {
		due[i] = suppress.Suppression{FindingID: fmt.Sprintf("f%d", i)}
	}
	n := suppressionExpiryNotification(due)
	require.Len(t, n.Fields, suppressionNoticeMaxListed+1)
	require.Equal(t, "3 more", n.Fields[suppressionNoticeMaxListed].Value)
	require.Contains(t, n.Title, "13 finding suppressions")

	one := suppressionExpiryNotification(due[:1])
	require.Equal(t, "1 finding suppression expires within 14 days", one.Title)
}

func TestSuppressionExpiryPeriodic_RunsOnStartOnTheFeedsLane(t *testing.T) {
	args, opts, runOnStart := periodicByKind(t, buildPeriodicJobs(PeriodicConfig{}), SuppressionExpiryArgs{}.Kind())
	require.NotNil(t, args, "the expiry notice is unconditional")
	require.True(t, runOnStart, "a daily interval never elapses on a worker that restarts more often")
	require.NotNil(t, opts)
	require.Equal(t, queueFeeds, opts.Queue)
	require.False(t, opts.ScheduledAt.IsZero(), "offset past the boot storm")
}

// A notice no channel delivered is not marked sent: the next run re-announces
// it rather than the expiry going unseen.
func TestSuppressionExpiryWorker_UndeliveredStaysDue(t *testing.T) {
	src := &fakeExpiring{due: []suppress.Suppression{{FindingID: "f1"}}}
	require.NoError(t, (&SuppressionExpiryWorker{suppressions: src, notify: &recordingDispatcher{none: true}}).Work(context.Background(), expiryJob))
	require.Empty(t, src.marked, "every channel failed — nothing is marked sent")

	boom := errors.New("pg down")
	err := (&SuppressionExpiryWorker{suppressions: src, notify: &recordingDispatcher{err: boom}}).Work(context.Background(), expiryJob)
	require.ErrorIs(t, err, boom)
	require.Empty(t, src.marked)
}

// The real notify service reports delivery; a dispatcher that cannot leaves
// the worker unwired rather than guessing.
func TestNoticeDeliverer(t *testing.T) {
	require.NotNil(t, noticeDeliverer(&notify.Service{}))
	require.Nil(t, noticeDeliverer(dispatchOnly{}))
	require.Nil(t, noticeDeliverer(nil))
}

type dispatchOnly struct{}

func (dispatchOnly) Dispatch(context.Context, notify.Notification) {}
