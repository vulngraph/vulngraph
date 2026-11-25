package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	// suppressionExpiryInterval: the notice window is 14 days, so a daily check
	// gives every expiring suppression about two weeks of warning.
	suppressionExpiryInterval = 24 * time.Hour
	// suppressionNoticeMaxListed caps how many suppressions one notification
	// names; the title carries the full count.
	suppressionNoticeMaxListed = 10
)

// SuppressionExpiryArgs announces finding suppressions that expire within
// suppress.ExpiryNoticeWindow, so someone reviews them before the findings
// reappear.
type SuppressionExpiryArgs struct{}

func (SuppressionExpiryArgs) Kind() string { return "suppression_expiry" }

// InsertOpts: the feeds lane carries the other light daily ticks; this is one
// Postgres read and one dispatch. MaxAttempts 2 — the next daily tick is the
// real retry.
func (SuppressionExpiryArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueFeeds, 2)
}

// ExpiringSuppressions lists the suppressions whose expiry notice is due and
// records that it went out. *suppress.Service implements it.
type ExpiringSuppressions interface {
	ExpiryNoticesDue(ctx context.Context) ([]suppress.Suppression, error)
	MarkExpiryNoticesSent(ctx context.Context, findingIDs []string) error
}

// NoticeDeliverer sends a notification and reports how many channels
// delivered it. *notify.Service implements it.
type NoticeDeliverer interface {
	Deliver(ctx context.Context, n notify.Notification) (int, error)
}

// noticeDeliverer narrows the alert dispatcher to one that can report
// delivery. A dispatcher that cannot leaves the worker unwired — every notice
// stays due — rather than marking notices sent that may never have arrived.
func noticeDeliverer(d AlertDispatcher) NoticeDeliverer {
	nd, ok := d.(NoticeDeliverer)
	if !ok {
		return nil
	}
	return nd
}

// expiringSuppressions keeps a nil *suppress.Service a nil interface, so Work's
// nil check sees it instead of calling through a typed nil.
func expiringSuppressions(s *suppress.Service) ExpiringSuppressions {
	if s == nil {
		return nil
	}
	return s
}

// SuppressionExpiryWorker dispatches one notification per run naming the
// suppressions about to expire. Each expiry is announced once: the sent mark is
// what makes RunOnStart safe on a worker that restarts several times a day.
// The mark is written only when at least one channel delivered the notice — a
// failed delivery leaves the notices due for the next run.
type SuppressionExpiryWorker struct {
	river.WorkerDefaults[SuppressionExpiryArgs]
	suppressions ExpiringSuppressions
	notify       NoticeDeliverer
}

func (w *SuppressionExpiryWorker) Timeout(_ *river.Job[SuppressionExpiryArgs]) time.Duration {
	return 2 * time.Minute
}

func (w *SuppressionExpiryWorker) Work(ctx context.Context, _ *river.Job[SuppressionExpiryArgs]) error {
	// No dispatcher: leave every notice due, so wiring one later still
	// announces what is about to expire rather than marking it sent unseen.
	if w.suppressions == nil || w.notify == nil {
		return nil
	}
	due, err := w.suppressions.ExpiryNoticesDue(ctx)
	if err != nil {
		return fmt.Errorf("suppression_expiry: %w", err)
	}
	if len(due) == 0 {
		return nil
	}
	delivered, err := w.notify.Deliver(ctx, suppressionExpiryNotification(due))
	if err != nil {
		return fmt.Errorf("suppression_expiry: %w", err)
	}
	if delivered == 0 {
		log.FromContext(ctx).Warn().Int("expiring", len(due)).
			Msg("suppression expiry notice not delivered to any channel — left due for the next run")
		return nil
	}
	ids := make([]string, len(due))
	for i, s := range due {
		ids[i] = s.FindingID
	}
	if err := w.suppressions.MarkExpiryNoticesSent(ctx, ids); err != nil {
		return fmt.Errorf("suppression_expiry: %w", err)
	}
	log.FromContext(ctx).Info().Int("expiring", len(due)).Msg("suppression expiry notice dispatched")
	return nil
}

// suppressionExpiryNotification names the soonest-expiring suppressions (due is
// soonest first) and counts the rest.
func suppressionExpiryNotification(due []suppress.Suppression) notify.Notification {
	fields := make([]notify.Field, 0, min(len(due), suppressionNoticeMaxListed)+1)
	for _, s := range due[:min(len(due), suppressionNoticeMaxListed)] {
		fields = append(fields, notify.Field{
			Label: s.FindingID,
			Value: "expires " + s.ExpiresAt.UTC().Format("2006-01-02") + " — " + s.Reason,
		})
	}
	if extra := len(due) - suppressionNoticeMaxListed; extra > 0 {
		fields = append(fields, notify.Field{Label: "And", Value: fmt.Sprintf("%d more", extra)})
	}
	noun := "suppressions expire"
	if len(due) == 1 {
		noun = "suppression expires"
	}
	return notify.Notification{
		EventType: notify.EventSuppressionExpiry,
		Severity:  notify.SeverityMedium,
		Title:     fmt.Sprintf("%d finding %s within 14 days", len(due), noun),
		Message: "Review each one: renew it if the exception still holds, or let it lapse " +
			"and the finding returns to the pipeline.",
		Fields: fields,
	}
}
