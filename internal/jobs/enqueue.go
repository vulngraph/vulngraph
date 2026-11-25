package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// EnqueueSyncsArgs is the periodic tick that fans out one SyncConnectorArgs per
// enabled connector — the reconciliation sweep.
type EnqueueSyncsArgs struct{}

func (EnqueueSyncsArgs) Kind() string { return "enqueue_syncs" }

func (EnqueueSyncsArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueSync, 3)
}

// backoffCeiling is the hardest possible cap on how long an enabled connector
// can go between actual collection attempts, no matter how long its clean
// streak. Deliberately well under connector.DefaultStaleAfter (the Stale()
// alert threshold) so a maximally-backed-off healthy connector never sits at
// the edge of that threshold, where ordinary scheduling jitter could tip it
// into a false "stale" alert. It's also an independent correctness backstop:
// asset.ConnectorFingerprint is not provably exhaustive of every
// security-relevant provider-side signal, so no enabled connector should ever
// be allowed to go longer than this without at least trying to look again.
const backoffCeiling = 12 * time.Hour

// backoffInterval returns how long a connector with the given consecutive
// clean-sync streak (connector.Connector.SyncStreak) must wait between
// periodic sweeps, given the configured base interval. Requires 3 consecutive
// clean syncs before backing off at all, so a fingerprint that happens to
// match once by coincidence can't immediately start a long skip streak.
// Steps to x2, x4 and x6 the base at streaks 3, 6 and 12, always clamped to
// backoffCeiling regardless of base or streak (so a base above 12h is also
// capped at 12h).
//
// The streak counts consecutive clean SYNCS, not elapsed quiet wall-clock
// time: a connector synced frequently via a manual trigger or webhook
// advances its streak on activity, not idle time, so it can reach a deep
// backoff faster than "N * base of actual quiet" would suggest. Not a
// correctness hole (LastSyncedAt is still the real anchor isDueForSync
// compares against), just a reason the loudest connectors back off their
// periodic backstop sooner than a quieter one with the same streak count.
func backoffInterval(streak int, base time.Duration) time.Duration {
	var multiplier time.Duration
	switch {
	case streak >= 12:
		multiplier = 6
	case streak >= 6:
		multiplier = 4
	case streak >= 3:
		multiplier = 2
	default:
		multiplier = 1
	}
	if interval := base * multiplier; interval < backoffCeiling {
		return interval
	}
	return backoffCeiling
}

// isDueForSync reports whether the periodic sweep should enqueue a sync for
// c right now. A connector that has never synced (LastSyncedAt == nil) is
// always due, regardless of SyncStreak — a new connector must get its first
// sync immediately, not wait out some notion of backoff it hasn't earned.
//
// This deliberately does NOT gate manual "sync now" triggers or event/webhook
// -driven syncs — both insert SyncConnectorArgs directly via
// Enqueuer.EnqueueSync and never call this function; the backoff applies only
// to this periodic sweep's own decision to enqueue.
func isDueForSync(c connector.Connector, base time.Duration, now time.Time) bool {
	if c.LastSyncedAt == nil {
		return true
	}
	return now.Sub(*c.LastSyncedAt) >= backoffInterval(int(c.SyncStreak), base)
}

// EnqueueWorker lists enabled connectors and inserts a sync job for each one
// isDueForSync says is actually due — not every one, unconditionally, every
// tick. Most sweeps change nothing, and the existing sync_fingerprint only
// ever skips the downstream write, never the API cost of collection itself;
// this backoff gets most of the benefit of skipping collection using just the
// fingerprint signal already computed, no new provider integration.
// SyncConnectorArgs is unique-while-queued, so a connector already pending is
// not enqueued twice.
type EnqueueWorker struct {
	river.WorkerDefaults[EnqueueSyncsArgs]
	connectors       *connector.Service
	baseSyncInterval time.Duration
}

// Timeout overrides River's 1-minute default: enqueuing syncs for every
// connector does a list + one insert each in a transaction, and under DB
// contention that can brush past a minute.
func (EnqueueWorker) Timeout(_ *river.Job[EnqueueSyncsArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *EnqueueWorker) Work(ctx context.Context, _ *river.Job[EnqueueSyncsArgs]) error {
	conns, err := w.connectors.List(ctx, true)
	if err != nil {
		return fmt.Errorf("Work: list connectors: %w", err)
	}

	base := w.baseSyncInterval
	if base <= 0 {
		base = defaultSyncInterval
	}

	client := river.ClientFromContext[pgx.Tx](ctx)
	now := time.Now()
	enqueued, skippedBackoff := 0, 0
	for _, c := range conns {
		// An aws_org connector has no collector: DiscoverAWSOrgsArgs is its
		// sync, and it syncs the org's children, which are listed here.
		if c.Type == connector.TypeAWSOrg {
			continue
		}
		if !isDueForSync(c, base, now) {
			skippedBackoff++
			continue
		}
		if _, err := client.Insert(ctx, SyncConnectorArgs{ConnectorID: c.ID}, nil); err != nil {
			return fmt.Errorf("Work: enqueue sync for %s: %w", c.ID, err)
		}
		enqueued++
	}
	log.FromContext(ctx).Info().Int("connectors", enqueued).Int("skipped_backoff", skippedBackoff).
		Msg("sync sweep enqueued")
	return nil
}
