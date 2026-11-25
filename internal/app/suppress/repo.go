package suppress

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// PGRepo implements Repo on Postgres.
type PGRepo struct {
	q *sqlcgen.Queries
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool)} }

func (r *PGRepo) Upsert(ctx context.Context, s Suppression) (Suppression, error) {
	row, err := r.q.UpsertSuppression(ctx, sqlcgen.UpsertSuppressionParams{
		FindingID:    s.FindingID,
		Reason:       s.Reason,
		SuppressedBy: s.SuppressedBy,
		ExpiresAt:    s.ExpiresAt,
	})
	if err != nil {
		return Suppression{}, fmt.Errorf("Upsert: %w", err)
	}
	return toSuppression(row), nil
}

// Review moves a suppression's expiry and stamps who reviewed it. ErrNotFound
// when the finding has no suppression row (expired rows are kept, so an expired
// suppression can be renewed).
func (r *PGRepo) Review(ctx context.Context, findingID, by string, expiresAt time.Time) (Suppression, error) {
	row, err := r.q.ReviewSuppression(ctx, sqlcgen.ReviewSuppressionParams{
		FindingID: findingID, ExpiresAt: expiresAt, ReviewedBy: by,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Suppression{}, ErrNotFound
		}
		return Suppression{}, fmt.Errorf("Review: %w", err)
	}
	return toSuppression(row), nil
}

func (r *PGRepo) Delete(ctx context.Context, findingID string) error {
	n, err := r.q.DeleteSuppression(ctx, findingID)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *PGRepo) Get(ctx context.Context, findingID string) (Suppression, error) {
	row, err := r.q.GetSuppression(ctx, findingID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Suppression{}, ErrNotFound
		}
		return Suppression{}, fmt.Errorf("Get: %w", err)
	}
	return toSuppression(row), nil
}

func (r *PGRepo) List(ctx context.Context) ([]Suppression, error) {
	rows, err := r.q.ListSuppressions(ctx)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	out := make([]Suppression, len(rows))
	for i, row := range rows {
		out[i] = toSuppression(row)
	}
	return out, nil
}

// Expiries returns every suppressed finding id with its expiry — the minimal
// read for splitting a finding list into active and expired suppressions.
func (r *PGRepo) Expiries(ctx context.Context) (map[string]time.Time, error) {
	rows, err := r.q.ListSuppressionExpiries(ctx)
	if err != nil {
		return nil, fmt.Errorf("Expiries: %w", err)
	}
	out := make(map[string]time.Time, len(rows))
	for _, row := range rows {
		out[row.FindingID] = row.ExpiresAt
	}
	return out, nil
}

// DueExpiryNotice lists suppressions with after < expires_at <= until whose
// current expiry has not been announced yet, soonest first.
func (r *PGRepo) DueExpiryNotice(ctx context.Context, after, until time.Time) ([]Suppression, error) {
	rows, err := r.q.ListSuppressionsDueExpiryNotice(ctx, sqlcgen.ListSuppressionsDueExpiryNoticeParams{
		After: after, Until: until,
	})
	if err != nil {
		return nil, fmt.Errorf("DueExpiryNotice: %w", err)
	}
	out := make([]Suppression, len(rows))
	for i, row := range rows {
		out[i] = toSuppression(row)
	}
	return out, nil
}

// MarkExpiryNotified records that the expiry notice for each id's current
// expiry went out. Moving the expiry (re-suppress or review) clears it.
func (r *PGRepo) MarkExpiryNotified(ctx context.Context, findingIDs []string) error {
	if err := r.q.MarkSuppressionExpiryNotified(ctx, findingIDs); err != nil {
		return fmt.Errorf("MarkExpiryNotified: %w", err)
	}
	return nil
}

// insertAudit appends to the shared audit trail. Same table and column order as
// respond's decision trail — one table, one shape.
const insertAudit = `INSERT INTO audit_events (id, ts, actor, action, target_type, target_id, details)`

const auditWriteTimeout = 5 * time.Second

// CHAuditRepo persists suppression audit events in ClickHouse. Suppression
// state lives in Postgres; the audit trail lives with every other audit row.
type CHAuditRepo struct {
	ch *db.CH
}

func NewCHAuditRepo(ch *db.CH) *CHAuditRepo { return &CHAuditRepo{ch: ch} }

// RecordAudit appends one audit event.
func (r *CHAuditRepo) RecordAudit(ctx context.Context, e AuditEvent) error {
	id := dbutil.DeterministicID(e.TargetID, e.Action, e.Actor, e.TS.Format(time.RFC3339Nano))

	// Bounded independently of the caller: the state change is already committed
	// to Postgres, so a cancelled request must not drop the audit row.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()

	err := r.ch.Batch(writeCtx, insertAudit, func(b driver.Batch) error {
		return b.Append(id, e.TS, e.Actor, e.Action, e.TargetType, e.TargetID, e.Details)
	})
	if err != nil {
		return fmt.Errorf("RecordAudit: %w", err)
	}
	return nil
}

func toSuppression(row sqlcgen.FindingSuppression) Suppression {
	return Suppression{
		FindingID:    row.FindingID,
		Reason:       row.Reason,
		SuppressedBy: row.SuppressedBy,
		SuppressedAt: row.SuppressedAt,
		ExpiresAt:    row.ExpiresAt,
		// NULL last_reviewed_at = never reviewed → zero time.
		LastReviewedAt: row.LastReviewedAt.Time,
		ReviewedBy:     row.ReviewedBy,
	}
}
