package reasoncache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

type PGRepo struct {
	q    *sqlcgen.Queries
	pool *pgxpool.Pool
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool), pool: pool} }

func (r *PGRepo) Get(ctx context.Context, findingID string) (Entry, error) {
	row, err := r.q.GetReasoningCache(ctx, findingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, fmt.Errorf("Get: %w", err)
	}
	return entryFromRow(row), nil
}

// ListPending returns the cached decisions awaiting a human governor
// (parked-for-approval or escalated), newest first, capped at limit.
// actionClass narrows the scan to a single action class server-side, ahead of
// the cap — "" means unfiltered.
func (r *PGRepo) ListPending(ctx context.Context, limit int, actionClass string) ([]Entry, error) {
	var ac pgtype.Text
	if actionClass != "" {
		ac = pgtype.Text{String: actionClass, Valid: true}
	}
	rows, err := r.q.ListPendingReasoning(ctx, sqlcgen.ListPendingReasoningParams{
		Limit:       int32(limit),
		ActionClass: ac,
	})
	if err != nil {
		return nil, fmt.Errorf("ListPending: %w", err)
	}
	out := make([]Entry, len(rows))
	for i, row := range rows {
		out[i] = entryFromRow(row)
	}
	return out, nil
}

// TopEscalatedRepeats returns the escalated entries with the highest repeat
// count, ordered by RepeatCount DESC (newest-repeated-first isn't guaranteed).
// Repeats are not individually audited, so a COUNT over audit_events can't see
// them — this counter can.
func (r *PGRepo) TopEscalatedRepeats(ctx context.Context, limit int) ([]Entry, error) {
	rows, err := r.q.TopEscalatedRepeats(ctx, int32(limit))
	if err != nil {
		return nil, fmt.Errorf("TopEscalatedRepeats: %w", err)
	}
	out := make([]Entry, len(rows))
	for i, row := range rows {
		out[i] = entryFromRow(row)
	}
	return out, nil
}

func (r *PGRepo) Upsert(ctx context.Context, e Entry) error {
	concerns := e.CoVeConcerns
	if concerns == nil {
		concerns = []string{}
	}
	err := r.q.UpsertReasoningCache(ctx, sqlcgen.UpsertReasoningCacheParams{
		FindingID:        e.FindingID,
		Fingerprint:      e.Fingerprint,
		PlanActionClass:  e.ActionClass,
		PlanSummary:      e.Summary,
		PlanRationale:    e.Rationale,
		Outcome:          e.Outcome,
		ConfidenceBand:   e.ConfidenceBand,
		ConfidenceScore:  e.ConfidenceScore,
		EffectiveN:       e.EffectiveN,
		SampleCount:      int32(e.SampleCount),
		BlastRadius:      int32(e.BlastRadius),
		BlastRadiusKnown: e.BlastRadiusKnown,
		CoveConcerns:     concerns,
		DecidedAt:        e.DecidedAt,
		SafetyBand:       e.SafetyBand,
		EscalationReason: e.EscalationReason,
	})
	if err != nil {
		return fmt.Errorf("Upsert: %w", err)
	}
	return nil
}

// IncrementRepeat bumps repeat_count and stamps last_repeated_at = now() for
// findingID. Called from the respond.Decide repeat-decision skip path — a
// byte-identical repeat that is not itself audited still needs to register
// somewhere, or the escalation-hotspot signal goes blind.
func (r *PGRepo) IncrementRepeat(ctx context.Context, findingID string) error {
	if err := r.q.IncrementReasoningCacheRepeat(ctx, findingID); err != nil {
		return fmt.Errorf("IncrementRepeat: %w", err)
	}
	return nil
}

// DeleteForFindings removes cache entries for the given finding IDs, forcing
// a cache miss on the next Decide. Raw pool query (like enrichcache's
// equivalent) rather than sqlc, for a variadic-length delete that doesn't
// warrant a codegen round-trip.
func (r *PGRepo) DeleteForFindings(ctx context.Context, findingIDs []string) error {
	if len(findingIDs) == 0 {
		return nil
	}
	_, err := r.pool.Exec(ctx,
		`DELETE FROM reasoning_cache WHERE finding_id = ANY($1::text[])`,
		findingIDs,
	)
	if err != nil {
		return fmt.Errorf("DeleteForFindings: %w", err)
	}
	return nil
}

// PurgeAll deletes every reasoning-cache entry, unconditionally — the
// reconciliation lever for a LogicVersion bump (see LogicVersion's doc
// comment and Service.InvalidateAll). Returns the number of rows removed.
func (r *PGRepo) PurgeAll(ctx context.Context) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM reasoning_cache`)
	if err != nil {
		return 0, fmt.Errorf("PurgeAll: %w", err)
	}
	return tag.RowsAffected(), nil
}

func entryFromRow(row sqlcgen.ReasoningCache) Entry {
	var lastRepeated time.Time
	if row.LastRepeatedAt.Valid {
		lastRepeated = row.LastRepeatedAt.Time
	}
	return Entry{
		FindingID:        row.FindingID,
		Fingerprint:      row.Fingerprint,
		ActionClass:      row.PlanActionClass,
		Summary:          row.PlanSummary,
		Rationale:        row.PlanRationale,
		Outcome:          row.Outcome,
		ConfidenceBand:   row.ConfidenceBand,
		ConfidenceScore:  row.ConfidenceScore,
		EffectiveN:       row.EffectiveN,
		SampleCount:      int(row.SampleCount),
		BlastRadius:      int(row.BlastRadius),
		BlastRadiusKnown: row.BlastRadiusKnown,
		CoVeConcerns:     row.CoveConcerns,
		SafetyBand:       row.SafetyBand,
		DecidedAt:        row.DecidedAt,
		RepeatCount:      int(row.RepeatCount),
		LastRepeatedAt:   lastRepeated,
		EscalationReason: row.EscalationReason,
	}
}
