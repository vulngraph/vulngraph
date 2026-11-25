package enrichcache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

type PGRepo struct {
	q    *sqlcgen.Queries
	pool *pgxpool.Pool
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool), pool: pool} }

func (r *PGRepo) Get(ctx context.Context, findingID string) (Entry, error) {
	row, err := r.q.GetEnrichCache(ctx, findingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, fmt.Errorf("Get: %w", err)
	}
	return Entry{
		FindingID:  row.FindingID,
		InputFP:    row.InputFp,
		ContextFP:  row.ContextFp,
		ScoreBand:  row.ScoreBand,
		EnrichedAt: row.EnrichedAt,
		Graph: GraphContext{
			Exposed:       row.GraphExposed,
			PrivescBucket: row.GraphPrivesc,
			ReachBucket:   row.GraphReach,
		},
	}, nil
}

func (r *PGRepo) Upsert(ctx context.Context, e Entry) error {
	err := r.q.UpsertEnrichCache(ctx, sqlcgen.UpsertEnrichCacheParams{
		FindingID:    e.FindingID,
		InputFp:      e.InputFP,
		ContextFp:    e.ContextFP,
		ScoreBand:    e.ScoreBand,
		EnrichedAt:   e.EnrichedAt,
		GraphExposed: e.Graph.Exposed,
		GraphPrivesc: e.Graph.PrivescBucket,
		GraphReach:   e.Graph.ReachBucket,
	})
	if err != nil {
		return fmt.Errorf("Upsert: %w", err)
	}
	return nil
}

// LastFullPassVersion returns the enrichment LogicVersion that a full corpus pass
// last completed for, or "" if none ever has. Raw pool query rather than sqlc: a
// one-line operational read that would otherwise need a codegen round-trip.
func (r *PGRepo) LastFullPassVersion(ctx context.Context) (string, error) {
	var v string
	err := r.pool.QueryRow(ctx, `SELECT version FROM enrich_logic_version WHERE id`).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		// Migration seeds one row, so this means someone deleted it. Treat as
		// "never passed" — re-running a full pass is safe, skipping one is not.
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("LastFullPassVersion: %w", err)
	}
	return v, nil
}

// SetLastFullPassVersion records that a full corpus pass completed for version v.
// Called ONLY after a successful pass — recording it up-front would let a crashed
// pass permanently mask the fact that the corpus was never converged.
func (r *PGRepo) SetLastFullPassVersion(ctx context.Context, v string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE enrich_logic_version SET version = $1, applied_at = now() WHERE id`, v)
	if err != nil {
		return fmt.Errorf("SetLastFullPassVersion: %w", err)
	}
	return nil
}

// InvalidateFingerprints clears the stored input fingerprint of the given
// findings, forcing their next enrich past the change-gate. The row itself
// survives — deleting it (as this path once did) also erased the stored graph
// context and score band, so the next enrich looked like a brand-new finding.
func (r *PGRepo) InvalidateFingerprints(ctx context.Context, findingIDs []string) error {
	if len(findingIDs) == 0 {
		return nil
	}
	if err := r.q.InvalidateEnrichFingerprints(ctx, findingIDs); err != nil {
		return fmt.Errorf("InvalidateFingerprints: %w", err)
	}
	return nil
}

// AlertState returns the urgency a finding last alerted at, or ErrNotFound if
// it never alerted.
func (r *PGRepo) AlertState(ctx context.Context, findingID string) (AlertState, error) {
	row, err := r.q.GetFindingAlertState(ctx, findingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return AlertState{}, ErrNotFound
	}
	if err != nil {
		return AlertState{}, fmt.Errorf("AlertState: %w", err)
	}
	return AlertState{FindingID: row.FindingID, ScoreBand: row.ScoreBand, MustFixClass: row.MustFixClass, AlertedAt: row.AlertedAt}, nil
}

// RecordAlert stores the urgency a finding just alerted at.
func (r *PGRepo) RecordAlert(ctx context.Context, s AlertState) error {
	err := r.q.UpsertFindingAlertState(ctx, sqlcgen.UpsertFindingAlertStateParams{
		FindingID: s.FindingID, ScoreBand: s.ScoreBand, MustFixClass: s.MustFixClass, AlertedAt: s.AlertedAt,
	})
	if err != nil {
		return fmt.Errorf("RecordAlert: %w", err)
	}
	return nil
}

// ClearAlertStates forgets the alert history of the given findings.
func (r *PGRepo) ClearAlertStates(ctx context.Context, findingIDs []string) error {
	if len(findingIDs) == 0 {
		return nil
	}
	if err := r.q.DeleteFindingAlertStates(ctx, findingIDs); err != nil {
		return fmt.Errorf("ClearAlertStates: %w", err)
	}
	return nil
}

// PruneAlertStates drops alert state for findings not enriched since olderThan
// and returns how many rows went.
func (r *PGRepo) PruneAlertStates(ctx context.Context, olderThan time.Time) (int64, error) {
	n, err := r.q.PruneFindingAlertStates(ctx, olderThan)
	if err != nil {
		return 0, fmt.Errorf("PruneAlertStates: %w", err)
	}
	return n, nil
}
