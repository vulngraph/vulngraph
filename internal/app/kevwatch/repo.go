package kevwatch

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// PGRepo stores the catalog and the additions on Postgres:
// mutable, small, and transactional with a future River insert of the agent
// run each addition triggers.
type PGRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{pool: pool, q: sqlcgen.New(pool)} }

// KnownCVEs returns every CVE already in kev_catalog.
func (r *PGRepo) KnownCVEs(ctx context.Context) (map[string]bool, error) {
	ids, err := r.q.ListKEVCatalogCVEs(ctx)
	if err != nil {
		return nil, fmt.Errorf("KnownCVEs: %w", err)
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// Commit upserts the catalog and inserts the additions in one transaction,
// returning only the additions this call inserted (one already recorded is
// skipped, never re-emitted).
func (r *PGRepo) Commit(ctx context.Context, entries []Entry, additions []Addition) ([]Addition, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("Commit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := r.q.WithTx(tx)

	cat := sqlcgen.UpsertKEVCatalogParams{}
	for _, e := range entries {
		cat.CveIds = append(cat.CveIds, e.CVEID)
		cat.DatesAdded = append(cat.DatesAdded, e.DateAdded)
		cat.Names = append(cat.Names, e.Name)
	}
	if err := q.UpsertKEVCatalog(ctx, cat); err != nil {
		return nil, fmt.Errorf("Commit: catalog: %w", err)
	}

	var inserted []Addition
	if len(additions) > 0 {
		ev := sqlcgen.InsertKEVAddedEventsParams{}
		for _, a := range additions {
			ev.CveIds = append(ev.CveIds, a.CVEID)
			ev.DatesAdded = append(ev.DatesAdded, a.DateAdded)
			ev.Names = append(ev.Names, a.Name)
			ev.OpenFindings = append(ev.OpenFindings, int32(min(a.OpenFindings, 1<<31-1)))
		}
		rows, err := q.InsertKEVAddedEvents(ctx, ev)
		if err != nil {
			return nil, fmt.Errorf("Commit: events: %w", err)
		}
		for _, row := range rows {
			inserted = append(inserted, toAddition(row))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("Commit: %w", err)
	}
	return inserted, nil
}

// ListAdditions returns the most recently detected additions first.
func (r *PGRepo) ListAdditions(ctx context.Context, limit int) ([]Addition, error) {
	rows, err := r.q.ListKEVAddedEvents(ctx, int32(min(limit, MaxListLimit)))
	if err != nil {
		return nil, fmt.Errorf("ListAdditions: %w", err)
	}
	out := make([]Addition, len(rows))
	for i, row := range rows {
		out[i] = toAddition(row)
	}
	return out, nil
}

func toAddition(row sqlcgen.KevAddedEvent) Addition {
	return Addition{
		CVEID:        row.CveID,
		DateAdded:    timeOrZero(row.DateAdded),
		Name:         row.Name,
		OpenFindings: int(row.OpenFindings),
		DetectedAt:   row.DetectedAt,
	}
}

func timeOrZero(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time.UTC()
}
