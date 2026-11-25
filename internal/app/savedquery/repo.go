package savedquery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGRepo persists saved queries and their run history in Postgres.
type PGRepo struct {
	pool *pgxpool.Pool
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{pool: pool} }

const queryCols = `id, name, description, cypher, created_by, schedule,
	alert_channel_ids, alert_on_change, alert_severity, enabled, last_run_at,
	last_result_count, last_result_hash, created_at, updated_at`

// selectQueries reads saved queries from the relation %s (the table, or a
// data-modifying CTE's RETURNING) with each one's newest run, so the response
// can show the latest attempt next to the baseline. The lateral read is one
// index probe per query (idx_saved_query_runs_query).
const selectQueries = `SELECT q.id, q.name, q.description, q.cypher, q.created_by, q.schedule,
	q.alert_channel_ids, q.alert_on_change, q.alert_severity, q.enabled, q.last_run_at,
	q.last_result_count, q.last_result_hash, q.created_at, q.updated_at,
	lr.id, lr.ran_at, lr.node_count, lr.edge_count, lr.trigger, lr.error
	FROM %s q
	LEFT JOIN LATERAL (
		SELECT r.id, r.ran_at, r.node_count, r.edge_count, r.trigger, r.error
		FROM saved_query_runs r WHERE r.saved_query_id = q.id
		ORDER BY r.ran_at DESC, r.id DESC LIMIT 1
	) lr ON TRUE`

type scannable interface{ Scan(dest ...any) error }

func scanQuery(row scannable) (SavedQuery, error) {
	var q SavedQuery
	var runID, runTrigger, runError *string
	var runAt *time.Time
	var runNodes, runEdges *int
	err := row.Scan(
		&q.ID, &q.Name, &q.Description, &q.Cypher, &q.CreatedBy, &q.Schedule,
		&q.AlertChannelIDs, &q.AlertOnChange, &q.AlertSeverity, &q.Enabled, &q.LastRunAt,
		&q.LastResultCount, &q.LastResultHash, &q.CreatedAt, &q.UpdatedAt,
		&runID, &runAt, &runNodes, &runEdges, &runTrigger, &runError,
	)
	if err != nil {
		return SavedQuery{}, err
	}
	if runID != nil {
		q.LastAttempt = &Run{
			ID: *runID, SavedQueryID: q.ID, RanAt: *runAt, NodeCount: *runNodes,
			EdgeCount: *runEdges, Trigger: *runTrigger, Error: *runError,
		}
	}
	return q, nil
}

func (r *PGRepo) Create(ctx context.Context, q SavedQuery) (SavedQuery, error) {
	ids := q.AlertChannelIDs
	if ids == nil {
		ids = []string{}
	}
	row := r.pool.QueryRow(ctx,
		`WITH created AS (INSERT INTO saved_queries
			(name, description, cypher, created_by, schedule, alert_channel_ids, alert_on_change, alert_severity, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 RETURNING `+queryCols+`) `+fmt.Sprintf(selectQueries, "created"),
		q.Name, q.Description, q.Cypher, q.CreatedBy, q.Schedule, ids, q.AlertOnChange, q.AlertSeverity, q.Enabled,
	)
	out, err := scanQuery(row)
	if err != nil {
		return SavedQuery{}, fmt.Errorf("Create: %w", err)
	}
	return out, nil
}

func (r *PGRepo) Update(ctx context.Context, q SavedQuery) (SavedQuery, error) {
	ids := q.AlertChannelIDs
	if ids == nil {
		ids = []string{}
	}
	row := r.pool.QueryRow(ctx,
		`WITH updated AS (UPDATE saved_queries
		 SET name=$2, description=$3, cypher=$4, schedule=$5, alert_channel_ids=$6,
		     alert_on_change=$7, alert_severity=$8, enabled=$9, updated_at=now()
		 WHERE id=$1
		 RETURNING `+queryCols+`) `+fmt.Sprintf(selectQueries, "updated"),
		q.ID, q.Name, q.Description, q.Cypher, q.Schedule, ids, q.AlertOnChange, q.AlertSeverity, q.Enabled,
	)
	out, err := scanQuery(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SavedQuery{}, ErrNotFound
		}
		return SavedQuery{}, fmt.Errorf("Update: %w", err)
	}
	return out, nil
}

func (r *PGRepo) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM saved_queries WHERE id=$1`, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *PGRepo) Get(ctx context.Context, id string) (SavedQuery, error) {
	row := r.pool.QueryRow(ctx, fmt.Sprintf(selectQueries, "saved_queries")+` WHERE q.id=$1`, id)
	q, err := scanQuery(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SavedQuery{}, ErrNotFound
		}
		return SavedQuery{}, fmt.Errorf("Get: %w", err)
	}
	return q, nil
}

func (r *PGRepo) List(ctx context.Context) ([]SavedQuery, error) {
	rows, err := r.pool.Query(ctx, fmt.Sprintf(selectQueries, "saved_queries")+` ORDER BY q.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	defer rows.Close()
	var out []SavedQuery
	for rows.Next() {
		q, err := scanQuery(rows)
		if err != nil {
			return nil, fmt.Errorf("List scan: %w", err)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// ListScheduled returns enabled queries that have a cron schedule — the set the
// periodic dispatcher evaluates each tick.
func (r *PGRepo) ListScheduled(ctx context.Context) ([]SavedQuery, error) {
	rows, err := r.pool.Query(ctx,
		fmt.Sprintf(selectQueries, "saved_queries")+` WHERE q.enabled = TRUE AND q.schedule != ''`)
	if err != nil {
		return nil, fmt.Errorf("ListScheduled: %w", err)
	}
	defer rows.Close()
	var out []SavedQuery
	for rows.Next() {
		q, err := scanQuery(rows)
		if err != nil {
			return nil, fmt.Errorf("ListScheduled scan: %w", err)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// RecordRun appends a run-history row and, when advanceBaseline is set, moves
// the parent's last_* fields (the change-detection baseline) to this run in the
// same transaction so the baseline never drifts from the run log. A run that
// does not advance the baseline (failed, truncated, manual, undelivered alert)
// leaves last_* untouched: they always describe the last baseline run.
func (r *PGRepo) RecordRun(ctx context.Context, run Run, advanceBaseline bool) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("RecordRun: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`INSERT INTO saved_query_runs
			(saved_query_id, node_count, edge_count, result_hash, trigger, error)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		run.SavedQueryID, run.NodeCount, run.EdgeCount, run.ResultHash, run.Trigger, run.Error,
	); err != nil {
		return fmt.Errorf("RecordRun: insert: %w", err)
	}
	if !advanceBaseline {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("RecordRun: commit: %w", err)
		}
		return nil
	}
	if _, err := tx.Exec(ctx,
		`UPDATE saved_queries
		 SET last_run_at=now(), last_result_count=$2, last_result_hash=$3
		 WHERE id=$1`,
		run.SavedQueryID, run.NodeCount, run.ResultHash,
	); err != nil {
		return fmt.Errorf("RecordRun: update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("RecordRun: commit: %w", err)
	}
	return nil
}

// ListRuns returns the most recent runs for a query, newest first.
func (r *PGRepo) ListRuns(ctx context.Context, queryID string, limit int) ([]Run, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, saved_query_id, ran_at, node_count, edge_count, result_hash, trigger, error
		 FROM saved_query_runs WHERE saved_query_id=$1 ORDER BY ran_at DESC LIMIT $2`,
		queryID, limit)
	if err != nil {
		return nil, fmt.Errorf("ListRuns: %w", err)
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var run Run
		if err := rows.Scan(&run.ID, &run.SavedQueryID, &run.RanAt, &run.NodeCount,
			&run.EdgeCount, &run.ResultHash, &run.Trigger, &run.Error); err != nil {
			return nil, fmt.Errorf("ListRuns scan: %w", err)
		}
		out = append(out, run)
	}
	return out, rows.Err()
}
