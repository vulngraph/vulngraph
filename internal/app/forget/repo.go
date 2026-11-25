package forget

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGRepo stores the per-scope decision record and the tombstones.
//
// Raw pool queries rather than sqlc for the same reason enrichcache's
// LastFullPassVersion is: a handful of operational upserts over two tables that
// no other domain reads, where a codegen round-trip buys nothing.
type PGRepo struct{ pool *pgxpool.Pool }

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{pool: pool} }

// ScopeState is one stored row of forget_scope_state — the watermarks a
// decision needs from previous sweeps.
type ScopeState struct {
	LastCompleteAt time.Time
	PrevCompleteAt time.Time
	HighWater      int
	HighWaterAt    time.Time
}

const selectScopeStates = `
	SELECT scope, asset_type, last_complete_at, prev_complete_at,
	       enumerated_high_water, high_water_at
	FROM forget_scope_state WHERE connector_id = $1`

// ScopeStates loads every stored scope state for one connector, keyed by
// (scope, type). A connector with no rows yet returns an empty map, not an
// error: the first evaluation of a scope legitimately has no history, and it
// refuses on RefusalUnconfirmed for exactly that reason.
func (r *PGRepo) ScopeStates(ctx context.Context, connectorID string) (map[ScopeKey]ScopeState, error) {
	rows, err := r.pool.Query(ctx, selectScopeStates, connectorID)
	if err != nil {
		return nil, fmt.Errorf("ScopeStates: %w", err)
	}
	defer rows.Close()

	out := map[ScopeKey]ScopeState{}
	for rows.Next() {
		var (
			k    ScopeKey
			s    ScopeState
			prev *time.Time
		)
		if err := rows.Scan(&k.Scope, &k.AssetType, &s.LastCompleteAt, &prev,
			&s.HighWater, &s.HighWaterAt); err != nil {
			return nil, fmt.Errorf("ScopeStates: scan: %w", err)
		}
		if prev != nil {
			s.PrevCompleteAt = *prev
		}
		out[k] = s
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ScopeStates: rows: %w", err)
	}
	return out, nil
}

const upsertScopeState = `
	INSERT INTO forget_scope_state (
		connector_id, scope, asset_type, last_complete_at, prev_complete_at,
		enumerated, enumerated_high_water, high_water_at,
		stored, absent, confirmed, forgettable, refusal, evaluated_at)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
	ON CONFLICT (connector_id, scope, asset_type) DO UPDATE SET
		last_complete_at = EXCLUDED.last_complete_at,
		prev_complete_at = EXCLUDED.prev_complete_at,
		enumerated = EXCLUDED.enumerated,
		enumerated_high_water = EXCLUDED.enumerated_high_water,
		high_water_at = EXCLUDED.high_water_at,
		stored = EXCLUDED.stored,
		absent = EXCLUDED.absent,
		confirmed = EXCLUDED.confirmed,
		forgettable = EXCLUDED.forgettable,
		refusal = EXCLUDED.refusal,
		evaluated_at = EXCLUDED.evaluated_at`

// Record is one evaluated (scope, type) as it is persisted.
type Record struct {
	Scope          string
	AssetType      string
	LastCompleteAt time.Time
	PrevCompleteAt time.Time
	Enumerated     int
	HighWater      int
	HighWaterAt    time.Time
	Stored         int
	Absent         int
	Confirmed      int
	Forgettable    int
	Refusal        string
	EvaluatedAt    time.Time
}

// SaveRecords upserts one sweep's evaluations. Written one statement per record
// inside a single transaction: the record set per connector is small (one row
// per region and audited family), and a partially-written sweep
// would leave prev_complete_at inconsistent with last_complete_at, which is the
// pair the confirmation test reads.
func (r *PGRepo) SaveRecords(ctx context.Context, connectorID string, recs []Record) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("SaveRecords: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, rec := range recs {
		var prev any
		if !rec.PrevCompleteAt.IsZero() {
			prev = rec.PrevCompleteAt
		}
		if _, err := tx.Exec(ctx, upsertScopeState,
			connectorID, rec.Scope, rec.AssetType, rec.LastCompleteAt, prev,
			rec.Enumerated, rec.HighWater, rec.HighWaterAt,
			rec.Stored, rec.Absent, rec.Confirmed, rec.Forgettable,
			rec.Refusal, rec.EvaluatedAt); err != nil {
			return fmt.Errorf("SaveRecords: upsert %s/%s: %w", rec.Scope, rec.AssetType, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("SaveRecords: commit: %w", err)
	}
	return nil
}

const upsertTombstone = `
	INSERT INTO forget_tombstones (
		asset_id, connector_id, scope, asset_type, last_seen, believed_gone_at)
	VALUES ($1,$2,$3,$4,$5,$6)
	ON CONFLICT (asset_id) DO NOTHING`

// Tombstone is a recorded "believed gone at T". Never a deletion.
type Tombstone struct {
	AssetID   string
	Scope     string
	AssetType string
	LastSeen  time.Time
	GoneAt    time.Time
}

// SaveTombstones records tombstones, keeping the FIRST belief for an asset: DO
// NOTHING rather than DO UPDATE, because believed_gone_at is meant to answer
// "since when", and re-stamping it every sweep would turn the audit trail into
// a clock.
func (r *PGRepo) SaveTombstones(ctx context.Context, connectorID string, ts []Tombstone) (int, error) {
	if len(ts) == 0 {
		return 0, nil
	}
	batch := &pgx.Batch{}
	for _, t := range ts {
		batch.Queue(upsertTombstone, t.AssetID, connectorID, t.Scope, t.AssetType, t.LastSeen, t.GoneAt)
	}
	res := r.pool.SendBatch(ctx, batch)
	defer func() { _ = res.Close() }()
	written := 0
	for range ts {
		tag, err := res.Exec()
		if err != nil {
			return written, fmt.Errorf("SaveTombstones: %w", err)
		}
		written += int(tag.RowsAffected())
	}
	return written, nil
}
