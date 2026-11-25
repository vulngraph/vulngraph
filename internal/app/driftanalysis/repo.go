package driftanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// PGRepo implements Repo on Postgres.
type PGRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo {
	return &PGRepo{pool: pool, q: sqlcgen.New(pool)}
}

// connectorStatesQ returns, per connector with stored hashes, its newest
// change of any kind and the window_end of its latest batch (NULL when it has
// none). A same-hash re-stamp leaves first_seen_at and last_changed_at
// untouched (connector/repo.go upsertAssetHashEntry), so a sweep that changed
// nothing moves neither value.
const connectorStatesQ = `
SELECT h.connector_id, max(GREATEST(h.first_seen_at, h.last_changed_at)), w.watermark
FROM connector_asset_hashes h
LEFT JOIN (SELECT connector_id, max(window_end) AS watermark FROM drift_batches GROUP BY connector_id) w
  ON w.connector_id = h.connector_id
GROUP BY h.connector_id, w.watermark`

// changedSinceQ lists the assets with a drift event in (since, until]: new
// (change_count = 0, stamped first_seen_at) or changed in name or public IP
// (stamped last_changed_at). The predicate matches asset/drift.go's feed, so a
// hash change that left name and IP alone is no event.
const changedSinceQ = `
SELECT asset_id, ts FROM (
    SELECT asset_id,
           CASE WHEN change_count = 0 THEN first_seen_at ELSE last_changed_at END AS ts
    FROM connector_asset_hashes
    WHERE connector_id = $1
      AND (change_count = 0 OR curr_public_ip != prev_public_ip OR curr_name != prev_name)
) e
WHERE ts > $2 AND ts <= $3
ORDER BY ts, asset_id
LIMIT $4`

const changesQ = `
SELECT asset_id, curr_name, curr_public_ip, prev_name, prev_public_ip, change_count,
       asset_type, region,
       CASE WHEN change_count = 0 THEN first_seen_at ELSE last_changed_at END
FROM connector_asset_hashes
WHERE connector_id = $1 AND asset_id = ANY($2::text[])
ORDER BY asset_id`

// ConnectorStates lists every connector with stored hashes.
func (r *PGRepo) ConnectorStates(ctx context.Context) ([]ConnectorState, error) {
	rows, err := r.pool.Query(ctx, connectorStatesQ)
	if err != nil {
		return nil, fmt.Errorf("ConnectorStates: %w", err)
	}
	defer rows.Close()
	var out []ConnectorState
	for rows.Next() {
		var s ConnectorState
		var watermark *time.Time
		if err := rows.Scan(&s.ConnectorID, &s.Latest, &watermark); err != nil {
			return nil, fmt.Errorf("ConnectorStates: %w", err)
		}
		if watermark != nil {
			s.Watermark = *watermark
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ConnectorStates: %w", err)
	}
	return out, nil
}

// ChangedSince returns up to limit changed assets in (since, until], oldest first.
func (r *PGRepo) ChangedSince(ctx context.Context, connectorID string, since, until time.Time, limit int) ([]ChangedAsset, error) {
	rows, err := r.pool.Query(ctx, changedSinceQ, connectorID, since, until, limit)
	if err != nil {
		return nil, fmt.Errorf("ChangedSince: %w", err)
	}
	defer rows.Close()
	var out []ChangedAsset
	for rows.Next() {
		var c ChangedAsset
		if err := rows.Scan(&c.AssetID, &c.At); err != nil {
			return nil, fmt.Errorf("ChangedSince: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ChangedSince: %w", err)
	}
	return out, nil
}

// Changes reads what changed on the given assets. An asset whose hash row was
// deleted since the batch was cut is absent from the result.
func (r *PGRepo) Changes(ctx context.Context, connectorID string, assetIDs []string) ([]AssetChange, error) {
	rows, err := r.pool.Query(ctx, changesQ, connectorID, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("Changes: %w", err)
	}
	defer rows.Close()
	var out []AssetChange
	for rows.Next() {
		var c AssetChange
		var prevName, prevIP string
		var changeCount int
		if err := rows.Scan(&c.AssetID, &c.Name, &c.PublicIP, &prevName, &prevIP, &changeCount,
			&c.AssetType, &c.Region, &c.DetectedAt); err != nil {
			return nil, fmt.Errorf("Changes: %w", err)
		}
		classifyChange(&c, changeCount, prevName, prevIP)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("Changes: %w", err)
	}
	return out, nil
}

// classifyChange fills Kind/Field/Old/New. Gaining or losing a public IP is an
// exposure change, not a field edit.
func classifyChange(c *AssetChange, changeCount int, prevName, prevIP string) {
	if changeCount == 0 {
		c.Kind = KindNewAsset
		return
	}
	ipChanged := c.PublicIP != prevIP
	nameChanged := c.Name != prevName
	switch {
	case ipChanged && nameChanged:
		c.Field, c.OldValue, c.NewValue = "public_ip,name", prevIP+" / "+prevName, c.PublicIP+" / "+c.Name
	case ipChanged:
		c.Field, c.OldValue, c.NewValue = "public_ip", prevIP, c.PublicIP
	default:
		c.Field, c.OldValue, c.NewValue = "name", prevName, c.Name
	}
	switch {
	case prevIP == "" && c.PublicIP != "":
		c.Kind = KindNewExposure
	case prevIP != "" && c.PublicIP == "":
		c.Kind = KindRemovedExposure
	default:
		c.Kind = KindChanged
	}
}

// CreateBatch inserts the batch and, when enqueue is non-nil and the row is
// new, calls it inside the same transaction. created is false when the id
// already existed; enqueue is then not called.
func (r *PGRepo) CreateBatch(ctx context.Context, b Batch, enqueue EnqueueFunc) (bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("CreateBatch: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	n, err := sqlcgen.New(tx).InsertDriftBatch(ctx, sqlcgen.InsertDriftBatchParams{
		ID: b.ID, ConnectorID: b.ConnectorID, WindowStart: b.WindowStart, WindowEnd: b.WindowEnd,
		AssetIds: nonNil(b.AssetIDs), Truncated: b.Truncated, Status: b.Status,
	})
	if err != nil {
		return false, fmt.Errorf("CreateBatch: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	if enqueue != nil {
		if err := enqueue(ctx, tx, b); err != nil {
			return false, fmt.Errorf("CreateBatch: enqueue: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("CreateBatch: commit: %w", err)
	}
	return true, nil
}

func (r *PGRepo) Get(ctx context.Context, id string) (Batch, error) {
	row, err := r.q.GetDriftBatch(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Batch{}, ErrNotFound
	}
	if err != nil {
		return Batch{}, fmt.Errorf("Get: %w", err)
	}
	return toBatch(row)
}

// List returns analyses created at or after since, newest first. Baseline
// rows are watermarks and are not listed.
func (r *PGRepo) List(ctx context.Context, since time.Time, limit int) ([]Batch, error) {
	rows, err := r.q.ListDriftBatches(ctx, sqlcgen.ListDriftBatchesParams{Since: since, MaxRows: int32(limit)})
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	return toBatches("List", rows)
}

// ToRequeue returns pending batches created before pendingBefore and unknown
// batches with a retryable reason and fewer than maxAttempts attempts.
func (r *PGRepo) ToRequeue(ctx context.Context, pendingBefore time.Time, maxAttempts, limit int) ([]Batch, error) {
	rows, err := r.q.ListDriftBatchesToRequeue(ctx, sqlcgen.ListDriftBatchesToRequeueParams{
		PendingBefore:    pendingBefore,
		RetryableReasons: []string{ReasonBudget, ReasonLLMError},
		MaxAttempts:      int32(maxAttempts),
		MaxRows:          int32(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("ToRequeue: %w", err)
	}
	return toBatches("ToRequeue", rows)
}

func (r *PGRepo) RecordAttempt(ctx context.Context, id string) error {
	if _, err := r.q.RecordDriftAttempt(ctx, id); err != nil {
		return fmt.Errorf("RecordAttempt: %w", err)
	}
	return nil
}

// Save writes the outcome of an attempt. It only touches pending or unknown
// rows, so a duplicate job cannot overwrite an analysed batch. verdict is nil
// for an unknown outcome.
func (r *PGRepo) Save(ctx context.Context, id, status string, verdict *Verdict, unknownReason string, at time.Time) error {
	var raw []byte
	if verdict != nil {
		var err error
		if raw, err = json.Marshal(verdict); err != nil {
			return fmt.Errorf("Save: %w", err)
		}
	}
	_, err := r.q.SaveDriftAnalysis(ctx, sqlcgen.SaveDriftAnalysisParams{
		ID: id, Status: status, Verdict: raw, UnknownReason: unknownReason,
		AnalysedAt: pgtype.Timestamptz{Time: at, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("Save: %w", err)
	}
	return nil
}

// Prune deletes batches created before cutoff.
func (r *PGRepo) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := r.q.PruneDriftBatches(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("Prune: %w", err)
	}
	return n, nil
}

func toBatches(op string, rows []sqlcgen.DriftBatch) ([]Batch, error) {
	out := make([]Batch, 0, len(rows))
	for _, row := range rows {
		b, err := toBatch(row)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		out = append(out, b)
	}
	return out, nil
}

func toBatch(row sqlcgen.DriftBatch) (Batch, error) {
	b := Batch{
		ID: row.ID, ConnectorID: row.ConnectorID, WindowStart: row.WindowStart, WindowEnd: row.WindowEnd,
		AssetIDs: row.AssetIds, Truncated: row.Truncated, Status: row.Status, Attempts: int(row.Attempts),
		UnknownReason: row.UnknownReason, CreatedAt: row.CreatedAt,
	}
	if row.AnalysedAt.Valid {
		b.AnalysedAt = row.AnalysedAt.Time
	}
	if len(row.Verdict) > 0 {
		if err := json.Unmarshal(row.Verdict, &b.Verdict); err != nil {
			return Batch{}, fmt.Errorf("batch %s verdict: %w", row.ID, err)
		}
	}
	return b, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
