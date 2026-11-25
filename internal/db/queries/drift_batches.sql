-- name: InsertDriftBatch :execrows
-- Idempotent on the deterministic batch id: a second insert of the same
-- window is a no-op, so the caller enqueues the analyse job only when n = 1.
INSERT INTO drift_batches (id, connector_id, window_start, window_end, asset_ids, truncated, status)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (id) DO NOTHING;

-- name: GetDriftBatch :one
SELECT * FROM drift_batches WHERE id = $1;

-- name: ListDriftBatches :many
-- Baseline rows are watermarks, not analyses.
SELECT * FROM drift_batches
WHERE status <> 'baseline' AND created_at >= sqlc.arg(since)
ORDER BY created_at DESC
LIMIT sqlc.arg(max_rows);

-- name: ListDriftBatchesToRequeue :many
-- Pending batches whose job was lost (older than pending_before), and unknown
-- batches whose reason is transient and that still have attempts left.
SELECT * FROM drift_batches
WHERE (status = 'pending' AND created_at < sqlc.arg(pending_before))
   OR (status = 'unknown' AND unknown_reason = ANY(sqlc.arg(retryable_reasons)::text[])
       AND attempts < sqlc.arg(max_attempts))
ORDER BY created_at
LIMIT sqlc.arg(max_rows);

-- name: RecordDriftAttempt :execrows
UPDATE drift_batches SET attempts = attempts + 1
WHERE id = $1 AND status IN ('pending', 'unknown');

-- name: SaveDriftAnalysis :execrows
-- Never overwrites an analysed or baseline row, so a duplicate job is inert.
UPDATE drift_batches
SET status = $2, verdict = $3, unknown_reason = $4, analysed_at = $5
WHERE id = $1 AND status IN ('pending', 'unknown');

-- name: PruneDriftBatches :execrows
DELETE FROM drift_batches WHERE created_at < $1;
