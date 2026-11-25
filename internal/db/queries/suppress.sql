-- name: UpsertSuppression :one
INSERT INTO finding_suppressions (finding_id, reason, suppressed_by, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (finding_id) DO UPDATE
  SET reason = EXCLUDED.reason, suppressed_by = EXCLUDED.suppressed_by,
      suppressed_at = now(), expires_at = EXCLUDED.expires_at, expiry_notified_at = NULL
RETURNING *;

-- name: ReviewSuppression :one
UPDATE finding_suppressions
SET expires_at = $2, reviewed_by = $3, last_reviewed_at = now(), expiry_notified_at = NULL
WHERE finding_id = $1
RETURNING *;

-- name: DeleteSuppression :execrows
DELETE FROM finding_suppressions WHERE finding_id = $1;

-- name: GetSuppression :one
SELECT * FROM finding_suppressions WHERE finding_id = $1;

-- name: ListSuppressions :many
SELECT * FROM finding_suppressions ORDER BY suppressed_at DESC;

-- name: ListSuppressionExpiries :many
SELECT finding_id, expires_at FROM finding_suppressions;

-- name: ListSuppressionsDueExpiryNotice :many
SELECT * FROM finding_suppressions
WHERE expires_at > sqlc.arg(after) AND expires_at <= sqlc.arg(until) AND expiry_notified_at IS NULL
ORDER BY expires_at;

-- name: MarkSuppressionExpiryNotified :exec
UPDATE finding_suppressions SET expiry_notified_at = now()
WHERE finding_id = ANY(sqlc.arg(finding_ids)::text[]);
