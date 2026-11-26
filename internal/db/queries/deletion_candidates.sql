-- name: LockDeletionObservation :one
SELECT GREATEST(COALESCE(last_synced_at, 'epoch'::timestamptz),
    COALESCE(deletion_observed_at, 'epoch'::timestamptz))::timestamptz AS observed_at
FROM connectors WHERE id = @connector_id FOR UPDATE;

-- name: SetDeletionObservation :exec
UPDATE connectors SET deletion_observed_at = @observed_at::timestamptz WHERE id = @connector_id;

-- name: ObserveDeletionCandidates :exec
INSERT INTO connector_deletion_candidates (connector_id, asset_id, first_missing_at, last_missing_at)
SELECT h.connector_id, h.asset_id, @observed_at::timestamptz, @observed_at::timestamptz
FROM connector_asset_hashes AS h
WHERE h.connector_id = @connector_id AND h.asset_id = ANY(@asset_ids::text[])
ON CONFLICT (connector_id, asset_id) DO UPDATE
SET last_missing_at = EXCLUDED.last_missing_at;

-- name: ResetUnobservedDeletionCandidates :exec
DELETE FROM connector_deletion_candidates
WHERE connector_id = @connector_id AND last_missing_at <> @observed_at::timestamptz;

-- name: ClearDeletionCandidates :exec
DELETE FROM connector_deletion_candidates WHERE connector_id = @connector_id;

-- name: ConfirmedDeletionCandidates :many
SELECT asset_id FROM connector_deletion_candidates
WHERE connector_id = @connector_id AND last_missing_at = @observed_at::timestamptz
  AND first_missing_at <= @confirmed_before::timestamptz
ORDER BY first_missing_at, asset_id
LIMIT @batch_size;
