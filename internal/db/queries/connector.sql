-- name: CreateConnector :one
INSERT INTO connectors (type, name, config_enc, enabled, event_source)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetConnector :one
SELECT * FROM connectors WHERE id = $1;

-- name: ListConnectors :many
SELECT * FROM connectors ORDER BY type, name;

-- name: ListEnabledConnectors :many
SELECT * FROM connectors WHERE enabled = true ORDER BY type, name;

-- name: UpdateConnectorConfig :exec
UPDATE connectors SET config_enc = $2, updated_at = now() WHERE id = $1;

-- name: ResealConnectorConfig :execrows
UPDATE connectors SET config_enc = sqlc.arg(new_config_enc), updated_at = now()
WHERE id = sqlc.arg(id) AND config_enc = sqlc.arg(old_config_enc);

-- name: SetConnectorEnabled :exec
UPDATE connectors SET enabled = $2, updated_at = now() WHERE id = $1;

-- name: SetConnectorMode :one
-- Returns the mode the row held before this write. The FOR UPDATE subquery
-- reads it under the row lock the update takes, so a concurrent change cannot
-- slip between the read and the write.
UPDATE connectors c SET mode = sqlc.arg(mode), updated_at = now()
FROM (SELECT p.id, p.mode FROM connectors p WHERE p.id = sqlc.arg(id) FOR UPDATE) AS prev
WHERE c.id = prev.id
RETURNING prev.mode AS previous_mode;

-- name: SetConnectorSyncResult :exec
-- last_success_at is advanced only on a successful sync: callers pass the sync
-- time as @last_success_at on success and NULL on failure, so COALESCE keeps the
-- prior success timestamp when the latest attempt errored.
--
-- sync_streak increments on a clean, complete, non-backfill sync (the caller's
-- clean_no_op) and resets to 0 on anything else — a real change, a partial
-- collection, a check-registry backfill, or an outright failure. See
-- internal/jobs/enqueue.go's backoffInterval for how the streak throttles the
-- periodic sync sweep.
--
-- partial_streak increments whenever this sync was Partial (some best-effort
-- collector skipped) and resets to 0 the moment one completes non-Partial —
-- independent of last_success_at, which advances on ANY runErr==nil result.
-- See Connector.PartiallyStale.
UPDATE connectors
SET sync_status = $2,
    sync_error = $3,
    last_synced_at = $4,
    last_success_at = COALESCE(sqlc.narg('last_success_at'), last_success_at),
    sync_streak = CASE WHEN sqlc.arg('clean_no_op')::boolean THEN sync_streak + 1 ELSE 0 END,
    partial_streak = CASE WHEN sqlc.arg('partial')::boolean THEN partial_streak + 1 ELSE 0 END,
    updated_at = now()
WHERE id = $1;

-- name: SetConnectorSyncFingerprint :exec
-- Update the connector-level content fingerprint after a successful sync.
UPDATE connectors SET sync_fingerprint = $2, updated_at = now() WHERE id = $1;

-- name: DeleteConnector :execrows
DELETE FROM connectors WHERE id = $1;

-- name: GetConnectorAssetHashes :many
SELECT asset_id, hash, asset_type, region FROM connector_asset_hashes WHERE connector_id = $1;

-- name: DeleteConnectorAssetHashes :exec
DELETE FROM connector_asset_hashes
WHERE connector_id = $1 AND asset_id = ANY($2::text[]);

-- name: RecordAssetDeletions :many
-- Records the sync's proven deletions. Called with exactly
-- the ids whose hashes the same complete sweep deleted.
INSERT INTO asset_deletions (asset_id, connector_id, deleted_at)
SELECT candidate.asset_id, @connector_id, @deleted_at
FROM unnest(@asset_ids::text[]) AS candidate(asset_id)
WHERE NOT EXISTS (
    SELECT 1 FROM connector_asset_hashes AS owner
    WHERE owner.asset_id = candidate.asset_id AND owner.connector_id::text <> @connector_id
)
ON CONFLICT (asset_id) DO UPDATE
    SET connector_id = EXCLUDED.connector_id, deleted_at = EXCLUDED.deleted_at, retired_at = NULL
RETURNING asset_id;

-- name: PruneAssetDeletions :execrows
-- Drops deletion records older than the asset rows they describe can live
-- (the ClickHouse assets TTL is last_seen + 180 days).
DELETE FROM asset_deletions WHERE deleted_at < @cutoff;

-- name: GetAssetDeletions :many
SELECT d.asset_id, d.deleted_at FROM asset_deletions AS d
WHERE d.asset_id = ANY(@asset_ids::text[])
AND NOT EXISTS (
    SELECT 1 FROM connector_asset_hashes AS owner
    WHERE owner.asset_id = d.asset_id AND owner.connector_id::text <> d.connector_id
);

-- name: PendingAssetRetirements :many
SELECT d.asset_id, d.deleted_at FROM asset_deletions AS d
WHERE d.retired_at IS NULL
AND NOT EXISTS (
    SELECT 1 FROM connector_asset_hashes AS owner WHERE owner.asset_id = d.asset_id
)
ORDER BY d.deleted_at, d.asset_id
LIMIT @batch_size;

-- name: CompleteAssetRetirements :exec
UPDATE asset_deletions SET retired_at = now()
WHERE (asset_id, deleted_at) IN (
    SELECT unnest(@asset_ids::text[]), unnest(@deleted_ats::timestamptz[])
);

-- name: RecordProvenCapability :exec
-- Idempotent by design: ON CONFLICT DO NOTHING, because proof is monotonic
-- — a capability already proven stays proven, and
-- re-recording it must never reset first_proven_at or error.
INSERT INTO connector_proven_capabilities (connector_id, capability, first_proven_at)
VALUES ($1, $2, $3)
ON CONFLICT (connector_id, capability) DO NOTHING;

-- name: ListProvenCapabilities :many
SELECT capability FROM connector_proven_capabilities WHERE connector_id = $1;


-- name: ListConnectorsCollectingAsset :many
-- The enabled connectors whose sync currently collects this asset — the
-- record of which credentials can reach it (rows leave when the sync stops
-- seeing the asset).
SELECT h.connector_id FROM connector_asset_hashes h
JOIN connectors c ON c.id = h.connector_id
WHERE h.asset_id = $1 AND c.enabled
ORDER BY h.connector_id;

-- name: ListAWSOrgAccounts :many
-- The org connector's discovered accounts, joined with each child connector's
-- health so the UI can show both in one read.
SELECT a.org_connector_id, a.account_id, a.name, a.email, a.aws_state, a.ou_path,
       a.status, a.status_detail, COALESCE(a.child_connector_id::text, '')::text AS child_connector_id,
       a.first_seen_at, a.last_seen_at, a.status_changed_at,
       c.enabled AS child_enabled, c.sync_status AS child_sync_status,
       c.sync_error AS child_sync_error, c.last_success_at AS child_last_success_at,
       c.created_at AS child_created_at
FROM aws_org_accounts a
LEFT JOIN connectors c ON c.id = a.child_connector_id
WHERE a.org_connector_id = $1
ORDER BY a.account_id;

-- name: UpsertAWSOrgAccount :exec
-- status_changed_at moves only when the status does; last_seen_at is the
-- caller's (the last discovery that listed the account).
INSERT INTO aws_org_accounts
    (org_connector_id, account_id, name, email, aws_state, ou_path, status, status_detail,
     child_connector_id, first_seen_at, last_seen_at, status_changed_at)
VALUES (@org_connector_id, @account_id, @name, @email, @aws_state, @ou_path, @status, @status_detail,
        NULLIF(@child_connector_id::text, '')::uuid, @seen_at, @last_seen_at, @seen_at)
ON CONFLICT (org_connector_id, account_id) DO UPDATE SET
    name               = EXCLUDED.name,
    email              = EXCLUDED.email,
    aws_state          = EXCLUDED.aws_state,
    ou_path            = EXCLUDED.ou_path,
    status_detail      = EXCLUDED.status_detail,
    child_connector_id = EXCLUDED.child_connector_id,
    last_seen_at       = EXCLUDED.last_seen_at,
    status_changed_at  = CASE WHEN aws_org_accounts.status <> EXCLUDED.status
                              THEN EXCLUDED.status_changed_at
                              ELSE aws_org_accounts.status_changed_at END,
    status             = EXCLUDED.status;

-- name: DisableAWSOrgChildren :exec
-- Disables (never deletes) every child of an org connector. Run in the same
-- transaction as the org connector's delete, so no child is left enabled with
-- no org to resolve its credentials from.
UPDATE connectors SET enabled = false, updated_at = now()
WHERE id IN (SELECT child_connector_id FROM aws_org_accounts
             WHERE org_connector_id = $1 AND child_connector_id IS NOT NULL);
