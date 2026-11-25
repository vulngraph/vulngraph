-- name: SetConnectorDiskScan :one
-- Returns the mode the row held before this write, read under the row lock the
-- update takes, so the audit row's before value is exact. enabled_by/at record
-- who last enabled it and are cleared when the mode goes back to off.
UPDATE connectors c
SET disk_scan_mode = sqlc.arg(mode),
    disk_scan_enabled_by = sqlc.arg(enabled_by),
    disk_scan_enabled_at = sqlc.narg(enabled_at),
    updated_at = now()
FROM (SELECT p.id, p.disk_scan_mode FROM connectors p WHERE p.id = sqlc.arg(id) FOR UPDATE) AS prev
WHERE c.id = prev.id
RETURNING prev.disk_scan_mode AS previous_mode;

-- name: InsertDiskScanRun :one
INSERT INTO disk_scan_runs (connector_id, status, started_at, finished_at, err)
VALUES ($1, $2, $3, sqlc.narg(finished_at), $4)
RETURNING *;

-- name: GetDiskScanRun :one
SELECT * FROM disk_scan_runs WHERE id = $1;

-- name: ListDiskScanRuns :many
SELECT * FROM disk_scan_runs
WHERE sqlc.arg(connector_id)::text = '' OR connector_id::text = sqlc.arg(connector_id)::text
ORDER BY started_at DESC
LIMIT sqlc.arg(max_rows);

-- name: FinishDiskScanRun :execrows
UPDATE disk_scan_runs
SET status = $2, finished_at = $3, volumes = $4, scanned = $5, gaps = $6, not_enabled = $7, err = $8
WHERE id = $1;

-- name: CountDiskScanVolumes :one
SELECT count(*) FILTER (WHERE inventory_known)                         AS scanned,
       count(*) FILTER (WHERE NOT inventory_known AND gap <> 'not_enabled') AS gaps,
       count(*) FILTER (WHERE gap = 'not_enabled')                      AS not_enabled
FROM disk_scan_volumes WHERE run_id = $1;

-- name: UpsertDiskScanVolume :exec
INSERT INTO disk_scan_volumes (run_id, asset_id, volume_ref, boot, snapshot_id, snapshot_source, encrypted,
                               inventory_known, cve_matchable_known, gap, package_count, observed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (run_id, asset_id, volume_ref) DO UPDATE SET
    boot = EXCLUDED.boot, snapshot_id = EXCLUDED.snapshot_id, snapshot_source = EXCLUDED.snapshot_source,
    encrypted = EXCLUDED.encrypted, inventory_known = EXCLUDED.inventory_known,
    cve_matchable_known = EXCLUDED.cve_matchable_known, gap = EXCLUDED.gap,
    package_count = EXCLUDED.package_count, observed_at = EXCLUDED.observed_at;

-- name: LatestDiskScanVolumes :many
-- One row per asset: its boot volume's newest result, else its newest result.
SELECT DISTINCT ON (asset_id)
       run_id, asset_id, volume_ref, snapshot_id, snapshot_source, encrypted,
       inventory_known, cve_matchable_known, gap, package_count, observed_at
FROM disk_scan_volumes
WHERE asset_id = ANY(sqlc.arg(asset_ids)::text[])
ORDER BY asset_id, boot DESC, observed_at DESC;

-- name: ListDiskScanVolumes :many
SELECT run_id, asset_id, volume_ref, snapshot_id, snapshot_source, encrypted,
       inventory_known, cve_matchable_known, gap, package_count, observed_at
FROM disk_scan_volumes WHERE run_id = $1 ORDER BY asset_id, volume_ref;

-- name: InsertDiskScanSnapshotIntent :execrows
-- A retried job hits the (run_id, volume_ref) key and gets n = 0.
INSERT INTO disk_scan_snapshots (run_id, connector_id, provider, region, volume_ref, created_at, delete_after)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (run_id, volume_ref) DO NOTHING;

-- name: GetDiskScanSnapshotIntent :one
SELECT * FROM disk_scan_snapshots WHERE run_id = $1 AND volume_ref = $2;

-- name: AttachDiskScanSnapshot :execrows
UPDATE disk_scan_snapshots SET snapshot_id = $2 WHERE id = $1 AND deleted_at IS NULL;

-- name: MarkDiskScanSnapshotDeleted :execrows
UPDATE disk_scan_snapshots SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL;

-- name: MarkDiskScanSnapshotDeletedByRef :execrows
UPDATE disk_scan_snapshots SET deleted_at = $3
WHERE provider = $1 AND snapshot_id = $2 AND deleted_at IS NULL;

-- name: ListDiskScanOrphans :many
SELECT * FROM disk_scan_snapshots
WHERE deleted_at IS NULL AND delete_after < $1
ORDER BY delete_after
LIMIT $2;

-- name: GetDiskScanCache :one
SELECT * FROM disk_scan_cache
WHERE provider = $1 AND snapshot_id = $2 AND (expires_at IS NULL OR expires_at > $3);

-- name: PutDiskScanCache :exec
INSERT INTO disk_scan_cache (provider, snapshot_id, digest, extents, encrypted, inventory_known,
                             cve_matchable_known, gap, package_count, cached_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, sqlc.narg(expires_at))
ON CONFLICT (provider, snapshot_id) DO UPDATE SET
    digest = EXCLUDED.digest, extents = EXCLUDED.extents, encrypted = EXCLUDED.encrypted,
    inventory_known = EXCLUDED.inventory_known, cve_matchable_known = EXCLUDED.cve_matchable_known,
    gap = EXCLUDED.gap, package_count = EXCLUDED.package_count,
    cached_at = EXCLUDED.cached_at, expires_at = EXCLUDED.expires_at;

-- name: LatestDiskScanVolumesForAsset :many
-- One row per volume of the asset: that volume's newest result.
SELECT DISTINCT ON (volume_ref)
       run_id, asset_id, volume_ref, snapshot_id, snapshot_source, encrypted,
       inventory_known, cve_matchable_known, gap, package_count, observed_at
FROM disk_scan_volumes
WHERE asset_id = $1
ORDER BY volume_ref, observed_at DESC;
