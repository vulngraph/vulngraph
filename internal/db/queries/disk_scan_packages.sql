-- name: UpsertDiskScanPackages :exec
INSERT INTO disk_scan_packages (asset_id, volume_ref, run_id, snapshot_id, ecosystem, packages, observed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (asset_id, volume_ref) DO UPDATE SET
    run_id = EXCLUDED.run_id, snapshot_id = EXCLUDED.snapshot_id, ecosystem = EXCLUDED.ecosystem,
    packages = EXCLUDED.packages, observed_at = EXCLUDED.observed_at;

-- name: ListDiskScanPackages :many
SELECT asset_id, volume_ref, run_id, snapshot_id, ecosystem, packages, observed_at
FROM disk_scan_packages
WHERE asset_id = ANY(sqlc.arg(asset_ids)::text[]);

-- name: GetDiskScanConnectorMode :one
SELECT disk_scan_mode FROM disk_scan_connector_modes WHERE connector_id = $1;
