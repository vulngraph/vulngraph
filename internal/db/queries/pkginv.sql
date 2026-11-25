-- name: UpsertPackageInventory :execrows
-- A claim only replaces an older or equal one of the same source and asset: an
-- older observed_at is a stale replay and writes nothing (0 rows).
INSERT INTO package_inventories (
    source, asset_id, api_key_id, scanner_name, scanner_version,
    os_id, os_version_id, os_name, ecosystem, observed_at, received_at,
    complete, package_count, covered, inventory_known, cve_matchable_known, gap)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
ON CONFLICT (source, asset_id) DO UPDATE SET
    api_key_id = EXCLUDED.api_key_id,
    scanner_name = EXCLUDED.scanner_name,
    scanner_version = EXCLUDED.scanner_version,
    os_id = EXCLUDED.os_id,
    os_version_id = EXCLUDED.os_version_id,
    os_name = EXCLUDED.os_name,
    ecosystem = EXCLUDED.ecosystem,
    observed_at = EXCLUDED.observed_at,
    received_at = EXCLUDED.received_at,
    complete = EXCLUDED.complete,
    package_count = EXCLUDED.package_count,
    covered = EXCLUDED.covered,
    inventory_known = EXCLUDED.inventory_known,
    cve_matchable_known = EXCLUDED.cve_matchable_known,
    gap = EXCLUDED.gap
WHERE package_inventories.observed_at <= EXCLUDED.observed_at;

-- name: GetPackageInventory :one
SELECT * FROM package_inventories WHERE source = $1 AND asset_id = $2;

-- name: ListPackageInventoriesForAssets :many
SELECT * FROM package_inventories
WHERE asset_id = ANY(sqlc.arg(asset_ids)::text[])
ORDER BY asset_id, observed_at DESC, source;
