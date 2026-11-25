-- name: GetScannedPackagesSince :many
-- Returns (ecosystem, name, version, scanned_at) for packages scanned after
-- the cutoff. The OSV worker skips packages already checked recently — unless
-- a purl that maps to one first appeared after its scan.
SELECT ecosystem, name, version, scanned_at
FROM osv_scanned_packages
WHERE scanned_at > @cutoff;

-- name: GetOSVScanStaleness :one
-- Returns the oldest scan timestamp and the total row count in
-- osv_scanned_packages — the Postgres half of the scan-staleness gauge (the
-- ClickHouse half, current package-inventory size, comes from
-- asset.Service.CountPackages). Answers "how stale is our worst-covered
-- package?", which graph_feed_last_success_timestamp_seconds{feed="osv"}
-- cannot: that gauge stamps on every successful refresh_osv run even when 0
-- new packages were scanned (everything within osvRescanAfter).
-- coalesce guards an empty table (brand-new install, before the first
-- refresh_osv run has ever completed): min() over zero rows is NULL, which
-- would fail to scan into a non-nullable timestamp. The epoch fallback is
-- never read as a real staleness signal — the caller gates on scanned_count
-- being zero first.
SELECT
    coalesce(min(scanned_at), 'epoch'::timestamptz)::timestamptz AS oldest_scanned_at,
    count(*)::bigint                                             AS scanned_count
FROM osv_scanned_packages;

-- name: MarkPackagesScanned :exec
-- Upserts scan timestamps for a batch of packages. Called after each
-- successful OSV API pass.
INSERT INTO osv_scanned_packages (ecosystem, name, version, scanned_at)
SELECT
    unnest(@ecosystems::text[]),
    unnest(@names::text[]),
    unnest(@versions::text[]),
    now()
ON CONFLICT (ecosystem, name, version) DO UPDATE
    SET scanned_at = now();

-- name: DeleteOrphanedScannedPackages :execrows
-- Deletes osv_scanned_packages rows older than @cutoff whose
-- (ecosystem, name, version) is no longer present in the current package
-- inventory (e.g. an image rebuild bumped the package to a newer version, or
-- the asset was removed outright). Without this, such a row is never
-- re-queried — nothing in the live inventory matches it — and never ages out
-- on its own, permanently depressing
-- graph_osv_scan_oldest_scanned_timestamp_seconds even though live coverage
-- is healthy (GraphOSVScanCoverageStale would fire on a weeks-old orphan even
-- when every current package was scanned within the week). The OSV refresh
-- passes the start of its inventory listing as @cutoff, so every row for a
-- package that has left the live inventory goes: its findings are resolved as
-- resource_gone, and a package that comes back must be re-queried at once to
-- reopen them rather than sit out the rest of a rescan window.
DELETE FROM osv_scanned_packages o
WHERE o.scanned_at < @cutoff
  AND NOT EXISTS (
    SELECT 1
    FROM (
        SELECT
            unnest(@ecosystems::text[]) AS ecosystem,
            unnest(@names::text[])      AS name,
            unnest(@versions::text[])   AS version
    ) AS live
    WHERE live.ecosystem = o.ecosystem
      AND live.name = o.name
      AND live.version = o.version
  );
