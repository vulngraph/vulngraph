-- name: ListKEVCatalogCVEs :many
SELECT cve_id FROM kev_catalog;

-- name: UpsertKEVCatalog :exec
-- One statement for the whole batch. A changed dateAdded or name is refreshed;
-- first_seen_at never moves.
INSERT INTO kev_catalog (cve_id, date_added, name)
-- Parallel unnest() calls in one SELECT list zip element-wise.
-- Go's zero time stands for an unknown dateAdded and is stored as NULL.
SELECT unnest(@cve_ids::text[]), NULLIF(unnest(@dates_added::timestamptz[]), '0001-01-01 00:00:00+00'), unnest(@names::text[])
ON CONFLICT (cve_id) DO UPDATE
    SET date_added = EXCLUDED.date_added, name = EXCLUDED.name
    WHERE kev_catalog.date_added IS DISTINCT FROM EXCLUDED.date_added
       OR kev_catalog.name <> EXCLUDED.name;

-- name: InsertKEVAddedEvents :many
-- Returns only the rows this call inserted: an event already recorded (a
-- retried or concurrent refresh) is skipped, not re-emitted.
INSERT INTO kev_added_events (cve_id, date_added, name, open_findings)
SELECT unnest(@cve_ids::text[]), NULLIF(unnest(@dates_added::timestamptz[]), '0001-01-01 00:00:00+00'), unnest(@names::text[]), unnest(@open_findings::integer[])
ON CONFLICT (cve_id) DO NOTHING
RETURNING cve_id, date_added, name, open_findings, detected_at;

-- name: ListKEVAddedEvents :many
SELECT cve_id, date_added, name, open_findings, detected_at
FROM kev_added_events
ORDER BY detected_at DESC, cve_id
LIMIT @row_limit;
