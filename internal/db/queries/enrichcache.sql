-- name: GetEnrichCache :one
SELECT * FROM enrich_cache WHERE finding_id = $1;

-- name: UpsertEnrichCache :exec
INSERT INTO enrich_cache (finding_id, input_fp, context_fp, score_band, enriched_at,
                          graph_exposed, graph_privesc, graph_reach)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (finding_id) DO UPDATE SET
    input_fp      = EXCLUDED.input_fp,
    context_fp    = EXCLUDED.context_fp,
    score_band    = EXCLUDED.score_band,
    enriched_at   = EXCLUDED.enriched_at,
    graph_exposed = EXCLUDED.graph_exposed,
    graph_privesc = EXCLUDED.graph_privesc,
    graph_reach   = EXCLUDED.graph_reach;

-- name: InvalidateEnrichFingerprints :exec
-- Forces the next enrich of each finding past the change-gate while keeping
-- the rest of the row: the stored graph context (carry-forward on a failed
-- read) and score band survive.
UPDATE enrich_cache SET input_fp = '' WHERE finding_id = ANY(@finding_ids::text[]);

-- name: GetFindingAlertState :one
SELECT * FROM finding_alert_state WHERE finding_id = $1;

-- name: UpsertFindingAlertState :exec
-- Keeps the high-water mark under concurrent writers: the band never moves
-- down and must_fix, once recorded, stays.
INSERT INTO finding_alert_state (finding_id, score_band, must_fix_class, alerted_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (finding_id) DO UPDATE SET
    score_band = CASE
        WHEN coalesce(array_position(ARRAY['monitor','pipeline','high','page'], EXCLUDED.score_band), 0)
           > coalesce(array_position(ARRAY['monitor','pipeline','high','page'], finding_alert_state.score_band), 0)
        THEN EXCLUDED.score_band ELSE finding_alert_state.score_band END,
    must_fix_class = CASE
        WHEN finding_alert_state.must_fix_class = 'must_fix' THEN finding_alert_state.must_fix_class
        ELSE EXCLUDED.must_fix_class END,
    alerted_at = EXCLUDED.alerted_at;

-- name: DeleteFindingAlertStates :exec
-- A resolved finding's alert history ends with it: its regression is a new
-- episode that must alert again.
DELETE FROM finding_alert_state WHERE finding_id = ANY(@finding_ids::text[]);

-- name: PruneFindingAlertStates :execrows
-- Drops alert state for findings no longer being enriched (gone without a
-- resolve, e.g. aged out by TTL): every open finding is re-enriched at least
-- once per freshness backstop, so a cache row this old is not an open finding.
DELETE FROM finding_alert_state a
WHERE a.alerted_at < @older_than::timestamptz
  AND NOT EXISTS (
    SELECT 1 FROM enrich_cache c
    WHERE c.finding_id = a.finding_id AND c.enriched_at >= @older_than::timestamptz
  );

