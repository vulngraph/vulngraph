-- name: RecordOutcome :exec
-- A non-NULL dedupe_key makes the insert idempotent: a second outcome for the
-- same decision is dropped by the partial unique index.
INSERT INTO action_outcomes (action_class, asset_type, environment, success, decided_by, occurred_at, dedupe_key)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (dedupe_key) WHERE dedupe_key IS NOT NULL DO NOTHING;

-- name: RecentOutcomes :many
SELECT * FROM action_outcomes
WHERE action_class = $1 AND asset_type = $2
ORDER BY occurred_at DESC
LIMIT $3;

-- name: RecentOutcomesByAsset :many
SELECT * FROM action_outcomes
WHERE asset_type = $1
ORDER BY occurred_at DESC
LIMIT $2;
