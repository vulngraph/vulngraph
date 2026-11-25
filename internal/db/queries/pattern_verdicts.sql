-- name: UpsertPatternVerdict :exec
INSERT INTO pattern_verdicts (check_id, action_class, resource_type, verdict, decided_by, decided_at)
VALUES ($1, $2, $3, $4, $5, now())
ON CONFLICT (check_id, action_class, resource_type) DO UPDATE SET
    verdict    = EXCLUDED.verdict,
    decided_by = EXCLUDED.decided_by,
    decided_at = EXCLUDED.decided_at;

-- name: GetPatternVerdict :one
SELECT verdict, decided_by, decided_at FROM pattern_verdicts
WHERE check_id = $1 AND action_class = $2 AND resource_type = $3;
