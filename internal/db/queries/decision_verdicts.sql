-- name: UpsertDecisionVerdict :exec
INSERT INTO decision_verdicts (finding_id, cluster_key, verdict, actor, note, fingerprint, created_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (finding_id) DO UPDATE SET
    cluster_key = EXCLUDED.cluster_key,
    verdict     = EXCLUDED.verdict,
    actor       = EXCLUDED.actor,
    note        = EXCLUDED.note,
    fingerprint = EXCLUDED.fingerprint,
    created_at  = EXCLUDED.created_at;

-- name: ListResolvedVerdicts :many
-- finding_id + the context fingerprint captured when the verdict was recorded, so
-- the queue can re-surface a resolved finding whose fingerprint has since changed.
SELECT finding_id, fingerprint FROM decision_verdicts;
