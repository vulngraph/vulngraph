-- name: GetReasoningCache :one
SELECT * FROM reasoning_cache WHERE finding_id = $1;

-- name: ListPendingReasoning :many
-- Decisions awaiting a human governor: parked-for-approval or escalated, newest
-- first. The govern queue composes these with finding context and excludes any
-- finding that already has a verdict. action_class narrows the scan to a
-- single action class (NULL means unfiltered) — filtered server-side, ahead of
-- the limit, so a narrow filter can't be starved by unrelated rows filling the
-- capped scan window (mirrors respond.ListDecisions' filter-before-cap).
SELECT * FROM reasoning_cache
WHERE outcome IN ('parked_for_approval', 'escalated')
  AND (sqlc.narg('action_class')::text IS NULL OR plan_action_class = sqlc.narg('action_class'))
ORDER BY decided_at DESC
LIMIT $1;

-- name: UpsertReasoningCache :exec
INSERT INTO reasoning_cache (
    finding_id, fingerprint, plan_action_class, plan_summary, plan_rationale, outcome,
    confidence_band, confidence_score, effective_n, sample_count, blast_radius, blast_radius_known,
    cove_concerns, decided_at, safety_band, escalation_reason
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
ON CONFLICT (finding_id) DO UPDATE SET
    fingerprint        = EXCLUDED.fingerprint,
    plan_action_class  = EXCLUDED.plan_action_class,
    plan_summary       = EXCLUDED.plan_summary,
    plan_rationale     = EXCLUDED.plan_rationale,
    outcome            = EXCLUDED.outcome,
    confidence_band    = EXCLUDED.confidence_band,
    confidence_score   = EXCLUDED.confidence_score,
    effective_n        = EXCLUDED.effective_n,
    sample_count       = EXCLUDED.sample_count,
    blast_radius       = EXCLUDED.blast_radius,
    blast_radius_known = EXCLUDED.blast_radius_known,
    cove_concerns      = EXCLUDED.cove_concerns,
    decided_at         = EXCLUDED.decided_at,
    safety_band        = EXCLUDED.safety_band,
    escalation_reason  = EXCLUDED.escalation_reason;

-- name: IncrementReasoningCacheRepeat :exec
-- Repeat counter: bumps it on respond.Decide's repeat-decision skip path so
-- "escalated N times running" survives even when the byte-identical repeat is
-- never itself written to the audit trail. Best-effort from the caller's side —
-- see reasoncache.Service.IncrementRepeat.
UPDATE reasoning_cache
SET repeat_count = repeat_count + 1,
    last_repeated_at = now()
WHERE finding_id = $1;

-- name: TopEscalatedRepeats :many
-- Repeat counter: replaces the ClickHouse selectEscalationHotspots leg of
-- DecisionsSummary. Repeats are not all individually audited (repeat-decision
-- skip), so the hotspot signal — a finding escalating over and over — comes
-- from this counter instead of counting audit rows.
SELECT * FROM reasoning_cache
WHERE outcome = 'escalated'
ORDER BY repeat_count DESC
LIMIT $1;
