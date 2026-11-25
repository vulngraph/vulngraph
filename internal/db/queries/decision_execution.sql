-- name: GetDecisionExecution :one
SELECT * FROM decision_executions WHERE decision_id = $1;

-- name: ClaimDecisionExecution :one
-- Takes a decision for one click: inserts its row, or takes over a row whose
-- last attempt failed or whose second-admin grant expired unused. A row
-- another click holds (awaiting with a live grant), that already succeeded,
-- or that is running is left alone, and nothing is returned. A running row is
-- NEVER taken over on age: a pod that crashed mid-call leaves one whose cloud
-- change may have happened, and only FailStalledDecisionExecution (an admin
-- who checked the cloud) releases it.
INSERT INTO decision_executions (
    decision_id, finding_id, connector_id, action, params, plan, status,
    requested_by, requested_by_id, grant_token, grant_expires_at, executed_by, executed_by_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, sqlc.narg('grant_expires_at'), $11, $12
)
ON CONFLICT (decision_id) DO UPDATE SET
    finding_id       = EXCLUDED.finding_id,
    connector_id     = EXCLUDED.connector_id,
    action           = EXCLUDED.action,
    params           = EXCLUDED.params,
    plan             = EXCLUDED.plan,
    status           = EXCLUDED.status,
    requested_by     = EXCLUDED.requested_by,
    requested_by_id  = EXCLUDED.requested_by_id,
    grant_token      = EXCLUDED.grant_token,
    grant_expires_at = EXCLUDED.grant_expires_at,
    executed_by      = EXCLUDED.executed_by,
    executed_by_id   = EXCLUDED.executed_by_id,
    detail           = '',
    error            = '',
    created_at       = now(),
    updated_at       = now()
WHERE decision_executions.status = 'failed'
   OR (decision_executions.status = 'awaiting_second_admin' AND decision_executions.grant_expires_at < now())
RETURNING *;

-- name: ClaimApprovedDecisionExecution :one
-- The second admin's click: takes an awaiting row whose grant is still live,
-- never for the admin who requested it. Nothing is returned when another
-- click got there first.
UPDATE decision_executions
SET status = 'running', executed_by = $2, executed_by_id = $3, updated_at = now()
WHERE decision_id = $1
  AND status = 'awaiting_second_admin'
  AND grant_expires_at > now()
  AND requested_by_id <> $3
RETURNING *;

-- name: FinishDecisionExecution :exec
-- Records the executor's actual result and drops the spent grant — only for
-- the attempt that claimed it. created_at is reset by every new claim, so a
-- run an admin released (and a retry re-claimed) cannot have its late result
-- overwrite the retry's state.
UPDATE decision_executions
SET status = $2, detail = $3, error = $4, grant_token = '', updated_at = now()
WHERE decision_id = $1 AND status = 'running' AND created_at = sqlc.arg('claimed_at');

-- name: FailStalledDecisionExecution :one
-- An admin's explicit release of a run whose outcome is unknown (its cloud
-- call was cut off), or that has been running for longer than
-- stale_after_seconds: marks it failed (so a later click may retry) and drops
-- its grant. Staleness is measured on the database clock, the same clock that
-- stamped updated_at, so a skewed pod cannot release a run still in flight.
-- Nothing is returned when the run finished, or moved, in between.
UPDATE decision_executions
SET status = 'failed', error = $2, grant_token = '', updated_at = now()
WHERE decision_id = $1
  AND (status = 'outcome_unknown'
       OR (status = 'running'
           AND updated_at < now() - make_interval(secs => sqlc.arg('stale_after_seconds')::double precision)))
RETURNING *;
