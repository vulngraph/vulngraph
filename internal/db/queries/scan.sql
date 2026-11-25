-- name: CreateScanRun :one
INSERT INTO scan_runs (status, target_count) VALUES ('running', $1) RETURNING *;

-- name: FinishScanRun :exec
UPDATE scan_runs
SET status = $2, finding_count = $3, error = $4, finished_at = now(),
    template_tags = $5, template_count = $6,
    target_urls = $7, scanner_name = $8
WHERE id = $1;

-- name: GetScanRun :one
SELECT * FROM scan_runs WHERE id = $1;

-- name: ListScanRuns :many
SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT $1;

-- name: CancelScanRun :exec
UPDATE scan_runs SET status = 'cancelled', finished_at = now()
WHERE id = $1 AND status = 'running';

-- name: FailStaleScanRuns :many
-- Reap runs orphaned in 'running' by a worker that died (SIGKILL / OOM / pod
-- eviction) before FinishScanRun could set a terminal status. Any run started
-- before the cutoff is failed with an explanatory error. Returns the reaped ids.
UPDATE scan_runs
SET status = 'failed', finished_at = now(),
    error = 'orphaned — no completion within the reap window (worker likely died mid-scan)'
WHERE status = 'running' AND started_at < $1
RETURNING id;
