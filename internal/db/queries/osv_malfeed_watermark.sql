-- name: GetOSVMalFeedWatermark :one
-- Returns the last-seen ossf/malicious-packages commit SHA. pgx.ErrNoRows on
-- a cold start (no watermark written yet) — the caller treats that as "".
SELECT last_sha FROM osv_malfeed_watermark WHERE id = 1;

-- name: SetOSVMalFeedWatermark :exec
INSERT INTO osv_malfeed_watermark (id, last_sha, updated_at)
VALUES (1, @last_sha, now())
ON CONFLICT (id) DO UPDATE SET last_sha = @last_sha, updated_at = now();
