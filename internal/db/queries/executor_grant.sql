-- name: RedeemExecutorGrant :execrows
-- Records the first use of an approval grant. Zero rows affected means the
-- grant was already redeemed or its approver no longer has the issuing authority.
WITH authorized AS MATERIALIZED (
    SELECT id FROM users
    WHERE id = sqlc.arg(approver_id) AND role = 'admin' AND disabled_at IS NULL
      AND authority_version = sqlc.arg(authority_version)
    FOR SHARE
)
INSERT INTO executor_grant_redemptions (grant_hash, redeemed_by_id, expires_at)
SELECT sqlc.arg(grant_hash), sqlc.arg(redeemed_by_id), sqlc.arg(expires_at)
FROM authorized
ON CONFLICT (grant_hash) DO NOTHING;

-- name: PurgeExpiredExecutorGrants :exec
-- Drops redemptions of grants that expired before the cutoff: an expired grant
-- is refused on its expiry alone, so its row no longer guards anything.
DELETE FROM executor_grant_redemptions WHERE expires_at < $1;
