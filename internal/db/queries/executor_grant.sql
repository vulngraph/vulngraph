-- name: RedeemExecutorGrant :execrows
-- Records the first use of an approval grant. Zero rows affected means the
-- grant was already redeemed.
INSERT INTO executor_grant_redemptions (grant_hash, redeemed_by_id, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (grant_hash) DO NOTHING;

-- name: PurgeExpiredExecutorGrants :exec
-- Drops redemptions of grants that expired before the cutoff: an expired grant
-- is refused on its expiry alone, so its row no longer guards anything.
DELETE FROM executor_grant_redemptions WHERE expires_at < $1;
