-- name: ConsumeApprovalLinkNonce :execrows
-- One row per spent email approval link; a second insert affects no rows.
INSERT INTO approval_link_nonces (nonce, expires_at)
VALUES ($1, $2)
ON CONFLICT (nonce) DO NOTHING;

-- name: ApprovalLinkNonceSpent :one
SELECT EXISTS (SELECT 1 FROM approval_link_nonces WHERE nonce = $1);

-- name: PurgeExpiredApprovalLinkNonces :exec
-- An expired link is refused by its own signed expiry, so its row is no
-- longer needed to keep it single-use.
DELETE FROM approval_link_nonces WHERE expires_at < $1;
