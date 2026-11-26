-- name: CreateUser :one
INSERT INTO users (email, password_hash, role, admin_since)
VALUES (sqlc.arg(email), sqlc.arg(password_hash), sqlc.arg(role)::text,
        CASE WHEN sqlc.arg(role)::text = 'admin' THEN now() END)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower(sqlc.arg(email));

-- name: GetUserByOIDCIdentity :one
SELECT * FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2;

-- name: BindUserOIDCIdentity :execrows
UPDATE users SET oidc_issuer = $2, oidc_subject = $3, updated_at = now()
WHERE id = $1 AND oidc_subject IS NULL;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at DESC;

-- name: SetUserRole :execrows
-- admin_since moves only when the role becomes admin: staying admin keeps it
-- (NULL included, for an admin from before the column), leaving admin clears it.
UPDATE users SET role = sqlc.arg(role)::text,
    admin_since = CASE
        WHEN sqlc.arg(role)::text <> 'admin' THEN NULL
        WHEN role = 'admin' THEN admin_since
        ELSE now()
    END,
    updated_at = now()
WHERE id = sqlc.arg(id);

-- name: SetUserDisabledAt :execrows
UPDATE users SET disabled_at = $2, updated_at = now() WHERE id = $1;

-- name: DeleteUser :execrows
DELETE FROM users WHERE id = $1;

-- name: DeleteUserSessions :execrows
WITH revoked AS (
    UPDATE users SET authority_version = authority_version + 1 WHERE id = $1 RETURNING id
)
DELETE FROM sessions WHERE user_id IN (SELECT id FROM revoked);

-- name: CountActiveAdmins :one
SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL;

-- name: SetUserTOTPSecret :exec
UPDATE users SET totp_secret = $2, totp_last_step = NULL, updated_at = now() WHERE id = $1;

-- name: AdvanceUserTOTPStep :execrows
UPDATE users SET totp_last_step = sqlc.arg(step)
WHERE id = sqlc.arg(id) AND (totp_last_step IS NULL OR totp_last_step < sqlc.arg(step));

-- name: CreateSession :exec
INSERT INTO sessions (token_hash, user_id, expires_at)
VALUES ($1, $2, $3);

-- name: GetUserBySessionToken :one
SELECT u.* FROM users u
JOIN sessions s ON s.user_id = u.id
WHERE s.token_hash = $1 AND s.expires_at > now() AND u.disabled_at IS NULL;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE token_hash = $1;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at <= now();

-- name: LockUserAdministration :exec
SELECT pg_advisory_xact_lock(hashtext('graph.users.first_admin'));

-- name: AnyUserExists :one
SELECT EXISTS (SELECT 1 FROM users);

-- name: ListUserTOTPSecrets :many
SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL ORDER BY id;

-- name: ResealUserTOTPSecret :execrows
UPDATE users SET totp_secret = sqlc.arg(sealed)
WHERE id = sqlc.arg(id) AND totp_secret = sqlc.arg(old);
