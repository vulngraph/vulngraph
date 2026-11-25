package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	keyPrefix = "gph_"
	// displayPrefixLen is the part of a key shown in the UI ("gph_a1b2").
	displayPrefixLen = 8
	// lookupIDLen is the length of every key's indexed, unique lookup_id:
	// "gph_" plus 12 hex chars, 48 bits. The 16 bits of the display prefix
	// collide after a few hundred keys.
	lookupIDLen = 16
	// createAttempts bounds retries on the (astronomically unlikely) lookup_id
	// collision for a freshly generated key.
	createAttempts = 3
	// uniqueViolation is the Postgres SQLSTATE for a unique-constraint violation.
	uniqueViolation = "23505"
	// lastUsedResolution is how stale last_used_at may get before a verified
	// request rewrites it, so a busy key costs one UPDATE a minute, not one
	// per request.
	lastUsedResolution = time.Minute
)

// PGRepo implements Repository on Postgres using raw pgx queries.
// The api_keys queries have no sqlc-generated helpers; raw pgx keeps the build
// self-contained.
type PGRepo struct {
	pool *pgxpool.Pool
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{pool: pool} }

// Create generates a fresh key, stores its SHA-256 digest, and
// returns the domain APIKey together with the plaintext key. The plaintext is
// returned ONCE — the caller must hand it to the user immediately.
func (r *PGRepo) Create(ctx context.Context, userID, name string, scope Scope, expiresAt *time.Time) (APIKey, string, error) {
	for attempt := 1; ; attempt++ {
		key, plaintext, err := r.create(ctx, userID, name, scope, expiresAt)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && attempt < createAttempts {
			continue
		}
		return key, plaintext, err
	}
}

func (r *PGRepo) create(ctx context.Context, userID, name string, scope Scope, expiresAt *time.Time) (APIKey, string, error) {
	// 32 random bytes → 64-char hex string → full key = "gph_" + 64 chars
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return APIKey{}, "", fmt.Errorf("Create: generate key bytes: %w", err)
	}
	plaintext := keyPrefix + hex.EncodeToString(raw)
	prefix := plaintext[:displayPrefixLen]
	lookupID := plaintext[:lookupIDLen]

	const q = `
		INSERT INTO api_keys (user_id, name, key_hash, prefix, lookup_id, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`

	var id string
	var createdAt time.Time
	err := r.pool.QueryRow(ctx, q, userID, name, hashKey(plaintext), prefix, lookupID, string(scope), expiresAt).
		Scan(&id, &createdAt)
	if err != nil {
		return APIKey{}, "", fmt.Errorf("Create: insert: %w", err)
	}

	key := APIKey{
		ID:        id,
		UserID:    userID,
		Name:      name,
		Prefix:    prefix,
		Scopes:    scope,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
	}
	return key, plaintext, nil
}

// List returns all keys for userID, including expired ones so the UI can show
// and let the user delete them. The hash and plaintext are never returned.
func (r *PGRepo) List(ctx context.Context, userID string) ([]APIKey, error) {
	const q = `
		SELECT id, user_id, name, prefix, scopes, last_used_at, expires_at, created_at
		FROM   api_keys
		WHERE  user_id = $1
		ORDER  BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(
			&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
			&k.LastUsedAt, &k.ExpiresAt, &k.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("List: scan: %w", err)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("List: rows: %w", err)
	}
	return out, nil
}

// Delete hard-deletes a key by id, scoped to the owning userID so users
// cannot delete each other's keys.
func (r *PGRepo) Delete(ctx context.Context, id, userID string) error {
	const q = `DELETE FROM api_keys WHERE id = $1 AND user_id = $2`
	tag, err := r.pool.Exec(ctx, q, id, userID)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// keyCandidate is the stored key whose lookup_id matches a presented plaintext.
type keyCandidate struct {
	key  APIKey
	hash string
}

// Verify finds the stored key matching plaintext by its unique 16-char
// lookup_id, checks the digest, enforces expiry, refreshes last_used_at when
// it is older than lastUsedResolution, and returns it. Returns ErrNotFound
// when nothing matches.
func (r *PGRepo) Verify(ctx context.Context, plaintext string) (APIKey, error) {
	if len(plaintext) < lookupIDLen {
		return APIKey{}, ErrNotFound
	}

	// A disabled owner's keys never match: offboarding a user ends their keys'
	// access without deleting them.
	const q = `
		SELECT k.id, k.user_id, k.name, k.key_hash, k.prefix, k.scopes, k.last_used_at, k.expires_at, k.created_at,
		       u.email, u.role, u.created_at, u.admin_since
		FROM   api_keys k
		JOIN   users u ON u.id = k.user_id
		WHERE  u.disabled_at IS NULL
		  AND  k.lookup_id = $1`

	var c keyCandidate
	var adminSince *time.Time
	err := r.pool.QueryRow(ctx, q, plaintext[:lookupIDLen]).Scan(
		&c.key.ID, &c.key.UserID, &c.key.Name, &c.hash, &c.key.Prefix, &c.key.Scopes,
		&c.key.LastUsedAt, &c.key.ExpiresAt, &c.key.CreatedAt, &c.key.OwnerEmail, &c.key.OwnerRole,
		&c.key.OwnerCreatedAt, &adminSince,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("Verify: lookup: %w", err)
	}
	if adminSince != nil {
		c.key.OwnerAdminSince = *adminSince
	}

	k, ok := matchKey(c, plaintext, time.Now())
	if !ok {
		return APIKey{}, ErrNotFound
	}

	// last_used_at is informational; a failed write does not refuse the key.
	now := time.Now()
	if !lastUsedStale(k.LastUsedAt, now) {
		return k, nil
	}
	const upd = `UPDATE api_keys SET last_used_at = $1 WHERE id = $2`
	if _, err := r.pool.Exec(ctx, upd, now, k.ID); err == nil {
		k.LastUsedAt = &now
	}
	return k, nil
}

// hashKey is the stored form of a key: hex SHA-256, the same digest session
// tokens are stored as. A key carries 256 random bits, so a fast digest
// cannot be brute-forced and a password KDF would only charge every request
// its CPU cost.
func hashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// lastUsedStale reports whether last_used_at is old enough to rewrite.
func lastUsedStale(last *time.Time, now time.Time) bool {
	return last == nil || now.Sub(*last) >= lastUsedResolution
}

// matchKey reports whether c's stored digest matches plaintext and the key is
// unexpired. The digests are compared in constant time.
//
// Expiry is enforced on the match: a key past its expires_at must not
// authenticate even though its hash still matches. Without this the only
// credential-rotation knob the platform offers is cosmetic, and a leaked key
// that can reach execute_action never loses access until hard-deleted.
func matchKey(c keyCandidate, plaintext string, now time.Time) (APIKey, bool) {
	if subtle.ConstantTimeCompare([]byte(hashKey(plaintext)), []byte(c.hash)) != 1 {
		return APIKey{}, false
	}
	if c.key.ExpiresAt != nil && !c.key.ExpiresAt.After(now) {
		return APIKey{}, false
	}
	return c.key, true
}
