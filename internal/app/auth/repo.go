package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// SecretCipher seals TOTP seeds at rest. *connector.Cipher implements it, so
// TOTP seeds share the GRAPH_SECRET_KEY envelope and its rotation.
type SecretCipher interface {
	EncryptWithAAD(plaintext, aad []byte) ([]byte, error)
	DecryptWithAAD(ciphertext, aad []byte) ([]byte, error)
	// IsCurrentEnvelope reports whether ct is already sealed under the current key.
	IsCurrentEnvelope(ct []byte) bool
}

// PGRepo implements Repo on Postgres via sqlc.
type PGRepo struct {
	pool   *pgxpool.Pool
	q      *sqlcgen.Queries
	cipher SecretCipher
	tx     pgx.Tx
}

// NewPGRepo builds the repo. cipher seals and opens users.totp_secret.
func NewPGRepo(pool *pgxpool.Pool, cipher SecretCipher) *PGRepo {
	return &PGRepo{pool: pool, q: sqlcgen.New(pool), cipher: cipher}
}

const uniqueViolation = "23505"

func (r *PGRepo) CreateUser(ctx context.Context, email, passwordHash string, role Role) (User, error) {
	return createUser(ctx, r.q, email, passwordHash, role)
}

// CreateUserOrFirstAdmin provisions RoleAdmin instead of role when no user
// exists yet. The advisory lock serialises concurrent callers: the emptiness
// check and the insert of one commit before the next caller checks, so at most
// one of two simultaneous first sign-ins sees an empty table.
func (r *PGRepo) CreateUserOrFirstAdmin(ctx context.Context, email, passwordHash string, role Role) (User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("CreateUserOrFirstAdmin: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	q := r.q.WithTx(tx)
	if err := q.LockUserAdministration(ctx); err != nil {
		return User{}, fmt.Errorf("CreateUserOrFirstAdmin: lock: %w", err)
	}
	exists, err := q.AnyUserExists(ctx)
	if err != nil {
		return User{}, fmt.Errorf("CreateUserOrFirstAdmin: %w", err)
	}
	if !exists {
		role = RoleAdmin
	}
	user, err := createUser(ctx, q, email, passwordHash, role)
	if err != nil {
		return User{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("CreateUserOrFirstAdmin: commit: %w", err)
	}
	return user, nil
}

func createUser(ctx context.Context, q *sqlcgen.Queries, email, passwordHash string, role Role) (User, error) {
	row, err := q.CreateUser(ctx, sqlcgen.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
		Role:         string(role),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("CreateUser: %w", err)
	}
	return toDomainUser(row), nil
}

func (r *PGRepo) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := r.q.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListUsers: %w", err)
	}
	out := make([]User, len(rows))
	for i, row := range rows {
		out[i] = toDomainUser(row)
	}
	return out, nil
}

func (r *PGRepo) GetUserCredentialsByEmail(ctx context.Context, email string) (UserCredentials, error) {
	row, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserCredentials{}, ErrNotFound
		}
		return UserCredentials{}, fmt.Errorf("GetUserCredentialsByEmail: %w", err)
	}
	creds, err := r.toDomainCredentials(row)
	if err != nil {
		return UserCredentials{}, fmt.Errorf("GetUserCredentialsByEmail: %w", err)
	}
	return creds, nil
}

func (r *PGRepo) GetUserCredentialsByOIDC(ctx context.Context, issuer, subject string) (UserCredentials, error) {
	row, err := r.q.GetUserByOIDCIdentity(ctx, sqlcgen.GetUserByOIDCIdentityParams{
		OidcIssuer:  pgtype.Text{String: issuer, Valid: true},
		OidcSubject: pgtype.Text{String: subject, Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserCredentials{}, ErrNotFound
		}
		return UserCredentials{}, fmt.Errorf("GetUserCredentialsByOIDC: %w", err)
	}
	creds, err := r.toDomainCredentials(row)
	if err != nil {
		return UserCredentials{}, fmt.Errorf("GetUserCredentialsByOIDC: %w", err)
	}
	return creds, nil
}

// BindOIDCIdentity records the IdP identity on a not-yet-bound user. It
// returns ErrIdentityMismatch when the user is already bound (a concurrent
// first sign-in won) or the identity already belongs to another user.
func (r *PGRepo) BindOIDCIdentity(ctx context.Context, userID, issuer, subject string) error {
	n, err := r.q.BindUserOIDCIdentity(ctx, sqlcgen.BindUserOIDCIdentityParams{
		ID:          userID,
		OidcIssuer:  pgtype.Text{String: issuer, Valid: true},
		OidcSubject: pgtype.Text{String: subject, Valid: true},
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return ErrIdentityMismatch
		}
		return fmt.Errorf("BindOIDCIdentity: %w", err)
	}
	if n == 0 {
		return ErrIdentityMismatch
	}
	return nil
}

func (r *PGRepo) GetUserBySessionToken(ctx context.Context, tokenHash string) (User, error) {
	row, err := r.q.GetUserBySessionToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUnauthenticated
		}
		return User{}, fmt.Errorf("GetUserBySessionToken: %w", err)
	}
	return toDomainUser(row), nil
}

func (r *PGRepo) CreateSession(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error {
	err := r.q.CreateSession(ctx, sqlcgen.CreateSessionParams{
		TokenHash: tokenHash,
		UserID:    userID,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return fmt.Errorf("CreateSession: %w", err)
	}
	return nil
}

func (r *PGRepo) DeleteSession(ctx context.Context, tokenHash string) error {
	if err := r.q.DeleteSession(ctx, tokenHash); err != nil {
		return fmt.Errorf("DeleteSession: %w", err)
	}
	return nil
}

func (r *PGRepo) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	n, err := r.q.DeleteExpiredSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("DeleteExpiredSessions: %w", err)
	}
	return n, nil
}

func (r *PGRepo) SetTOTPSecret(ctx context.Context, userID, secret string) error {
	sealed, err := sealTOTP(r.cipher, userID, secret)
	if err != nil {
		return fmt.Errorf("SetTOTPSecret: %w", err)
	}
	err = r.q.SetUserTOTPSecret(ctx, sqlcgen.SetUserTOTPSecretParams{
		ID:         userID,
		TotpSecret: &sealed,
	})
	if err != nil {
		return fmt.Errorf("SetTOTPSecret: %w", err)
	}
	return nil
}

func (r *PGRepo) GetUserByID(ctx context.Context, id string) (User, error) {
	row, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, fmt.Errorf("GetUserByID: %w", err)
	}
	return toDomainUser(row), nil
}

func (r *PGRepo) SetUserRole(ctx context.Context, id string, role Role, revokeSessions bool) (int64, error) {
	n, err := r.updateUser(ctx, id, revokeSessions, func(q *sqlcgen.Queries) (int64, error) {
		return q.SetUserRole(ctx, sqlcgen.SetUserRoleParams{ID: id, Role: string(role)})
	})
	if err != nil {
		return 0, fmt.Errorf("SetUserRole: %w", err)
	}
	return n, nil
}

// SetUserDisabledAt disables the user at t, or re-enables them when t is nil.
func (r *PGRepo) SetUserDisabledAt(ctx context.Context, id string, t *time.Time, revokeSessions bool) (int64, error) {
	var at pgtype.Timestamptz
	if t != nil {
		at = pgtype.Timestamptz{Time: *t, Valid: true}
	}
	n, err := r.updateUser(ctx, id, revokeSessions, func(q *sqlcgen.Queries) (int64, error) {
		return q.SetUserDisabledAt(ctx, sqlcgen.SetUserDisabledAtParams{ID: id, DisabledAt: at})
	})
	if err != nil {
		return 0, fmt.Errorf("SetUserDisabledAt: %w", err)
	}
	return n, nil
}

// updateUser runs update on user id and, when revokeSessions is set, deletes
// the user's sessions in the same transaction. It returns the sessions deleted.
func (r *PGRepo) updateUser(ctx context.Context, id string, revokeSessions bool, update func(*sqlcgen.Queries) (int64, error)) (int64, error) {
	if r.tx != nil {
		return updateUserQueries(ctx, r.q, id, revokeSessions, update)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("updateUser: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n, err := updateUserQueries(ctx, r.q.WithTx(tx), id, revokeSessions, update)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("updateUser: commit: %w", err)
	}
	return n, nil
}

func updateUserQueries(ctx context.Context, q *sqlcgen.Queries, id string, revokeSessions bool, update func(*sqlcgen.Queries) (int64, error)) (int64, error) {
	n, err := update(q)
	if err != nil {
		return 0, fmt.Errorf("updateUser: %w", err)
	}
	if n == 0 {
		return 0, ErrNotFound
	}
	if !revokeSessions {
		return 0, nil
	}
	n, err = q.DeleteUserSessions(ctx, id)
	if err != nil {
		return 0, fmt.Errorf("updateUser: sessions: %w", err)
	}
	return n, nil
}

// DeleteUser removes the user; sessions and API keys cascade.
func (r *PGRepo) DeleteUser(ctx context.Context, id string) error {
	n, err := r.q.DeleteUser(ctx, id)
	if err != nil {
		return fmt.Errorf("DeleteUser: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *PGRepo) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	n, err := r.q.DeleteUserSessions(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("DeleteUserSessions: %w", err)
	}
	return n, nil
}

func (r *PGRepo) CountActiveAdmins(ctx context.Context) (int64, error) {
	n, err := r.q.CountActiveAdmins(ctx)
	if err != nil {
		return 0, fmt.Errorf("CountActiveAdmins: %w", err)
	}
	return n, nil
}

// AdvanceTOTPStep records step as the user's last accepted TOTP step, and
// returns ErrTOTPReplayed when it is not later than the one already stored.
// The conditional UPDATE makes two concurrent logins with the same code race
// safely: exactly one advances the step.
func (r *PGRepo) AdvanceTOTPStep(ctx context.Context, userID string, step int64) error {
	n, err := r.q.AdvanceUserTOTPStep(ctx, sqlcgen.AdvanceUserTOTPStepParams{ID: userID, Step: pgtype.Int8{Int64: step, Valid: true}})
	if err != nil {
		return fmt.Errorf("AdvanceTOTPStep: %w", err)
	}
	if n == 0 {
		return ErrTOTPReplayed
	}
	return nil
}

func toDomainUser(row sqlcgen.User) User {
	return User{
		ID:               row.ID,
		Email:            row.Email,
		Role:             Role(row.Role),
		TOTPEnabled:      row.TotpSecret != nil,
		CreatedAt:        row.CreatedAt,
		AdminSince:       row.AdminSince.Time,
		AuthorityVersion: row.AuthorityVersion,
		DisabledAt:       timePtr(row.DisabledAt),
	}
}

func timePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

func (r *PGRepo) toDomainCredentials(row sqlcgen.User) (UserCredentials, error) {
	creds := UserCredentials{User: toDomainUser(row), PasswordHash: row.PasswordHash}
	if row.TotpSecret != nil {
		secret, err := openTOTP(r.cipher, row.ID, *row.TotpSecret)
		if err != nil {
			return UserCredentials{}, fmt.Errorf("user %s: %w", row.ID, err)
		}
		creds.TOTPSecret = secret
	}
	creds.OIDCIssuer = row.OidcIssuer.String
	creds.OIDCSubject = row.OidcSubject.String
	return creds, nil
}

// sealedTOTPPrefix marks a sealed users.totp_secret value. Every write seals, so
// a value without it is not a seed this code wrote and is refused on read.
const sealedTOTPPrefix = "sealed:"

// totpAAD binds a sealed seed to its user row, so a ciphertext copied onto
// another user does not open.
func totpAAD(userID string) []byte { return []byte("graph/users.totp_secret/" + userID) }

func sealTOTP(c SecretCipher, userID, secret string) (string, error) {
	ct, err := c.EncryptWithAAD([]byte(secret), totpAAD(userID))
	if err != nil {
		return "", fmt.Errorf("seal totp secret: %w", err)
	}
	return sealedTOTPPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// openTOTP returns the seed a sealed stored value holds.
func openTOTP(c SecretCipher, userID, stored string) (string, error) {
	ct, sealed, err := decodeSealedTOTP(stored)
	if err != nil {
		return "", err
	}
	if !sealed {
		return "", errors.New("open totp secret: stored value is not sealed")
	}
	plain, err := c.DecryptWithAAD(ct, totpAAD(userID))
	if err != nil {
		return "", fmt.Errorf("open totp secret: %w", err)
	}
	return string(plain), nil
}

func decodeSealedTOTP(stored string) (ct []byte, sealed bool, err error) {
	enc, ok := strings.CutPrefix(stored, sealedTOTPPrefix)
	if !ok {
		return nil, false, nil
	}
	ct, err = base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, true, fmt.Errorf("decode totp secret: %w", err)
	}
	return ct, true, nil
}

// RewrapTOTPSecrets re-seals every TOTP seed sealed under a key other than the
// current one, and reports how many rows it rewrote. Each write is conditional
// on the value it read, so a concurrent enrolment is never overwritten. Safe to
// re-run; a second run rewrites nothing. A seed that cannot be opened or
// written is left unchanged, the pass continues with the remaining rows, and
// the error names every such user.
func (r *PGRepo) RewrapTOTPSecrets(ctx context.Context) (int, error) {
	rows, err := r.q.ListUserTOTPSecrets(ctx)
	if err != nil {
		return 0, fmt.Errorf("RewrapTOTPSecrets: %w", err)
	}
	n, err := rewrapTOTPRows(ctx, r.cipher, rows, r.q.ResealUserTOTPSecret)
	if err != nil {
		return n, fmt.Errorf("RewrapTOTPSecrets: %w", err)
	}
	return n, nil
}

// totpResealer writes one re-sealed seed if the row still holds the value read.
type totpResealer func(ctx context.Context, arg sqlcgen.ResealUserTOTPSecretParams) (int64, error)

// rewrapTOTPRows is RewrapTOTPSecrets over rows already read. A row that fails
// does not stop the rows after it.
func rewrapTOTPRows(ctx context.Context, cipher SecretCipher, rows []sqlcgen.ListUserTOTPSecretsRow, reseal totpResealer) (int, error) {
	var n int
	var errs []error
	for _, row := range rows {
		if row.TotpSecret == nil {
			continue
		}
		changed, err := rewrapTOTPRow(ctx, cipher, row.ID, *row.TotpSecret, reseal)
		if err != nil {
			errs = append(errs, fmt.Errorf("user %s (left unchanged): %w", row.ID, err))
			continue
		}
		n += int(changed)
	}
	if len(errs) > 0 {
		return n, fmt.Errorf("rewrapTOTPRows: %d seed(s) not re-sealed: %w", len(errs), errors.Join(errs...))
	}
	return n, nil
}

func rewrapTOTPRow(ctx context.Context, cipher SecretCipher, userID, old string, reseal totpResealer) (int64, error) {
	ct, sealed, err := decodeSealedTOTP(old)
	if err != nil {
		return 0, fmt.Errorf("rewrapTOTPRow: %w", err)
	}
	if !sealed {
		return 0, errors.New("rewrapTOTPRow: stored value is not sealed")
	}
	if cipher.IsCurrentEnvelope(ct) {
		return 0, nil
	}
	secret, err := openTOTP(cipher, userID, old)
	if err != nil {
		return 0, fmt.Errorf("rewrapTOTPRow: %w", err)
	}
	resealed, err := sealTOTP(cipher, userID, secret)
	if err != nil {
		return 0, fmt.Errorf("rewrapTOTPRow: %w", err)
	}
	changed, err := reseal(ctx, sqlcgen.ResealUserTOTPSecretParams{ID: userID, Old: &old, Sealed: &resealed})
	if err != nil {
		return 0, fmt.Errorf("rewrapTOTPRow: %w", err)
	}
	return changed, nil
}
