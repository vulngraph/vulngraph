//go:build integration

package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_UserAndSessionRoundtrip(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, testPGDSN(), db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close) // registered first so it runs LAST (cleanups are LIFO)
	repo := NewPGRepo(pool, testCipher(t))

	// Unique per run: leftover rows from an interrupted run must never collide.
	suffix := time.Now().Format("150405.000000")
	email := "it-" + suffix + "@example.com"
	tokenHash, expiredHash := "tok-"+suffix, "expired-"+suffix
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email)
		require.NoError(t, err)
	})

	user, err := repo.CreateUser(ctx, email, "fake-hash", RoleAnalyst)
	require.NoError(t, err)
	require.Equal(t, RoleAnalyst, user.Role)
	require.False(t, user.TOTPEnabled)

	_, err = repo.CreateUser(ctx, email, "fake-hash", RoleAnalyst)
	require.ErrorIs(t, err, ErrEmailTaken)

	creds, err := repo.GetUserCredentialsByEmail(ctx, email)
	require.NoError(t, err)
	require.Equal(t, "fake-hash", creds.PasswordHash)

	require.NoError(t, repo.SetTOTPSecret(ctx, user.ID, "secret"))
	creds, err = repo.GetUserCredentialsByEmail(ctx, email)
	require.NoError(t, err)
	require.Equal(t, "secret", creds.TOTPSecret)
	require.True(t, creds.TOTPEnabled)

	// At rest the column holds the sealed envelope, never the seed, and a
	// value that is not sealed is refused rather than used as a seed.
	var stored string
	require.NoError(t, pool.QueryRow(ctx, "SELECT totp_secret FROM users WHERE id = $1", user.ID).Scan(&stored))
	require.True(t, strings.HasPrefix(stored, sealedTOTPPrefix))
	_, err = pool.Exec(ctx, "UPDATE users SET totp_secret = 'plainseed' WHERE id = $1", user.ID)
	require.NoError(t, err)
	_, err = repo.GetUserCredentialsByEmail(ctx, email)
	require.Error(t, err)
	_, err = pool.Exec(ctx, "UPDATE users SET totp_secret = $2 WHERE id = $1", user.ID, stored)
	require.NoError(t, err)

	// TOTP replay guard: a step must strictly advance, and
	// re-enrolling resets it.
	require.NoError(t, repo.AdvanceTOTPStep(ctx, user.ID, 100))
	require.ErrorIs(t, repo.AdvanceTOTPStep(ctx, user.ID, 100), ErrTOTPReplayed)
	require.ErrorIs(t, repo.AdvanceTOTPStep(ctx, user.ID, 99), ErrTOTPReplayed)
	require.NoError(t, repo.AdvanceTOTPStep(ctx, user.ID, 101))
	require.NoError(t, repo.SetTOTPSecret(ctx, user.ID, "secret"))
	require.NoError(t, repo.AdvanceTOTPStep(ctx, user.ID, 50))

	require.NoError(t, repo.CreateSession(ctx, tokenHash, user.ID, time.Now().Add(time.Hour)))
	got, err := repo.GetUserBySessionToken(ctx, tokenHash)
	require.NoError(t, err)
	require.Equal(t, user.ID, got.ID)

	require.NoError(t, repo.CreateSession(ctx, expiredHash, user.ID, time.Now().Add(-time.Hour)))
	_, err = repo.GetUserBySessionToken(ctx, expiredHash)
	require.ErrorIs(t, err, ErrUnauthenticated)

	_, err = pool.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", user.ID)
	require.NoError(t, err)
	_, err = repo.GetUserBySessionToken(ctx, tokenHash)
	require.ErrorIs(t, err, ErrUnauthenticated, "a disabled user's session must stop working")
	creds, err = repo.GetUserCredentialsByEmail(ctx, email)
	require.NoError(t, err)
	require.NotNil(t, creds.DisabledAt)
	_, err = pool.Exec(ctx, "UPDATE users SET disabled_at = NULL WHERE id = $1", user.ID)
	require.NoError(t, err)

	require.NoError(t, repo.DeleteSession(ctx, tokenHash))
	_, err = repo.GetUserBySessionToken(ctx, tokenHash)
	require.ErrorIs(t, err, ErrUnauthenticated)

	_, err = repo.GetUserCredentialsByEmail(ctx, "missing@example.com")
	require.ErrorIs(t, err, ErrNotFound)

	// Lookups are case-insensitive, and the schema refuses a non-canonical
	// address.
	creds, err = repo.GetUserCredentialsByEmail(ctx, strings.ToUpper(email))
	require.NoError(t, err)
	require.Equal(t, user.ID, creds.ID)
	_, err = repo.CreateUser(ctx, "Mixed-"+email, "fake-hash", RoleViewer)
	require.Error(t, err, "CHECK (email = lower(email)) must reject a mixed-case write")

	// OIDC binding: first bind wins, a second is refused,
	// and the identity is unique across users.
	issuer, subject := "https://idp.example", "sub-"+suffix
	_, err = repo.GetUserCredentialsByOIDC(ctx, issuer, subject)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, repo.BindOIDCIdentity(ctx, user.ID, issuer, subject))
	creds, err = repo.GetUserCredentialsByOIDC(ctx, issuer, subject)
	require.NoError(t, err)
	require.Equal(t, user.ID, creds.ID)
	require.Equal(t, subject, creds.OIDCSubject)
	require.ErrorIs(t, repo.BindOIDCIdentity(ctx, user.ID, issuer, "other"), ErrIdentityMismatch)

	otherEmail := "it-other-" + suffix + "@example.com"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM users WHERE email = $1", otherEmail) })
	other, err := repo.CreateUser(ctx, otherEmail, "fake-hash", RoleViewer)
	require.NoError(t, err)
	require.ErrorIs(t, repo.BindOIDCIdentity(ctx, other.ID, issuer, subject), ErrIdentityMismatch)
}

func TestPGRepo_UserAdministration(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, testPGDSN(), db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool, testCipher(t))

	email := "it-admin-" + time.Now().Format("150405.000000") + "@example.com"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email) })
	user, err := repo.CreateUser(ctx, email, "fake-hash", RoleViewer)
	require.NoError(t, err)

	got, err := repo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, email, got.Email)

	before, err := repo.CountActiveAdmins(ctx)
	require.NoError(t, err)
	for i := range 2 {
		require.NoError(t, repo.CreateSession(ctx, fmt.Sprintf("adm-%d-%s", i, user.ID), user.ID, time.Now().Add(time.Hour)))
	}
	revoked, err := repo.SetUserRole(ctx, user.ID, RoleAdmin, false)
	require.NoError(t, err)
	require.Zero(t, revoked, "the sessions are kept unless asked for")
	after, err := repo.CountActiveAdmins(ctx)
	require.NoError(t, err)
	require.Equal(t, before+1, after)

	now := time.Now()
	revoked, err = repo.SetUserDisabledAt(ctx, user.ID, &now, true)
	require.NoError(t, err)
	require.Equal(t, int64(2), revoked, "disabling ended both sessions in the same transaction")
	got, err = repo.GetUserByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, got.DisabledAt)
	disabledCount, err := repo.CountActiveAdmins(ctx)
	require.NoError(t, err)
	require.Equal(t, before, disabledCount, "a disabled admin is not an active admin")
	_, err = repo.SetUserDisabledAt(ctx, user.ID, nil, false)
	require.NoError(t, err)

	require.NoError(t, repo.CreateSession(ctx, "adm-x-"+user.ID, user.ID, time.Now().Add(time.Hour)))
	n, err := repo.DeleteUserSessions(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), n)

	require.NoError(t, repo.DeleteUser(ctx, user.ID))
	require.ErrorIs(t, repo.DeleteUser(ctx, user.ID), ErrNotFound)
	_, err = repo.GetUserByID(ctx, user.ID)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = repo.SetUserRole(ctx, user.ID, RoleViewer, true)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = repo.SetUserDisabledAt(ctx, user.ID, nil, true)
	require.ErrorIs(t, err, ErrNotFound)
}

// admin_since is when the role last became admin, written in the same statement
// as the role. It starts the executor's approver age floor, so promoting an old
// account must restart it, and a legacy admin (NULL) must keep reading as unknown.
func TestPGRepo_AdminSinceTracksBecomingAdmin(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, testPGDSN(), db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool, testCipher(t))

	suffix := time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM users WHERE email LIKE $1", "since-%-"+suffix+"@example.com")
		require.NoError(t, err)
	})
	adminSince := func(id string) time.Time {
		u, err := repo.GetUserByID(ctx, id)
		require.NoError(t, err)
		return u.AdminSince
	}

	// Created as admin: stamped now.
	created, err := repo.CreateUser(ctx, "since-admin-"+suffix+"@example.com", "fake-hash", RoleAdmin)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), created.AdminSince, time.Minute)

	// Created as viewer: unknown.
	viewer, err := repo.CreateUser(ctx, "since-viewer-"+suffix+"@example.com", "fake-hash", RoleViewer)
	require.NoError(t, err)
	require.True(t, viewer.AdminSince.IsZero())

	// An old viewer promoted now: the clock restarts at the promotion, not at created_at.
	_, err = pool.Exec(ctx, "UPDATE users SET created_at = now() - interval '400 days' WHERE id = $1", viewer.ID)
	require.NoError(t, err)
	_, err = repo.SetUserRole(ctx, viewer.ID, RoleAdmin, false)
	require.NoError(t, err)
	promoted := adminSince(viewer.ID)
	require.WithinDuration(t, time.Now(), promoted, time.Minute)

	// Setting admin again keeps the original time.
	_, err = repo.SetUserRole(ctx, viewer.ID, RoleAdmin, false)
	require.NoError(t, err)
	require.True(t, promoted.Equal(adminSince(viewer.ID)), "staying admin must not restart the clock")

	// Moving between non-admin roles stays unknown; leaving admin clears it.
	_, err = repo.SetUserRole(ctx, viewer.ID, RoleAnalyst, false)
	require.NoError(t, err)
	require.True(t, adminSince(viewer.ID).IsZero())

	// A legacy admin with unknown tenure receives a new tenure start; an old
	// account creation timestamp cannot satisfy the approval age floor.
	_, err = pool.Exec(ctx, "UPDATE users SET role = 'admin', admin_since = NULL WHERE id = $1", viewer.ID)
	require.NoError(t, err)
	_, err = repo.SetUserRole(ctx, viewer.ID, RoleAdmin, false)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), adminSince(viewer.ID), time.Minute)
}

// CreateUserOrFirstAdmin: on a populated table it keeps the requested role; on
// an empty one, concurrent first sign-ins race and exactly one becomes admin.
// The race half needs an empty users table, so it runs only against a scratch
// database (GRAPH_TEST_PG_DSN) — the shared dev database always has users.
func TestPGRepo_CreateUserOrFirstAdmin(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, testPGDSN(), db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool, testCipher(t))

	var empty bool
	require.NoError(t, pool.QueryRow(ctx, "SELECT NOT EXISTS (SELECT 1 FROM users)").Scan(&empty))
	suffix := time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM users WHERE email LIKE $1", "%-"+suffix+"@example.com")
		require.NoError(t, err)
	})

	if !empty {
		u, err := repo.CreateUserOrFirstAdmin(ctx, "later-"+suffix+"@example.com", "h", RoleViewer)
		require.NoError(t, err)
		require.Equal(t, RoleViewer, u.Role, "a populated install never bootstraps")
		t.Skip("users table not empty: the concurrent bootstrap race needs a scratch GRAPH_TEST_PG_DSN")
	}

	const racers = 8
	type result struct {
		role Role
		err  error
	}
	results := make(chan result, racers)
	for i := range racers {
		go func() {
			u, err := repo.CreateUserOrFirstAdmin(ctx, fmt.Sprintf("racer%d-%s@example.com", i, suffix), "h", RoleViewer)
			results <- result{u.Role, err}
		}()
	}
	admins := 0
	for range racers {
		res := <-results
		require.NoError(t, res.err)
		if res.role == RoleAdmin {
			admins++
		}
	}
	require.Equal(t, 1, admins, "exactly one concurrent first sign-in becomes admin")
}

// testPGDSN is the compose Postgres; GRAPH_TEST_PG_DSN points the test at another database.
func testPGDSN() string {
	if v := os.Getenv("GRAPH_TEST_PG_DSN"); v != "" {
		return v
	}
	return "postgres://graph:graph@localhost:5432/graph?sslmode=disable"
}
