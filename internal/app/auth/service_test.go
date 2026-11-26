package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// fakeRepo is an in-memory Repo for service tests.
type fakeRepo struct {
	adminMu   sync.Mutex
	users     map[string]UserCredentials // by email
	sessions  map[string]session         // by token hash
	totpSteps map[string]int64           // last accepted step by user id
	nextID    int
	// oidcLookupErr, when set, fails GetUserCredentialsByOIDC (a store error).
	oidcLookupErr error
	// userWriteErr, when set, fails SetUserRole and SetUserDisabledAt with
	// nothing changed (a rolled-back transaction).
	userWriteErr error
}

type session struct {
	userID    string
	expiresAt time.Time
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{users: map[string]UserCredentials{}, sessions: map[string]session{}, totpSteps: map[string]int64{}}
}

func (f *fakeRepo) CreateUser(_ context.Context, email, passwordHash string, role Role) (User, error) {
	if _, exists := f.users[email]; exists {
		return User{}, ErrEmailTaken
	}
	f.nextID++
	user := User{ID: string(rune('a' + f.nextID)), Email: email, Role: role, CreatedAt: time.Now()}
	f.users[email] = UserCredentials{User: user, PasswordHash: passwordHash}
	return user, nil
}

func (f *fakeRepo) CreateUserOrFirstAdmin(ctx context.Context, email, passwordHash string, role Role) (User, error) {
	if len(f.users) == 0 {
		role = RoleAdmin
	}
	return f.CreateUser(ctx, email, passwordHash, role)
}

func (f *fakeRepo) ListUsers(_ context.Context) ([]User, error) {
	out := make([]User, 0, len(f.users))
	for _, c := range f.users {
		out = append(out, c.User)
	}
	return out, nil
}

func (f *fakeRepo) GetUserCredentialsByEmail(_ context.Context, email string) (UserCredentials, error) {
	creds, ok := f.users[email]
	if !ok {
		return UserCredentials{}, ErrNotFound
	}
	return creds, nil
}

func (f *fakeRepo) GetUserBySessionToken(_ context.Context, tokenHash string) (User, error) {
	s, ok := f.sessions[tokenHash]
	if !ok || s.expiresAt.Before(time.Now()) {
		return User{}, ErrUnauthenticated
	}
	for _, creds := range f.users {
		if creds.ID == s.userID && creds.DisabledAt == nil {
			return creds.User, nil
		}
	}
	return User{}, ErrUnauthenticated
}

// disable marks a seeded user disabled, as the admin endpoint would.
func (f *fakeRepo) disable(email string) {
	creds := f.users[email]
	now := time.Now()
	creds.DisabledAt = &now
	f.users[email] = creds
}

func (f *fakeRepo) CreateSession(_ context.Context, tokenHash, userID string, expiresAt time.Time) error {
	f.sessions[tokenHash] = session{userID: userID, expiresAt: expiresAt}
	return nil
}

func (f *fakeRepo) DeleteSession(_ context.Context, tokenHash string) error {
	delete(f.sessions, tokenHash)
	return nil
}

func (f *fakeRepo) DeleteExpiredSessions(_ context.Context) (int64, error) {
	var n int64
	for hash, s := range f.sessions {
		if !s.expiresAt.After(time.Now()) {
			delete(f.sessions, hash)
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) SetTOTPSecret(_ context.Context, userID, secret string) error {
	for email, creds := range f.users {
		if creds.ID == userID {
			creds.TOTPSecret = secret
			f.users[email] = creds
			delete(f.totpSteps, userID)
			return nil
		}
	}
	return ErrNotFound
}

func (f *fakeRepo) AdvanceTOTPStep(_ context.Context, userID string, step int64) error {
	if last, ok := f.totpSteps[userID]; ok && step <= last {
		return ErrTOTPReplayed
	}
	f.totpSteps[userID] = step
	return nil
}

const testPassword = "correct-horse-battery"

func newTestService(t *testing.T) (*Service, *fakeRepo) {
	t.Helper()
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.CreateUser(context.Background(), "admin@example.com", testPassword, RoleAdmin)
	require.NoError(t, err)
	return svc, repo
}

func TestLogin_Succeeds(t *testing.T) {
	svc, _ := newTestService(t)

	token, user, err := svc.Login(context.Background(), "admin@example.com", testPassword, "")
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.Equal(t, "admin@example.com", user.Email)

	authed, err := svc.Authenticate(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, user.ID, authed.ID)
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, _ := newTestService(t)
	_, _, err := svc.Login(context.Background(), "admin@example.com", "wrong-password-here", "")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestLogin_UnknownEmail(t *testing.T) {
	svc, _ := newTestService(t)
	_, _, err := svc.Login(context.Background(), "nobody@example.com", testPassword, "")
	require.ErrorIs(t, err, ErrInvalidCredentials)
}

func TestLogin_TOTP(t *testing.T) {
	svc, repo := newTestService(t)
	url, err := svc.EnrollTOTP(context.Background(), "admin@example.com")
	require.NoError(t, err)
	require.Contains(t, url, "otpauth://")

	// A right password without a code must be indistinguishable from a wrong
	// password: "totp code required" confirmed the password to a guesser.
	t.Run("missing code is the generic error", func(t *testing.T) {
		_, _, err := svc.Login(context.Background(), "admin@example.com", testPassword, "")
		require.ErrorIs(t, err, ErrInvalidCredentials)
	})

	t.Run("wrong code is the generic error", func(t *testing.T) {
		_, _, err := svc.Login(context.Background(), "admin@example.com", testPassword, "000000")
		require.ErrorIs(t, err, ErrInvalidCredentials)
	})

	t.Run("valid code with wrong password is the generic error", func(t *testing.T) {
		code, err := totp.GenerateCode(repo.users["admin@example.com"].TOTPSecret, time.Now())
		require.NoError(t, err)
		_, _, err = svc.Login(context.Background(), "admin@example.com", "wrong-password-here", code)
		require.ErrorIs(t, err, ErrInvalidCredentials)
	})

	t.Run("valid code, then its replay", func(t *testing.T) {
		code, err := totp.GenerateCode(repo.users["admin@example.com"].TOTPSecret, time.Now())
		require.NoError(t, err)
		token, _, err := svc.Login(context.Background(), "admin@example.com", testPassword, code)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		_, _, err = svc.Login(context.Background(), "admin@example.com", testPassword, code)
		require.ErrorIs(t, err, ErrInvalidCredentials, "a used code must not log in again")
	})
}

func TestMatchTOTPStep(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "t", AccountName: "a"})
	require.NoError(t, err)
	now := time.Unix(1_800_000_000, 0)
	current := now.Unix() / 30

	for offset := int64(-1); offset <= 1; offset++ {
		code, err := totp.GenerateCode(key.Secret(), now.Add(time.Duration(offset)*30*time.Second))
		require.NoError(t, err)
		step, ok := matchTOTPStep(code, key.Secret(), now)
		require.True(t, ok, "offset %d within skew", offset)
		require.Equal(t, current+offset, step)
	}

	stale, err := totp.GenerateCode(key.Secret(), now.Add(-90*time.Second))
	require.NoError(t, err)
	_, ok := matchTOTPStep(stale, key.Secret(), now)
	require.False(t, ok, "outside the skew window")

	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		_, ok := matchTOTPStep(bad, key.Secret(), now)
		require.False(t, ok, bad)
	}
}

func TestIssueToken_AuthenticatesWithoutPassword(t *testing.T) {
	svc, _ := newTestService(t)

	token, err := svc.IssueToken(context.Background(), "admin@example.com")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	user, err := svc.Authenticate(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "admin@example.com", user.Email)
	require.Equal(t, RoleAdmin, user.Role)
}

func TestIssueToken_UnknownEmail(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.IssueToken(context.Background(), "nobody@example.com")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestLogout_InvalidatesSession(t *testing.T) {
	svc, _ := newTestService(t)
	token, _, err := svc.Login(context.Background(), "admin@example.com", testPassword, "")
	require.NoError(t, err)

	require.NoError(t, svc.Logout(context.Background(), token, "sign_out"))

	_, err = svc.Authenticate(context.Background(), token)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestAuthenticate_BogusToken(t *testing.T) {
	svc, _ := newTestService(t)
	_, err := svc.Authenticate(context.Background(), "not-a-real-token")
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestCreateUser_Validation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tests := []struct {
		name     string
		email    string
		password string
		role     Role
		wantErr  string
	}{
		{"bad email", "not-an-email", testPassword, RoleViewer, "email"},
		{"bad role", "x@example.com", testPassword, Role("root"), "invalid role"},
		{"short password", "x@example.com", "short", RoleViewer, "at least 12 characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateUser(ctx, tt.email, tt.password, tt.role)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}

	t.Run("duplicate email", func(t *testing.T) {
		_, err := svc.CreateUser(ctx, "admin@example.com", testPassword, RoleViewer)
		require.ErrorIs(t, err, ErrEmailTaken)
	})
}

func TestDisabledUser_CannotAuthenticate(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()
	token, _, err := svc.Login(ctx, "admin@example.com", testPassword, "")
	require.NoError(t, err)

	repo.disable("admin@example.com")

	_, err = svc.Authenticate(ctx, token)
	require.ErrorIs(t, err, ErrUnauthenticated, "an existing session stops working")

	_, _, err = svc.Login(ctx, "admin@example.com", testPassword, "")
	require.ErrorIs(t, err, ErrInvalidCredentials, "password login is refused with the generic error")

	_, _, err = svc.LoginOAuth(ctx, "admin@example.com", Provisioning{Role: RoleViewer})
	require.ErrorIs(t, err, ErrUserDisabled)

	_, err = svc.IssueToken(ctx, "admin@example.com")
	require.ErrorIs(t, err, ErrUserDisabled)
}

func TestEmailsAreCaseInsensitive(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	u, err := svc.CreateUser(ctx, "  Alice@Example.COM ", testPassword, RoleViewer)
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", u.Email, "stored in canonical form")

	_, err = svc.CreateUser(ctx, "ALICE@example.com", testPassword, RoleViewer)
	require.ErrorIs(t, err, ErrEmailTaken)

	_, got, err := svc.Login(ctx, "ALICE@EXAMPLE.com", testPassword, "")
	require.NoError(t, err)
	require.Equal(t, u.ID, got.ID)

	// An IdP returning a differently-cased address signs into the existing
	// account rather than provisioning a second one.
	_, got, err = svc.LoginOAuth(ctx, "Admin@Example.com", Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	require.Equal(t, RoleAdmin, got.Role)
	require.Len(t, repo.users, 2)
}
