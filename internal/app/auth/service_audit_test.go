package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

type auditRow struct {
	action, targetType, targetID, actor string
	details                             map[string]any
}

type fakeAudit struct{ rows []auditRow }

func (f *fakeAudit) Record(ctx context.Context, action, targetType, targetID string, details map[string]any) {
	actor := ""
	if u, ok := UserFromContext(ctx); ok {
		actor = u.Email
	}
	f.rows = append(f.rows, auditRow{action, targetType, targetID, actor, details})
}

func newAuditedAuth(t *testing.T) (*Service, *fakeRepo, *fakeAudit, context.Context) {
	t.Helper()
	svc, repo := newTestService(t)
	a := &fakeAudit{}
	svc.WithAudit(a)
	admin := repo.users["admin@example.com"].User
	return svc, repo, a, ContextWithUser(context.Background(), admin)
}

// No row ever carries a credential: these are the only detail keys written.
var allowedDetailKeys = map[string]bool{
	"email": true, "role": true, "before": true, "after": true, "was_disabled": true,
	"sessions_revoked": true, "replaced": true, "expires_at": true, "via": true, "issuer": true,
	"method": true, "reason": true, "email_malformed": true, "totp": true,
}

func rowsWithAction(rows []auditRow, action string) []auditRow {
	var out []auditRow
	for _, r := range rows {
		if r.action == action {
			out = append(out, r)
		}
	}
	return out
}

func requireNoSecrets(t *testing.T, rows []auditRow) {
	t.Helper()
	for _, r := range rows {
		require.Equal(t, AuditTargetUser, r.targetType)
		for k := range r.details {
			require.Truef(t, allowedDetailKeys[k], "%s writes unexpected detail %q", r.action, k)
		}
	}
}

func TestUserAdministration_IsAudited(t *testing.T) {
	svc, _, a, ctx := newAuditedAuth(t)

	u, err := svc.CreateUser(ctx, "Analyst@Example.com", testPassword, RoleAnalyst)
	require.NoError(t, err)
	promote := RoleAdmin
	_, err = svc.UpdateUser(ctx, userID(t, svc, "admin@example.com"), u.ID, UserUpdate{Role: &promote})
	require.NoError(t, err)
	disabled := true
	_, err = svc.UpdateUser(ctx, userID(t, svc, "admin@example.com"), u.ID, UserUpdate{Disabled: &disabled})
	require.NoError(t, err)
	enabled := false
	_, err = svc.UpdateUser(ctx, userID(t, svc, "admin@example.com"), u.ID, UserUpdate{Disabled: &enabled})
	require.NoError(t, err)
	_, err = svc.RevokeSessions(ctx, userID(t, svc, "admin@example.com"), u.ID)
	require.NoError(t, err)
	require.NoError(t, svc.DeleteUser(ctx, userID(t, svc, "admin@example.com"), u.ID))

	require.Equal(t, []auditRow{
		{AuditActionUserCreate, AuditTargetUser, u.ID, "admin@example.com", map[string]any{"email": "analyst@example.com", "role": "analyst"}},
		{AuditActionUserRoleChange, AuditTargetUser, u.ID, "admin@example.com", map[string]any{"email": "analyst@example.com", "before": "analyst", "after": "admin"}},
		{AuditActionUserDisable, AuditTargetUser, u.ID, "admin@example.com", map[string]any{"email": "analyst@example.com", "was_disabled": false, "sessions_revoked": int64(0)}},
		{AuditActionUserEnable, AuditTargetUser, u.ID, "admin@example.com", map[string]any{"email": "analyst@example.com", "was_disabled": true}},
		{AuditActionSessionsRevoke, AuditTargetUser, u.ID, "admin@example.com", map[string]any{"email": "analyst@example.com", "sessions_revoked": int64(0)}},
		{AuditActionUserDelete, AuditTargetUser, u.ID, "admin@example.com", map[string]any{"email": "analyst@example.com", "role": "admin"}},
	}, a.rows)
	requireNoSecrets(t, a.rows)
}

// A refused change writes no row: only what took effect is recorded.
func TestUserAdministration_RefusedChangesWriteNoRow(t *testing.T) {
	svc, _, a, ctx := newAuditedAuth(t)
	self := userID(t, svc, "admin@example.com")
	viewer := RoleViewer

	_, err := svc.UpdateUser(ctx, self, self, UserUpdate{Role: &viewer})
	require.ErrorIs(t, err, ErrSelfAction)
	_, err = svc.CreateUser(ctx, "short@example.com", "short", RoleViewer)
	require.Error(t, err)
	require.ErrorIs(t, svc.DeleteUser(ctx, self, "missing"), ErrNotFound)
	require.Empty(t, a.rows)
}

// A role or disable write that fails commits nothing (the change and its
// sign-out share one transaction), so it writes no row and keeps the sessions.
func TestUserAdministration_FailedWriteWritesNoRow(t *testing.T) {
	svc, repo, a, ctx := newAuditedAuth(t)
	svc.WithRequireAdminTOTP(true)
	u, err := svc.CreateUser(ctx, "analyst@example.com", testPassword, RoleAnalyst)
	require.NoError(t, err)
	token, _, err := svc.Login(context.Background(), "analyst@example.com", testPassword, "")
	require.NoError(t, err)
	a.rows = nil
	repo.userWriteErr = errors.New("connection reset")

	admin, disabled := RoleAdmin, true
	_, err = svc.UpdateUser(ctx, userID(t, svc, "admin@example.com"), u.ID, UserUpdate{Role: &admin})
	require.ErrorIs(t, err, repo.userWriteErr)
	_, err = svc.UpdateUser(ctx, userID(t, svc, "admin@example.com"), u.ID, UserUpdate{Disabled: &disabled})
	require.ErrorIs(t, err, repo.userWriteErr)

	require.Empty(t, a.rows)
	got, err := svc.Authenticate(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, RoleAnalyst, got.Role, "the failed promotion left the role and its session as they were")
}

func TestEnrollTOTP_AuditsEnrolmentAndReset(t *testing.T) {
	svc, _, a, _ := newAuditedAuth(t)
	_, err := svc.EnrollTOTP(context.Background(), "admin@example.com")
	require.NoError(t, err)
	_, err = svc.EnrollTOTP(context.Background(), "admin@example.com")
	require.NoError(t, err)

	id := userID(t, svc, "admin@example.com")
	require.Equal(t, []auditRow{
		{AuditActionTOTPEnroll, AuditTargetUser, id, "", map[string]any{"email": "admin@example.com", "replaced": false}},
		{AuditActionTOTPEnroll, AuditTargetUser, id, "", map[string]any{"email": "admin@example.com", "replaced": true}},
	}, a.rows)
	requireNoSecrets(t, a.rows)
}

func TestIssueToken_IsAudited(t *testing.T) {
	svc, _, a, _ := newAuditedAuth(t)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return at }

	token, err := svc.IssueToken(context.Background(), "admin@example.com")
	require.NoError(t, err)
	require.Equal(t, []auditRow{{AuditActionTokenIssue, AuditTargetUser, userID(t, svc, "admin@example.com"), "",
		map[string]any{"email": "admin@example.com", "role": "admin", "expires_at": "2026-03-08T12:00:00Z"}}}, a.rows)
	for _, v := range a.rows[0].details {
		require.NotEqual(t, token, v, "the token is never written")
	}
}

// A first SSO sign-in creates an account: a row whose actor is the new user.
// A returning user's sign-in writes no provisioning row; every sign-in writes
// an auth.login row.
func TestSSOProvisioning_IsAuditedAsTheNewUser(t *testing.T) {
	svc, _, a, _ := newAuditedAuth(t)
	id := OIDCIdentity{Issuer: "https://idp.example.com", Subject: "sub-1", Email: "new@example.com"}

	_, u, err := svc.LoginOIDC(context.Background(), id, Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	_, _, err = svc.LoginOIDC(context.Background(), id, Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	_, _, err = svc.LoginOAuth(context.Background(), "proxy@example.com", Provisioning{Role: RoleViewer})
	require.NoError(t, err)

	prov := rowsWithAction(a.rows, AuditActionUserProvision)
	require.Len(t, prov, 2)
	require.Equal(t, auditRow{AuditActionUserProvision, AuditTargetUser, u.ID, "new@example.com",
		map[string]any{"email": "new@example.com", "role": "viewer", "via": "oidc", "issuer": "https://idp.example.com"}}, prov[0])
	require.Equal(t, "proxy@example.com", prov[1].actor)
	require.Equal(t, "oauth2_proxy", prov[1].details["via"])
	logins := rowsWithAction(a.rows, AuditActionLogin)
	require.Len(t, logins, 3)
	require.Equal(t, auditRow{AuditActionLogin, AuditTargetUser, u.ID, "new@example.com",
		map[string]any{"email": "new@example.com", "method": "oidc", "issuer": "https://idp.example.com"}}, logins[1])
	require.Equal(t, "oauth2_proxy", logins[2].details["method"])
	requireNoSecrets(t, a.rows)
}

func TestRequireAdminTOTP_RefusesPasswordSignInWithoutTOTP(t *testing.T) {
	svc, repo := newTestService(t)
	svc.WithRequireAdminTOTP(true)
	_, err := svc.CreateUser(context.Background(), "viewer@example.com", testPassword, RoleViewer)
	require.NoError(t, err)

	_, _, err = svc.Login(context.Background(), "admin@example.com", testPassword, "")
	require.ErrorIs(t, err, ErrInvalidCredentials, "an admin with no TOTP cannot sign in by password")
	require.Empty(t, repo.sessions)

	_, _, err = svc.Login(context.Background(), "viewer@example.com", testPassword, "")
	require.NoError(t, err, "the rule is for admins only")

	_, err = svc.EnrollTOTP(context.Background(), "admin@example.com")
	require.NoError(t, err)
	code, err := totp.GenerateCode(repo.users["admin@example.com"].TOTPSecret, time.Now())
	require.NoError(t, err)
	_, _, err = svc.Login(context.Background(), "admin@example.com", testPassword, code)
	require.NoError(t, err, "an enrolled admin signs in with a code")
}

func TestRequireAdminTOTP_OffByDefault(t *testing.T) {
	svc, _ := newTestService(t)
	_, _, err := svc.Login(context.Background(), "admin@example.com", testPassword, "")
	require.NoError(t, err)
}

// A user promoted to admin under the rule loses the sessions they opened
// without a code, so the admin role is only held by a session that passed it.
func TestRequireAdminTOTP_PromotionEndsSessions(t *testing.T) {
	svc, _ := newTestService(t)
	a := &fakeAudit{}
	svc.WithAudit(a).WithRequireAdminTOTP(true)
	u, err := svc.CreateUser(context.Background(), "analyst@example.com", testPassword, RoleAnalyst)
	require.NoError(t, err)
	token, _, err := svc.Login(context.Background(), "analyst@example.com", testPassword, "")
	require.NoError(t, err)

	admin := RoleAdmin
	_, err = svc.UpdateUser(context.Background(), userID(t, svc, "admin@example.com"), u.ID, UserUpdate{Role: &admin})
	require.NoError(t, err)

	_, err = svc.Authenticate(context.Background(), token)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Equal(t, int64(1), a.rows[len(a.rows)-1].details["sessions_revoked"])
	_, _, err = svc.Login(context.Background(), "analyst@example.com", testPassword, "")
	require.ErrorIs(t, err, ErrInvalidCredentials, "the new admin signs in again under the TOTP rule")
}

func userID(t *testing.T, s *Service, email string) string {
	t.Helper()
	c, err := s.repo.GetUserCredentialsByEmail(context.Background(), email)
	require.NoError(t, err)
	return c.ID
}

// Every password sign-in writes a row: auth.login on success, auth.login_failed
// with the reason on failure. The client still sees one answer for all of them.
func TestPasswordSignIn_IsAudited(t *testing.T) {
	svc, repo, a, _ := newAuditedAuth(t)
	ctx := ContextWithClientIP(context.Background(), "192.0.2.7")
	adminID := repo.users["admin@example.com"].ID

	_, _, err := svc.Login(ctx, "admin@example.com", testPassword, "")
	require.NoError(t, err)
	_, _, err = svc.Login(ctx, "admin@example.com", "wrong-password-123", "")
	require.ErrorIs(t, err, ErrInvalidCredentials)
	_, _, err = svc.Login(ctx, "nobody@example.com", testPassword, "")
	require.ErrorIs(t, err, ErrInvalidCredentials)
	_, _, err = svc.Login(ctx, testPassword, testPassword, "")
	require.ErrorIs(t, err, ErrInvalidCredentials)

	require.Equal(t, []auditRow{
		{AuditActionLogin, AuditTargetUser, adminID, "admin@example.com",
			map[string]any{"email": "admin@example.com", "method": "password", "totp": false}},
		{AuditActionLoginFailed, AuditTargetUser, adminID, "",
			map[string]any{"email": "admin@example.com", "method": "password", "reason": LoginReasonWrongPassword}},
		{AuditActionLoginFailed, AuditTargetUser, "", "",
			map[string]any{"email": "nobody@example.com", "method": "password", "reason": LoginReasonUnknownEmail}},
		{AuditActionLoginFailed, AuditTargetUser, "", "",
			map[string]any{"email_malformed": true, "method": "password", "reason": LoginReasonUnknownEmail}},
	}, a.rows)
	requireNoSecrets(t, a.rows)
	for _, r := range a.rows {
		for _, v := range r.details {
			require.NotEqual(t, testPassword, v, "a password typed into the email field is not recorded")
		}
	}
}

func TestLogout_IsAudited(t *testing.T) {
	svc, repo, a, _ := newAuditedAuth(t)
	token, u, err := svc.Login(context.Background(), "admin@example.com", testPassword, "")
	require.NoError(t, err)
	a.rows = nil

	require.NoError(t, svc.Logout(ContextWithUser(context.Background(), u), token, "sign_out"))
	require.Equal(t, []auditRow{{AuditActionLogout, AuditTargetUser, repo.users["admin@example.com"].ID, "admin@example.com",
		map[string]any{"reason": "sign_out"}}}, a.rows)
}
