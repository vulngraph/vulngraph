package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/validate"
)

// Repo is the persistence the service needs. PGRepo implements it.
type Repo interface {
	WithUserAdministration(ctx context.Context, fn func(UserAdminRepo) error) error
	CreateUser(ctx context.Context, email, passwordHash string, role Role) (User, error)
	// CreateUserOrFirstAdmin is CreateUser, except that it provisions RoleAdmin
	// when the users table is empty — decided atomically with the insert, so two
	// concurrent first sign-ins cannot both become admin.
	CreateUserOrFirstAdmin(ctx context.Context, email, passwordHash string, role Role) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	GetUserCredentialsByEmail(ctx context.Context, email string) (UserCredentials, error)
	GetUserCredentialsByOIDC(ctx context.Context, issuer, subject string) (UserCredentials, error)
	BindOIDCIdentity(ctx context.Context, userID, issuer, subject string) error
	GetUserBySessionToken(ctx context.Context, tokenHash string) (User, error)
	CreateSession(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteExpiredSessions(ctx context.Context) (int64, error)
	SetTOTPSecret(ctx context.Context, userID, secret string) error
	AdvanceTOTPStep(ctx context.Context, userID string, step int64) error
	GetUserByID(ctx context.Context, id string) (User, error)
	// SetUserRole and SetUserDisabledAt also delete the user's sessions when
	// revokeSessions is set, in the same transaction, and return how many
	// ended: the change and the sign-out commit together or not at all.
	SetUserRole(ctx context.Context, id string, role Role, revokeSessions bool) (int64, error)
	SetUserDisabledAt(ctx context.Context, id string, t *time.Time, revokeSessions bool) (int64, error)
	DeleteUser(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) (int64, error)
	CountActiveAdmins(ctx context.Context) (int64, error)
}

const (
	sessionTTL        = 7 * 24 * time.Hour
	minPasswordLength = 12
	bcryptCost        = 12
	totpIssuer        = "Vulngraph"
)

// dummyHash is compared against when the email is unknown, so login latency
// does not reveal which emails exist.
var dummyHash = mustHash("graph-dummy-password-for-timing")

// AuditRecorder writes the audit_events row of an admin action that has taken
// effect, and reports its own write failures (audit.Service).
type AuditRecorder interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

type Service struct {
	repo  Repo
	now   func() time.Time
	audit AuditRecorder // nil: no audit rows (tests)
	// requireAdminTOTP refuses password sign-in to an admin with no TOTP
	// enrolled (REQUIRE_ADMIN_TOTP).
	requireAdminTOTP bool
}

func NewService(repo Repo) *Service {
	return &Service{repo: repo, now: time.Now}
}

// WithAudit records sign-ins (and refused ones), sign-outs, user,
// session-revocation, TOTP and token changes, and API keys refused on
// session-only routes in audit_events.
func (s *Service) WithAudit(a AuditRecorder) *Service {
	s.audit = a
	return s
}

// WithRequireAdminTOTP makes TOTP mandatory for admins who sign in with a
// password: an admin with no TOTP enrolled is refused, and promoting a user
// to admin ends their sessions so they sign in again under that rule. SSO
// sign-ins are unaffected; their second factor is the IdP's.
func (s *Service) WithRequireAdminTOTP(required bool) *Service {
	s.requireAdminTOTP = required
	return s
}

func (s *Service) record(ctx context.Context, action, userID string, details map[string]any) {
	if s.audit != nil {
		s.audit.Record(ctx, action, AuditTargetUser, userID, details)
	}
}

// Login verifies credentials (and TOTP when enrolled) and returns a session
// token. The caller stores only its hash; the token itself goes to the client.
//
// Every failure is ErrInvalidCredentials. In particular an enrolled user who
// sent the right password but no code gets the same answer as a wrong
// password: answering "totp code required" confirmed the password to anyone
// guessing it. The client sends password and code together.
func (s *Service) Login(ctx context.Context, email, password, totpCode string) (string, User, error) {
	email = NormalizeEmail(email)
	creds, err := s.repo.GetUserCredentialsByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		// Equalize timing with a real bcrypt comparison before failing.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return s.loginFailed(ctx, email, "", LoginReasonUnknownEmail)
	}
	if err != nil {
		return "", User{}, fmt.Errorf("Login: %w", err)
	}

	if bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(password)) != nil {
		return s.loginFailed(ctx, email, creds.ID, LoginReasonWrongPassword)
	}
	// Same answer as a wrong password: a disabled account is not confirmed.
	if creds.DisabledAt != nil {
		return s.loginFailed(ctx, email, creds.ID, LoginReasonDisabled)
	}
	if s.requireAdminTOTP && creds.Role == RoleAdmin && creds.TOTPSecret == "" {
		log.FromContext(ctx).Warn().Str("user_id", creds.ID).
			Msg("SECURITY: REQUIRE_ADMIN_TOTP refused the password sign-in of an admin with no TOTP enrolled; enroll with `graph user totp`")
		return s.loginFailed(ctx, email, creds.ID, LoginReasonAdminTOTPRequired)
	}

	if creds.TOTPSecret != "" {
		step, ok := matchTOTPStep(totpCode, creds.TOTPSecret, s.now())
		if !ok {
			return s.loginFailed(ctx, email, creds.ID, LoginReasonWrongTOTP)
		}
		if err := s.repo.AdvanceTOTPStep(ctx, creds.ID, step); err != nil {
			if errors.Is(err, ErrTOTPReplayed) {
				return s.loginFailed(ctx, email, creds.ID, LoginReasonTOTPReplayed)
			}
			return "", User{}, fmt.Errorf("Login: %w", err)
		}
	}
	return s.startSession(ctx, creds.User, "Login", map[string]any{"method": "password", "totp": creds.TOTPSecret != ""})
}

// loginFailed logs a refused password sign-in at warn, writes its
// auth.login_failed row, and returns the one answer every failure gets.
func (s *Service) loginFailed(ctx context.Context, email, userID, reason string) (string, User, error) {
	s.RecordSignInFailure(ctx, "password", email, userID, reason)
	return "", User{}, ErrInvalidCredentials
}

// RecordSignInFailure logs a refused sign-in at warn and writes its
// auth.login_failed row: the method (password, google, okta, iap,
// oauth2_proxy), the email as typed or asserted, and the reason (a
// LoginReason* value). userID is the matched account, or "" when none
// matched or none was looked up. An email that is not shaped like one is not recorded, since a
// password typed into the email field would otherwise land in the trail.
func (s *Service) RecordSignInFailure(ctx context.Context, method, email, userID, reason string) {
	details := map[string]any{"method": method, "reason": reason}
	if validate.Email("email", email) == nil {
		details["email"] = email
	} else {
		details["email_malformed"] = true
	}
	ev := log.FromContext(ctx).Warn().Str("method", method).Str("reason", reason).Str("client_ip", ClientIPFromContext(ctx))
	if e, ok := details["email"].(string); ok {
		ev = ev.Str("email", e)
	}
	ev.Msg("sign-in refused")
	if s.audit != nil {
		s.audit.Record(ctx, AuditActionLoginFailed, AuditTargetUser, userID, details)
	}
}

// RecordAPIKeyRefused writes the auth.api_key_refused row of a session-only
// route that refused key (RequireSession).
func (s *Service) RecordAPIKeyRefused(ctx context.Context, key APIKeyRecord, route string) {
	if s.audit != nil {
		s.audit.Record(ctx, AuditActionAPIKeyRefused, AuditTargetAPIKey, key.ID, map[string]any{"route": route})
	}
}

// LoginOAuth finds or creates the user identified by email and returns a
// session token. Only the oauth2-proxy header path calls it, after the proxy's
// shared secret proved the header came from the proxy (see WithOAuth2Proxy);
// that path has no (issuer, subject) to bind.
//
// prov decides the role of a first sign-in (RolePolicy.Provision). The role of
// an existing user is never changed by a sign-in. With ErrUserDisabled the
// returned User is the matched account.
func (s *Service) LoginOAuth(ctx context.Context, email string, prov Provisioning) (string, User, error) {
	if !prov.Role.Valid() {
		return "", User{}, fmt.Errorf("LoginOAuth: invalid auto-create role %q", prov.Role)
	}
	creds, _, err := s.findOrCreateUser(ctx, NormalizeEmail(email), prov, map[string]any{"via": "oauth2_proxy"})
	if err != nil {
		return "", User{}, fmt.Errorf("LoginOAuth: %w", err)
	}
	if creds.DisabledAt != nil {
		return "", creds.User, ErrUserDisabled
	}
	return s.startSession(ctx, creds.User, "LoginOAuth", map[string]any{"method": "oauth2_proxy"})
}

// findOrCreateUser returns the user with email, provisioning it per prov with
// an unusable random password when it does not exist yet; created reports
// which happened. via names the sign-in path in the provisioning audit row.
func (s *Service) findOrCreateUser(ctx context.Context, email string, prov Provisioning, via map[string]any) (UserCredentials, bool, error) {
	creds, err := s.repo.GetUserCredentialsByEmail(ctx, email)
	if !errors.Is(err, ErrNotFound) {
		if err != nil {
			return UserCredentials{}, false, fmt.Errorf("findOrCreateUser: %w", err)
		}
		return creds, false, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newRandomPassword()), bcryptCost)
	if err != nil {
		return UserCredentials{}, false, fmt.Errorf("findOrCreateUser: hash: %w", err)
	}
	create := s.repo.CreateUser
	if prov.BootstrapAdmin {
		create = s.repo.CreateUserOrFirstAdmin
	}
	user, err := create(ctx, email, string(hash), prov.Role)
	if errors.Is(err, ErrEmailTaken) {
		// Race: a concurrent sign-in created it — re-fetch. It reports as created:
		// the account did not exist before this sign-in began, so it is not the
		// pre-existing-account binding LoginOIDC audits.
		creds, err = s.repo.GetUserCredentialsByEmail(ctx, email)
		if err != nil {
			return UserCredentials{}, false, fmt.Errorf("findOrCreateUser: recheck: %w", err)
		}
		return creds, true, nil
	}
	if err != nil {
		return UserCredentials{}, false, fmt.Errorf("findOrCreateUser: create: %w", err)
	}
	details := map[string]any{"email": user.Email, "role": string(user.Role)}
	for k, v := range via {
		details[k] = v
	}
	s.record(ContextWithUser(ctx, user), AuditActionUserProvision, user.ID, details)
	return UserCredentials{User: user}, true, nil
}

// LoginOIDC signs in the user an OIDC provider vouched for, binding the account
// to the provider's (issuer, subject) on its first OIDC sign-in.
//
// Matching on the email claim alone let anyone who could get an IdP to assert
// a victim's address take the account over. So:
//   - an account already bound to this (issuer, subject) signs in, whatever
//     email the IdP now reports;
//   - otherwise the email finds the account, which must not be bound to a
//     different identity (ErrIdentityMismatch — the caller denies and logs);
//     an unbound account is bound now;
//   - an unknown email is provisioned per prov (RolePolicy.Provision) and bound.
//
// With ErrUserDisabled or ErrIdentityMismatch the returned User is the account
// the sign-in matched, so the caller's auth.login_failed row can name it.
func (s *Service) LoginOIDC(ctx context.Context, id OIDCIdentity, prov Provisioning) (string, User, error) {
	if id.Issuer == "" || id.Subject == "" {
		return "", User{}, fmt.Errorf("LoginOIDC: issuer and subject are required")
	}
	creds, err := s.repo.GetUserCredentialsByOIDC(ctx, id.Issuer, id.Subject)
	switch {
	case err == nil:
		if creds.DisabledAt != nil {
			return "", creds.User, ErrUserDisabled
		}
		return s.startSession(ctx, creds.User, "LoginOIDC", oidcVia(id))
	case !errors.Is(err, ErrNotFound):
		return "", User{}, fmt.Errorf("LoginOIDC: %w", err)
	}

	if !prov.Role.Valid() {
		return "", User{}, fmt.Errorf("LoginOIDC: invalid auto-create role %q", prov.Role)
	}
	creds, created, err := s.findOrCreateUser(ctx, NormalizeEmail(id.Email), prov, map[string]any{"via": "oidc", "issuer": id.Issuer})
	if err != nil {
		return "", User{}, fmt.Errorf("LoginOIDC: %w", err)
	}
	if creds.OIDCSubject != "" {
		return "", creds.User, ErrIdentityMismatch
	}
	if creds.DisabledAt != nil {
		return "", creds.User, ErrUserDisabled
	}
	if err := s.repo.BindOIDCIdentity(ctx, creds.ID, id.Issuer, id.Subject); err != nil {
		if errors.Is(err, ErrIdentityMismatch) {
			return "", creds.User, ErrIdentityMismatch
		}
		return "", User{}, fmt.Errorf("LoginOIDC: %w", err)
	}
	if !created {
		// An existing account was matched by the email claim alone. That is the
		// step an IdP that lets users pick their address could abuse, so it is
		// audited by name.
		log.FromContext(ctx).Warn().Str("user_id", creds.ID).Str("email", creds.Email).Str("role", string(creds.Role)).
			Str("issuer", id.Issuer).Str("subject", id.Subject).
			Msg("SECURITY: existing account bound to an SSO identity by email on its first SSO sign-in")
	}
	return s.startSession(ctx, creds.User, "LoginOIDC", oidcVia(id))
}

func oidcVia(id OIDCIdentity) map[string]any {
	return map[string]any{"method": "oidc", "issuer": id.Issuer}
}

// IdentityBelongsTo reports whether id is the identity bound to userID. An
// identity bound to nobody is not userID's.
func (s *Service) IdentityBelongsTo(ctx context.Context, id OIDCIdentity, userID string) (bool, error) {
	creds, err := s.repo.GetUserCredentialsByOIDC(ctx, id.Issuer, id.Subject)
	switch {
	case errors.Is(err, ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("IdentityBelongsTo: %w", err)
	}
	return creds.ID == userID, nil
}

// startSession creates a session for user and writes its auth.login row;
// via names the sign-in path (method, and issuer for OIDC).
func (s *Service) startSession(ctx context.Context, user User, op string, via map[string]any) (string, User, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", User{}, fmt.Errorf("%s: %w", op, err)
	}
	if err := s.repo.CreateSession(ctx, hashToken(token), user.ID, s.now().Add(sessionTTL)); err != nil {
		return "", User{}, fmt.Errorf("%s: %w", op, err)
	}
	details := map[string]any{"email": user.Email}
	for k, v := range via {
		details[k] = v
	}
	s.record(ContextWithUser(ctx, user), AuditActionLogin, user.ID, details)
	return token, user, nil
}

// newRandomPassword generates a random password for OAuth-only users: 256
// bits from crypto/rand, which never returns an error.
func newRandomPassword() string {
	return rand.Text() + rand.Text()
}

// IssueToken mints a session token for a user by email without a password or
// TOTP challenge. It exists for trusted out-of-band tooling that already has
// direct database access — the `graph user token` CLI, which hands the token to
// automation such as bootstrap as a Bearer credential. It is deliberately not
// reachable over HTTP; the only callers run with the same trust as `user create`.
// The session is an ordinary one, so whoever holds it acts as the person (no
// MFA, none of the API-key limits); docs/security-hardening.md says so.
func (s *Service) IssueToken(ctx context.Context, email string) (string, error) {
	email = NormalizeEmail(email)
	creds, err := s.repo.GetUserCredentialsByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("IssueToken: %w", err)
	}
	if creds.DisabledAt != nil {
		return "", ErrUserDisabled
	}
	token, err := newSessionToken()
	if err != nil {
		return "", fmt.Errorf("IssueToken: %w", err)
	}
	expires := s.now().Add(sessionTTL)
	if err := s.repo.CreateSession(ctx, hashToken(token), creds.ID, expires); err != nil {
		return "", fmt.Errorf("IssueToken: %w", err)
	}
	s.record(ctx, AuditActionTokenIssue, creds.ID, map[string]any{
		"email": creds.Email, "role": string(creds.Role), "expires_at": expires.UTC().Format(time.RFC3339),
	})
	return token, nil
}

// Authenticate resolves a session token to its user.
func (s *Service) Authenticate(ctx context.Context, token string) (User, error) {
	user, err := s.repo.GetUserBySessionToken(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			return User{}, ErrUnauthenticated
		}
		return User{}, fmt.Errorf("Authenticate: %w", err)
	}
	return user, nil
}

// Logout ends the session token names and writes an auth.logout row for the
// user on ctx, with reason: "sign_out" when the user signed out, or why the
// session was ended for them.
func (s *Service) Logout(ctx context.Context, token, reason string) error {
	if err := s.repo.DeleteSession(ctx, hashToken(token)); err != nil {
		return fmt.Errorf("Logout: %w", err)
	}
	userID := ""
	if u, ok := UserFromContext(ctx); ok {
		userID = u.ID
	}
	s.record(ctx, AuditActionLogout, userID, map[string]any{"reason": reason})
	return nil
}

// PurgeExpiredSessions deletes every session row whose expires_at has passed
// and returns how many were removed.
//
// Expiry is already enforced at authentication time (GetUserBySessionToken
// filters on expires_at), so this is not a credential-reuse guard. It exists
// because nothing else deletes the rows: without it the sessions table grows
// without bound and stands as an inventory of long-dead credential hashes, one
// row per login, forever. Called from a serve-pod ticker (cmd/graph/serve.go).
func (s *Service) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	n, err := s.repo.DeleteExpiredSessions(ctx)
	if err != nil {
		return 0, fmt.Errorf("PurgeExpiredSessions: %w", err)
	}
	return n, nil
}

// CreateUser registers a user. Password policy is length-only: length is the
// one property that reliably matters, and composition rules push people to
// predictable substitutions.
func (s *Service) CreateUser(ctx context.Context, email, password string, role Role) (User, error) {
	email = NormalizeEmail(email)
	if err := validate.Email("email", email); err != nil {
		return User{}, err
	}
	if !role.Valid() {
		return User{}, fmt.Errorf("CreateUser: invalid role %q", role)
	}
	if len(password) < minPasswordLength {
		return User{}, fmt.Errorf("CreateUser: password must be at least %d characters", minPasswordLength)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return User{}, fmt.Errorf("CreateUser: %w", err)
	}
	user, err := s.repo.CreateUser(ctx, email, string(hash), role)
	if err != nil {
		if errors.Is(err, ErrEmailTaken) {
			return User{}, ErrEmailTaken
		}
		return User{}, fmt.Errorf("CreateUser: %w", err)
	}
	s.record(ctx, AuditActionUserCreate, user.ID, map[string]any{"email": user.Email, "role": string(user.Role)})
	return user, nil
}

// ListUsers returns all users (admin view). Credentials never leave the repo.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	users, err := s.repo.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListUsers: %w", err)
	}
	return users, nil
}

// EnrollTOTP generates and stores a TOTP secret for the user and returns the
// otpauth:// URL to load into an authenticator app.
func (s *Service) EnrollTOTP(ctx context.Context, email string) (string, error) {
	email = NormalizeEmail(email)
	creds, err := s.repo.GetUserCredentialsByEmail(ctx, email)
	if err != nil {
		return "", fmt.Errorf("EnrollTOTP: %w", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: totpIssuer, AccountName: email})
	if err != nil {
		return "", fmt.Errorf("EnrollTOTP: %w", err)
	}
	if err := s.repo.SetTOTPSecret(ctx, creds.ID, key.Secret()); err != nil {
		return "", fmt.Errorf("EnrollTOTP: %w", err)
	}
	s.record(ctx, AuditActionTOTPEnroll, creds.ID, map[string]any{"email": creds.Email, "replaced": creds.TOTPSecret != ""})
	return key.URL(), nil
}

// totpPeriod and totpSkew match what EnrollTOTP provisions (pquerna/otp
// defaults: 30 s steps, 6 digits, SHA-1) and the one step of clock skew
// totp.Validate allowed.
const (
	totpPeriod = 30
	totpSkew   = 1
)

// matchTOTPStep returns the time step whose code equals code, within ±skew of
// now. The step (not just a yes/no) is what replay protection records.
func matchTOTPStep(code, secret string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	current := now.Unix() / totpPeriod
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(step*totpPeriod, 0), totp.ValidateOpts{
			Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// NormalizeEmail is the one canonical form of an email address: trimmed and
// lowercased. Every write and lookup goes through it (and a CHECK constraint
// enforces it in Postgres), so "Alice@corp.example" from an IdP and a
// pre-provisioned "alice@corp.example" are the same account.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func newSessionToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("newSessionToken: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func mustHash(password string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		panic(err) // unreachable: bcrypt only errors on invalid cost
	}
	return hash
}
