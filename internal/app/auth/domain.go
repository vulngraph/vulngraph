// Package auth owns users, sessions, and role-based access control.
package auth

import (
	"errors"
	"strings"
	"time"
)

// Role is the access level of a user. Write endpoints are gated on it.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

// Valid reports whether r is one of the three known roles.
func (r Role) Valid() bool {
	return r == RoleAdmin || r == RoleAnalyst || r == RoleViewer
}

// Privilege returns a monotonic rank for r — higher means more access.
// Used to ensure a principal can never grant a credential more privileged
// than the principal itself (e.g. minting an admin API key as a viewer).
// An unknown role ranks 0 so it can never out-rank a known role.
func (r Role) Privilege() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleAnalyst:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

// User is the authenticated identity attached to requests.
type User struct {
	ID          string
	Email       string
	Role        Role
	TOTPEnabled bool
	CreatedAt   time.Time
	// AdminSince is when the role last became admin; zero when unknown (not an
	// admin, or an admin that predates the column). The executor's account-age
	// floor counts from the later of CreatedAt and AdminSince.
	AdminSince       time.Time
	AuthorityVersion int64
	// DisabledAt is set when an admin offboarded the user: no login, and their
	// sessions and API keys stop authenticating.
	DisabledAt *time.Time
}

// UserCredentials carries the secrets needed to verify a login attempt.
// It never leaves the service layer.
type UserCredentials struct {
	User
	PasswordHash string
	TOTPSecret   string // empty when TOTP is not enrolled
	// OIDCIssuer/OIDCSubject bind the account to one IdP identity after its
	// first OIDC sign-in; empty until then.
	OIDCIssuer  string
	OIDCSubject string
}

// OIDCIdentity is what an OIDC provider asserted about the signed-in user.
// Subject is the provider's stable account id; Email has already been checked
// as verified by the provider (see identityFromUserInfo).
type OIDCIdentity struct {
	Issuer  string
	Subject string
	Email   string
}

// RolePolicy decides the role an SSO identity is provisioned with on its FIRST
// sign-in (ADMIN_EMAILS, OIDC_ADMIN_GROUPS, OIDC_ANALYST_GROUPS). Existing
// users keep their role. The zero value provisions every identity as viewer
// (plus the empty-install bootstrap, see Provision).
type RolePolicy struct {
	AdminEmails   []string
	AdminGroups   []string
	AnalystGroups []string
	// RequiredGroups (OIDC_REQUIRED_GROUPS), when set, is a sign-in gate, not
	// a role: every SSO sign-in that starts a session, new or existing user,
	// must carry one of these groups (Admits).
	RequiredGroups []string
}

// Admits reports whether an SSO identity carrying groups may sign in. With no
// RequiredGroups everyone the domain allowlist admits may; with them, an
// identity carrying none of them (a provider that sends no groups included)
// may not.
func (p RolePolicy) Admits(groups []string) bool {
	return len(p.RequiredGroups) == 0 || intersectsFold(p.RequiredGroups, groups)
}

// WantsGroups reports whether sign-in reads the IdP's groups at all, so the
// Okta flow requests the groups scope.
func (p RolePolicy) WantsGroups() bool { return p.HasGroupMapping() || len(p.RequiredGroups) > 0 }

// Provisioning is the outcome of RolePolicy.Provision.
type Provisioning struct {
	Role Role
	// BootstrapAdmin asks the repository to provision admin instead of Role
	// when no user exists yet, decided atomically with the insert.
	BootstrapAdmin bool
}

// HasGroupMapping reports whether any IdP group maps to a role.
func (p RolePolicy) HasGroupMapping() bool {
	return len(p.AdminGroups) > 0 || len(p.AnalystGroups) > 0
}

// Provision returns the role for a first sign-in of email carrying groups.
// domainAllowlisted is true when the email passed a named domain allowlist
// rather than an *_ALLOW_ANY_DOMAIN opt-out.
//
// An allowlisted domain must not provision admin, or every colleague's first
// sign-in would hold the cloud-mutating role. Admin has to be named: an email in
// AdminEmails or a group in AdminGroups. The one exception is an empty install
// with no role mapping configured at all (no AdminEmails, no groups), where
// the first allowlisted sign-in becomes admin so the platform is
// administrable at all. With a mapping configured the operator has said who
// administers, and a non-member must not win by signing in first. An
// allow-any identity never qualifies: it may be a stranger racing the operator.
func (p RolePolicy) Provision(email string, groups []string, domainAllowlisted bool) Provisioning {
	switch {
	case containsFold(p.AdminEmails, email), intersectsFold(p.AdminGroups, groups):
		return Provisioning{Role: RoleAdmin}
	case intersectsFold(p.AnalystGroups, groups):
		return Provisioning{Role: RoleAnalyst}
	}
	return Provisioning{Role: RoleViewer, BootstrapAdmin: domainAllowlisted && len(p.AdminEmails) == 0 && !p.HasGroupMapping()}
}

func containsFold(list []string, v string) bool {
	v = strings.TrimSpace(v)
	for _, s := range list {
		if v != "" && strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

func intersectsFold(list, values []string) bool {
	for _, v := range values {
		if containsFold(list, v) {
			return true
		}
	}
	return false
}

// Audit actions the auth service writes to audit_events, target_type
// AuditTargetUser and target_id the user id. Details never carry a password,
// hash, TOTP seed or session token.
const (
	AuditActionUserCreate     = "auth.user_create"
	AuditActionUserProvision  = "auth.user_provision"   // first SSO sign-in; the actor is the new user
	AuditActionUserRoleChange = "auth.user_role_change" // details: before, after
	AuditActionUserDisable    = "auth.user_disable"
	AuditActionUserEnable     = "auth.user_enable"
	AuditActionUserDelete     = "auth.user_delete"
	AuditActionSessionsRevoke = "auth.sessions_revoke"
	AuditActionTOTPEnroll     = "auth.totp_enroll" // details: replaced, true when an enrolled seed was reset
	AuditActionTokenIssue     = "auth.token_issue" // graph user token
	// AuditActionLogin: a session started (details: method, email; issuer for
	// an OIDC sign-in). The actor is the signed-in user.
	AuditActionLogin = "auth.login"
	// AuditActionLoginFailed: a refused sign-in (details: method, email as
	// typed or asserted, reason). target_id is the account the sign-in
	// matched, else empty: an SSO refusal names one only for disabled and
	// identity_mismatch, since its earlier gates refuse before any account
	// is looked up. The actor is unknown.
	AuditActionLoginFailed = "auth.login_failed"
	// AuditActionLogout: a session ended (details: reason).
	AuditActionLogout = "auth.logout"
	// AuditActionAPIKeyRefused: a session-only route refused an API key
	// (RequireSession); target_type AuditTargetAPIKey, details: route.
	AuditActionAPIKeyRefused = "auth.api_key_refused"
	AuditTargetUser          = "user"
	AuditTargetAPIKey        = "api_key"
)

// Sign-in failure reasons recorded on auth.login_failed rows. The client
// always sees one answer per path; the reason is for the audit trail only.
const (
	LoginReasonUnknownEmail      = "unknown_email"
	LoginReasonWrongPassword     = "wrong_password"
	LoginReasonDisabled          = "disabled"
	LoginReasonAdminTOTPRequired = "admin_totp_required"
	LoginReasonWrongTOTP         = "wrong_or_missing_totp"
	LoginReasonTOTPReplayed      = "totp_replayed"
	LoginReasonEmailUnverified   = "email_unverified"
	LoginReasonDomainNotAllowed  = "domain_not_allowed"
	LoginReasonHostedDomain      = "hosted_domain_not_allowed"
	LoginReasonGroupRequired     = "required_group_missing"
	LoginReasonIdentityMismatch  = "identity_mismatch"
)

var (
	// ErrInvalidCredentials is the ONE answer to every failed login factor —
	// unknown email, wrong password, disabled account, missing, wrong or
	// replayed TOTP code — so a response never confirms that a password was right.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrTOTPReplayed       = errors.New("auth: totp code already used")
	ErrEmailTaken         = errors.New("auth: email already registered")
	ErrUnauthenticated    = errors.New("auth: not authenticated")
	ErrNotFound           = errors.New("auth: user not found")
	ErrUserDisabled       = errors.New("auth: user is disabled")
	ErrEmailNotVerified   = errors.New("auth: identity provider has not verified the email")
	ErrIdentityMismatch   = errors.New("auth: account is bound to a different identity")
	ErrInvalidRole        = errors.New("auth: invalid role")
	// ErrRedirectURLRequired: an OAuth provider is configured without an
	// explicit redirect URL and without the dev-only host derivation opt-in.
	ErrRedirectURLRequired = errors.New("auth: OAuth redirect URL required")
	ErrSelfAction          = errors.New("auth: admins cannot disable, delete, re-role or revoke themselves")
	ErrLastAdmin           = errors.New("auth: would leave no active admin")
)
