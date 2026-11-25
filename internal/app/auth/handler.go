package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// SessionCookie is the HttpOnly cookie carrying the session token.
const SessionCookie = "graph_session"

type ctxUserKey struct{}

type ctxAPIKeyKey struct{}

type ctxBypassKey struct{}

// UserFromContext returns the authenticated user attached by RequireAuth.
func UserFromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(ctxUserKey{}).(User)
	return u, ok
}

// ContextWithUser attaches an authenticated user to the context. RequireAuth uses
// it after resolving the session; it is also the seam tests use to exercise
// handlers that read the user (e.g. the MCP write-tool admin check).
func ContextWithUser(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, ctxUserKey{}, u)
}

// BypassFromContext reports whether the request's user is the synthetic admin
// BYPASS_AUTH injects. That user stands for whoever reached serve, so it
// identifies nobody: every such request carries the same id and email.
func BypassFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(ctxBypassKey{}).(bool)
	return v
}

// APIKeyFromContext returns the API key the request authenticated with, when
// it did (RequireAuth's Bearer gph_* path).
func APIKeyFromContext(ctx context.Context) (APIKeyRecord, bool) {
	k, ok := ctx.Value(ctxAPIKeyKey{}).(APIKeyRecord)
	return k, ok
}

// ContextWithAPIKey records the API key a request authenticated with.
// RequireAuth uses it; tests use it to exercise key-aware handlers.
func ContextWithAPIKey(ctx context.Context, k APIKeyRecord) context.Context {
	return context.WithValue(ctx, ctxAPIKeyKey{}, k)
}

// GoogleOAuthConfig holds credentials for Google OIDC sign-in.
type GoogleOAuthConfig struct {
	ClientID       string
	ClientSecret   string
	RedirectURL    string   // GOOGLE_REDIRECT_URL; required unless RedirectFromHost
	AllowedDomains []string // only these email domains may sign in; empty denies unless AllowAnyDomain
	AllowAnyDomain bool     // explicit opt-out (GOOGLE_ALLOW_ANY_DOMAIN); new users become viewers
	// RedirectFromHost (dev only, OAUTH_REDIRECT_FROM_HOST) builds an unset
	// RedirectURL from the request's Host and X-Forwarded-Proto, both of which
	// a client controls when nothing in front overwrites them.
	RedirectFromHost bool
}

// Validate reports a config that would build its redirect URL from the request.
func (c GoogleOAuthConfig) Validate() error {
	return validateRedirectURL("GOOGLE_REDIRECT_URL", c.RedirectURL, c.RedirectFromHost)
}

// apiKeyVerifier is the narrow interface RequireAuth needs from the API key
// package. Defined here to keep auth independent of the apikey package.
type apiKeyVerifier interface {
	// Verify authenticates a raw gph_* key and returns the matching key record.
	Verify(ctx context.Context, plaintext string) (APIKeyRecord, error)
}

// APIKeyRecord carries the fields RequireAuth needs from an API key. It mirrors
// apikey.APIKey without importing that package (circular import prevention).
type APIKeyRecord struct {
	ID     string
	UserID string
	Name   string
	Scope  string // "read" | "write" | "admin" | "inventory"
	// OwnerEmail/OwnerRole are the owning user's current email and role;
	// OwnerCreatedAt is when the owner's account was created and
	// OwnerAdminSince when their role last became admin (zero = unknown).
	OwnerEmail      string
	OwnerRole       Role
	OwnerCreatedAt  time.Time
	OwnerAdminSince time.Time
	// ExpiresAt is when the key stops authenticating (its effective expiry).
	ExpiresAt time.Time
}

type Handler struct {
	svc       *Service
	bypass    bool               // when true, RequireAuth injects a synthetic admin
	googleCfg *GoogleOAuthConfig // nil = Google OAuth disabled
	oktaCfg   *OktaOAuthConfig   // nil = Okta OAuth disabled
	iap       *iapValidator      // nil = IAP not configured
	// iapDomains / iapAnyDomain gate which IAP identities may sign in and the
	// role a first sign-in provisions, exactly as for Google/Okta.
	iapDomains   []string
	iapAnyDomain bool
	// passwordBreakGlass keeps password login available behind IAP or
	// oauth2-proxy; see WithPasswordBreakGlass.
	passwordBreakGlass bool
	// oauth2-proxy header path; see WithOAuth2Proxy.
	oauth2Proxy            bool
	oauth2ProxySecret      [sha256.Size]byte // digest of OAUTH2_PROXY_SHARED_SECRET
	oauth2ProxySecretSet   bool
	oauth2ProxyDomains     []string
	oauth2ProxyIDToken     *idTokenVerifier // nil = no ID-token verification
	oauth2ProxyTrustGroups bool
	oauth2ProxyAnyDomain   bool
	// roles decides a first SSO sign-in's role; see WithRolePolicy.
	roles   RolePolicy
	apikeys apiKeyVerifier // nil = API key auth disabled
	// insecureCookies drops the Secure attribute; see CookieInsecureEnv.
	insecureCookies bool
	// Login brute-force limits; see WithLoginRateLimit.
	loginPerIP      *KeyedLimiter
	loginPerAccount *KeyedLimiter
	// clientIPHeader is honoured only from trustedProxies; see WithClientIPHeader.
	clientIPHeader string
	trustedProxies []netip.Prefix
}

// CookieInsecureEnv, set to exactly "true", drops the Secure attribute from
// every cookie so plain-http local development works (Safari refuses Secure
// cookies over http://localhost). Never set it on a deployment: a session
// cookie without Secure is sent over any plain-http request to the host.
const CookieInsecureEnv = "COOKIE_INSECURE"

func cookieInsecureFromEnv() bool { return os.Getenv(CookieInsecureEnv) == "true" }

func NewHandler(svc *Service) *Handler {
	return &Handler{
		svc:             svc,
		insecureCookies: cookieInsecureFromEnv(),
		loginPerIP:      NewKeyedLimiter(DefaultLoginPerIPPerMinute, DefaultLoginPerIPPerMinute),
		loginPerAccount: NewKeyedLimiter(DefaultLoginPerAccountPerMinute, DefaultLoginPerAccountPerMinute),
	}
}

// WithAPIKeys enables API key authentication on this handler. External agents
// (A2A clients) authenticate with `Authorization: Bearer gph_<key>` where the
// key is created in Settings → API Keys. The key's scope maps to the auth role:
// read → viewer, write → analyst, admin → admin.
func (h *Handler) WithAPIKeys(v apiKeyVerifier) *Handler {
	h.apikeys = v
	return h
}

// ScopeInventory is the API key scope that may only submit package inventory.
// It reads as viewer everywhere else; RequireAuth additionally refuses it on
// every route outside inventoryKeyRoutes.
const ScopeInventory = "inventory"

// inventoryKeyRoutes are the only routes an inventory-scoped key may reach, as
// the mux reports them in r.Pattern. The role such a key maps to (viewer) would
// otherwise let it read everything a viewer can.
var inventoryKeyRoutes = map[string]bool{
	"PUT /api/assets/{id}/package-inventory": true,
	"PUT /api/package-inventory":             true,
	"POST /api/mcp":                          true,
}

// APIKeyScopeToRole converts an API key scope string to the corresponding Role.
// This is the single source of truth for what a scope grants: both the Bearer
// auth path and the key-issuance privilege check must agree, or a key could be
// minted with more access than the issuance check believes it grants.
func APIKeyScopeToRole(scope string) Role {
	switch scope {
	case "admin":
		return RoleAdmin
	case "write":
		return RoleAnalyst
	case ScopeInventory:
		return RoleViewer
	default:
		return RoleViewer
	}
}

// lesserRole returns whichever of a and b grants less access.
func lesserRole(a, b Role) Role {
	if b.Privilege() < a.Privilege() {
		return b
	}
	return a
}

// WithGoogleOAuth enables Google OIDC sign-in on the handler.
func (h *Handler) WithGoogleOAuth(cfg *GoogleOAuthConfig) *Handler {
	h.googleCfg = cfg
	return h
}

// WithPasswordBreakGlass keeps email+password login enabled even when IAP or
// oauth2-proxy fronts the app (PASSWORD_LOGIN_BREAK_GLASS=true). Without it,
// password login is off in those modes: the proxy is the authentication, and
// a password form behind it is a second, weaker door that bypasses the
// proxy's MFA and policy for anyone who can reach the pod.
func (h *Handler) WithPasswordBreakGlass(enabled bool) *Handler {
	h.passwordBreakGlass = enabled
	return h
}

// passwordLoginEnabled reports whether POST /api/auth/login accepts passwords.
func (h *Handler) passwordLoginEnabled() bool {
	return (h.iap == nil && !h.oauth2Proxy) || h.passwordBreakGlass
}

// NewHandlerBypass returns a Handler that skips session checks entirely,
// injecting a synthetic admin user on every request. Use when the app is
// behind a network-level zero-trust proxy (e.g. ZTNA) and app-level auth
// is redundant.
func NewHandlerBypass() *Handler {
	return &Handler{bypass: true, insecureCookies: cookieInsecureFromEnv()}
}

// bypassUser is the synthetic admin injected when BYPASS_AUTH is set.
var bypassUser = User{
	ID:    "00000000-0000-0000-0000-000000000000",
	Email: "admin@internal",
	Role:  RoleAdmin,
}

type userResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// rejectWhenBypassed answers requests that need the user store when the handler
// was built with NewHandlerBypass, which has no Service: without this guard they
// dereference a nil service and surface as a recovered panic (500).
func (h *Handler) rejectWhenBypassed(w http.ResponseWriter) bool {
	if !h.bypass {
		return false
	}
	errs.WriteHTTPError(w, errs.NotFound("authentication is disabled (BYPASS_AUTH)"))
	return true
}

// Logout deletes the session and clears the cookie. With BYPASS_AUTH there is
// no session to delete, so it only clears the cookie.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if h.bypass {
		http.SetCookie(w, h.sessionCookie("", -time.Hour))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	cookie, err := r.Cookie(SessionCookie)
	if err == nil {
		if err := h.svc.Logout(r.Context(), cookie.Value, "sign_out"); err != nil {
			log.FromContext(r.Context()).Error().Err(err).Msg("logout failed")
			errs.WriteHTTPError(w, errs.Internal("logout failed"))
			return
		}
	}
	http.SetCookie(w, h.sessionCookie("", -time.Hour))
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the authenticated user.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := UserFromContext(r.Context())
	if !ok {
		errs.WriteHTTPErrorCtx(r.Context(), w, "not authenticated", http.StatusUnauthorized)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toUserResponse(user))
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// CreateUser registers a new user. Admin-only (enforced by RequireRole) and
// session-only (rejectAPIKey).
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if h.rejectWhenBypassed(w) || rejectAPIKey(w, r) {
		return
	}
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON"))
		return
	}

	user, err := h.svc.CreateUser(r.Context(), req.Email, req.Password, Role(req.Role))
	switch {
	case errors.Is(err, ErrEmailTaken):
		errs.WriteHTTPError(w, errs.Conflict("email already registered"))
		return
	case err != nil:
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	}
	writeJSON(r.Context(), w, http.StatusCreated, toUserResponse(user))
}

type userListItem struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	TOTPEnabled bool       `json:"totp_enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	Disabled    bool       `json:"disabled"`
	DisabledAt  *time.Time `json:"disabled_at"`
}

func toUserListItem(u User) userListItem {
	return userListItem{
		ID: u.ID, Email: u.Email, Role: string(u.Role), TOTPEnabled: u.TOTPEnabled,
		CreatedAt: u.CreatedAt, Disabled: u.DisabledAt != nil, DisabledAt: u.DisabledAt,
	}
}

// ListUsers returns all users (admin). Route: GET /api/users.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if h.rejectWhenBypassed(w) {
		return
	}
	users, err := h.svc.ListUsers(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list users failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list users"))
		return
	}
	out := make([]userListItem, len(users))
	for i, u := range users {
		out[i] = toUserListItem(u)
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"items": out})
}

// RequireAuth resolves the caller's session and attaches the user to the
// context. The token comes from the session cookie (browser UI) or, failing
// that, an `Authorization: Bearer <token>` header — both carry the same session
// token, so automation clients such as bootstrap authenticate without a cookie
// jar.
//
// When the handler was constructed with NewHandlerBypass (BYPASS_AUTH=true),
// the check is skipped entirely and the synthetic admin is injected.
func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	if h.bypass {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := ContextWithClientIP(r.Context(), h.clientAddr(r))
			ctx = context.WithValue(ctx, ctxBypassKey{}, true)
			next(w, r.WithContext(ContextWithUser(ctx, bypassUser)))
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(ContextWithClientIP(r.Context(), h.clientAddr(r)))
		if h.isOAuth2ProxyRequest(r) {
			if h.oauth2ProxySignIn(w, r, next) {
				return
			}
		}
		if h.iap != nil && r.Header.Get(iapAssertionHeader) != "" {
			if h.iapSignIn(w, r, next) {
				return
			}
		}

		token, ok := sessionToken(r)
		if !ok {
			errs.WriteHTTPErrorCtx(r.Context(), w, "not authenticated", http.StatusUnauthorized)
			return
		}

		// API key path — gph_* Bearer tokens authenticate external agents (A2A).
		// The key is created in Settings → API Keys; its scope maps to the role.
		if h.apikeys != nil && strings.HasPrefix(token, "gph_") {
			key, err := h.apikeys.Verify(r.Context(), token)
			if err != nil {
				errs.WriteHTTPErrorCtx(r.Context(), w, "invalid api key", http.StatusUnauthorized)
				return
			}
			if key.Scope == ScopeInventory && !inventoryKeyRoutes[r.Pattern] {
				log.FromContext(r.Context()).Warn().Str("api_key_id", key.ID).Str("route", r.Pattern).
					Msg("SECURITY: inventory-scoped API key refused outside the package-inventory routes")
				errs.WriteHTTPError(w, errs.Forbidden("an inventory API key may only submit package inventory"))
				return
			}
			// The principal is the owning user — id and email — so audit rows
			// name a person, never the key's user-chosen name. The role is the
			// key's scope capped at the owner's CURRENT role: demoting a user
			// demotes their keys.
			user := User{
				ID:         key.UserID,
				Email:      key.OwnerEmail,
				Role:       lesserRole(APIKeyScopeToRole(key.Scope), key.OwnerRole),
				CreatedAt:  key.OwnerCreatedAt,
				AdminSince: key.OwnerAdminSince,
			}
			ctx := ContextWithAPIKey(ContextWithUser(r.Context(), user), key)
			next(w, r.WithContext(ctx))
			return
		}

		user, err := h.svc.Authenticate(r.Context(), token)
		if err != nil {
			if errors.Is(err, ErrUnauthenticated) {
				errs.WriteHTTPErrorCtx(r.Context(), w, "not authenticated", http.StatusUnauthorized)
				return
			}
			log.FromContext(r.Context()).Error().Err(err).Msg("authenticate failed")
			errs.WriteHTTPError(w, errs.Internal("authentication failed"))
			return
		}
		next(w, r.WithContext(ContextWithUser(r.Context(), user)))
	}
}

// RequireRole gates a handler on the user's role. Admins pass every gate.
func RequireRole(role Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			errs.WriteHTTPErrorCtx(r.Context(), w, "not authenticated", http.StatusUnauthorized)
			return
		}
		if user.Role != role && user.Role != RoleAdmin {
			errs.WriteHTTPError(w, errs.Forbidden("insufficient role"))
			return
		}
		next(w, r)
	}
}

// sessionToken extracts the session token from the request: the session cookie
// takes precedence, falling back to a Bearer Authorization header.
func sessionToken(r *http.Request) (string, bool) {
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		return c.Value, true
	}
	const prefix = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, prefix) {
		if v := strings.TrimSpace(h[len(prefix):]); v != "" {
			return v, true
		}
	}
	return "", false
}

func (h *Handler) sessionCookie(token string, ttl time.Duration) *http.Cookie {
	return h.cookie(SessionCookie, token, int(ttl.Seconds()))
}

// cookie builds every cookie the handler sets. Secure is on unless the
// operator explicitly set CookieInsecureEnv; it is never derived from the
// request, because X-Forwarded-Proto is client-controlled whenever no proxy
// overwrites it and must not be able to downgrade a cookie.
func (h *Handler) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !h.insecureCookies,
		SameSite: http.SameSiteLaxMode,
	}
}

func toUserResponse(u User) userResponse {
	return userResponse{ID: u.ID, Email: u.Email, Role: string(u.Role)}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}

// ── Google OAuth2 / OIDC ─────────────────────────────────────────────────────

const oauthStateCookie = "graph_oauth_state"

// Providers lists available authentication methods so the frontend can
// render the right login UI. No auth required.
func (h *Handler) Providers(w http.ResponseWriter, r *http.Request) {
	type item struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	// When oauth2-proxy or IAP is active, the proxy handles authentication
	// before the request reaches the app — password login is irrelevant.
	// Omitting it makes the frontend skip the form and go straight to Google.
	var items []item
	if h.passwordLoginEnabled() {
		items = append(items, item{ID: "password", Name: "Email + password"})
	}
	if h.googleCfg != nil {
		items = append(items, item{ID: "google", Name: "Sign in with Google"})
	}
	if h.oktaCfg != nil {
		items = append(items, item{ID: "okta", Name: "Sign in with Okta"})
	}
	writeJSON(r.Context(), w, http.StatusOK, items)
}

// GoogleOAuthRedirect starts the OAuth2 flow by redirecting to Google's
// consent screen.
func (h *Handler) GoogleOAuthRedirect(w http.ResponseWriter, r *http.Request) {
	if h.rejectWhenBypassed(w) {
		return
	}
	if h.googleCfg == nil {
		errs.WriteHTTPError(w, errs.InvalidInput("Google OAuth not configured"))
		return
	}
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		errs.WriteHTTPError(w, errs.Internal("could not generate state"))
		return
	}
	cfg := h.oauthConfig(r)
	if cfg.RedirectURL == "" {
		errs.WriteHTTPError(w, errs.Internal("Google OAuth redirect URL not configured"))
		return
	}
	state := hex.EncodeToString(stateBytes)
	http.SetCookie(w, h.cookie(oauthStateCookie, state, 600))
	http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

// GoogleOAuthCallback handles the redirect from Google: exchanges the code
// for a token, fetches the user's email, and issues a session.
func (h *Handler) GoogleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if h.rejectWhenBypassed(w) {
		return
	}
	if h.googleCfg == nil {
		errs.WriteHTTPError(w, errs.InvalidInput("Google OAuth not configured"))
		return
	}
	if !validOAuthState(r) {
		errs.WriteHTTPErrorCtx(r.Context(), w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, h.cookie(oauthStateCookie, "", -1))

	token, err := h.oauthConfig(r).Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("google oauth exchange failed")
		errs.WriteHTTPError(w, errs.Internal("OAuth exchange failed"))
		return
	}
	info, err := fetchUserInfo(r.Context(), googleUserInfoURL, token.AccessToken)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("google userinfo failed")
		errs.WriteHTTPError(w, errs.Internal("could not fetch user info from Google"))
		return
	}
	h.completeOIDCSignIn(w, r, oidcSignIn{
		provider: "google", issuer: googleIssuer, allowed: h.googleCfg.AllowedDomains, allowAny: h.googleCfg.AllowAnyDomain,
		checkHostedDomain: true,
	}, info)
}

func (h *Handler) oauthConfig(r *http.Request) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.googleCfg.ClientID,
		ClientSecret: h.googleCfg.ClientSecret,
		RedirectURL:  oauthRedirectURL(r, h.googleCfg.RedirectURL, h.googleCfg.RedirectFromHost, "/api/auth/google/callback"),
		Scopes:       []string{"openid", "email"},
		Endpoint:     google.Endpoint,
	}
}

func emailDomain(email string) string {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return ""
	}
	return email[at+1:]
}
