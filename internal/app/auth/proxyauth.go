package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	oauth2ProxyEmailHeader  = "X-Auth-Request-Email"
	oauth2ProxyGroupsHeader = "X-Auth-Request-Groups"
	// OAuth2ProxySecretHeader carries OAUTH2_PROXY_SHARED_SECRET. It is defence
	// in depth, not proof of identity: however it is injected, anyone who can
	// read it (e.g. from a publicly routed oauth2-proxy /oauth2/auth that adds
	// it to its response) can replay it with any email. See WithOAuth2Proxy.
	OAuth2ProxySecretHeader = "X-Graph-Proxy-Secret"
	iapAssertionHeader      = "X-Goog-IAP-JWT-Assertion"
)

// OAuth2ProxyConfig configures the oauth2-proxy sign-in path.
type OAuth2ProxyConfig struct {
	// OIDCIssuer / OIDCAudience enable ID-token verification: oauth2-proxy
	// forwards the user's IdP-signed ID token (--set-authorization-header →
	// Authorization: Bearer), verified against the issuer's published keys.
	// When set, identity and groups come ONLY from the verified token.
	OIDCIssuer   string
	OIDCAudience string
	// OIDCAllowUnverifiedEmail accepts a token with NO email_verified claim
	// (some IdPs never send it). Risky: the first token sign-in binds an
	// existing account by email, so the IdP must not let users choose one.
	OIDCAllowUnverifiedEmail bool
	// SharedSecret, when set, must arrive in OAuth2ProxySecretHeader.
	SharedSecret string
	// TrustGroupsHeader accepts X-Auth-Request-Groups in shared-secret-only
	// mode. ingress-nginx only overwrites headers listed in
	// auth-response-headers, so an unlisted groups header is client-supplied.
	TrustGroupsHeader bool
	AllowedDomains    []string
	AllowAnyDomain    bool
}

// WithOAuth2Proxy enables sign-in through an oauth2-proxy in front of the
// ingress (nginx auth-url).
//
// The X-Auth-Request-Email header alone proves nothing: anything that reaches
// the pod sets it, and signing in an existing admin by email made that a
// one-header admin takeover. Two checks exist, strongest first:
//
//   - ID token (OIDCIssuer): only the IdP can sign the token, so a caller can
//     at most present its own identity. This holds even if the pod is
//     reachable around the proxy.
//   - Shared secret: proves the request passed something holding the secret.
//     It is a single bearer credential for every identity, so it only helps
//     while network policy keeps other workloads off the pod and the secret is
//     not readable by users; it is defence in depth, not the control.
//
// Configured with neither, every proxy request is refused (serve will not
// start that way). AllowedDomains / AllowAnyDomain gate emails as for the OIDC
// providers (domainGate); a first sign-in's role comes from the RolePolicy.
func (h *Handler) WithOAuth2Proxy(cfg OAuth2ProxyConfig) *Handler {
	h.oauth2Proxy = true
	h.oauth2ProxySecretSet = cfg.SharedSecret != ""
	h.oauth2ProxySecret = sha256.Sum256([]byte(cfg.SharedSecret))
	h.oauth2ProxyIDToken = nil
	if cfg.OIDCIssuer != "" {
		h.oauth2ProxyIDToken = newIDTokenVerifier(cfg.OIDCIssuer, cfg.OIDCAudience, cfg.OIDCAllowUnverifiedEmail)
	}
	h.oauth2ProxyTrustGroups = cfg.TrustGroupsHeader
	h.oauth2ProxyDomains = cfg.AllowedDomains
	h.oauth2ProxyAnyDomain = cfg.AllowAnyDomain
	return h
}

// WithIAP enables GCP Identity-Aware Proxy JWT validation. When configured,
// RequireAuth also accepts X-Goog-IAP-JWT-Assertion headers as proof of
// identity — the app auto-creates a session, so users authenticated by IAP
// never see the login page.
//
// audience is the IAP JWT audience for this service:
//
//	App Engine: /projects/{project_number}/apps/{project_id}
//	Cloud Run / GKE LB: /projects/{project_number}/global/backendServices/{service_id}
//
// allowedDomains/allowAnyDomain gate identities exactly as for Google and Okta:
// IAP admits whoever the IAP policy admits, which is not necessarily the
// organisation that should run this platform.
func (h *Handler) WithIAP(audience string, allowedDomains []string, allowAnyDomain bool) *Handler {
	h.iap = newIAPValidator(audience)
	h.iapDomains = allowedDomains
	h.iapAnyDomain = allowAnyDomain
	return h
}

// WithRolePolicy sets how a first SSO sign-in (Google, Okta, IAP,
// oauth2-proxy) is provisioned; see RolePolicy.Provision.
func (h *Handler) WithRolePolicy(p RolePolicy) *Handler {
	h.roles = p
	return h
}

// oauth2ProxySecretValid compares digests so the comparison is constant-time
// whatever the presented header's length.
func (h *Handler) oauth2ProxySecretValid(r *http.Request) bool {
	got := sha256.Sum256([]byte(r.Header.Get(OAuth2ProxySecretHeader)))
	return h.oauth2ProxySecretSet && subtle.ConstantTimeCompare(got[:], h.oauth2ProxySecret[:]) == 1
}

// isOAuth2ProxyRequest reports whether r carries anything the oauth2-proxy
// path must judge: the email header, or (in ID-token mode) a JWT bearer.
func (h *Handler) isOAuth2ProxyRequest(r *http.Request) bool {
	if !h.oauth2Proxy {
		return false
	}
	return r.Header.Get(oauth2ProxyEmailHeader) != "" || (h.oauth2ProxyIDToken != nil && bearerJWT(r) != "")
}

// oauth2ProxySignIn reports whether it wrote the response or called next;
// false lets RequireAuth fall through to the session check.
//
// A proxy request that fails verification is refused outright rather than
// ignored: in a proxied deployment the proxy sends what is required, so a
// failure means a request that reached the pod around it.
func (h *Handler) oauth2ProxySignIn(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) bool {
	ctx := r.Context()
	refuse := func(reason string, err error) bool {
		log.FromContext(ctx).Warn().Err(err).Str("email_header", r.Header.Get(oauth2ProxyEmailHeader)).
			Msg("SECURITY: oauth2-proxy sign-in refused: " + reason)
		errs.WriteHTTPErrorCtx(ctx, w, "identity was not proven by the authenticating proxy", http.StatusUnauthorized)
		return true
	}
	if h.oauth2ProxySecretSet && !h.oauth2ProxySecretValid(r) {
		return refuse("missing or wrong "+OAuth2ProxySecretHeader, nil)
	}
	if !h.oauth2ProxyIDToken.configured() && !h.oauth2ProxySecretSet {
		return refuse("neither ID-token verification nor a shared secret is configured", nil)
	}
	var id OIDCIdentity
	var groups []string
	if h.oauth2ProxyIDToken.configured() {
		session, hasSession := h.cookieSession(r)
		raw := bearerJWT(r)
		var err error
		if raw != "" {
			id, groups, err = h.oauth2ProxyIDToken.Verify(ctx, raw)
		}
		switch {
		case hasSession && (raw == "" || err != nil):
			// The token is only needed to start a session, and may have
			// expired while the session has not.
			return false
		case raw == "":
			return refuse("no ID token forwarded (oauth2-proxy --set-authorization-header)", nil)
		case err != nil:
			return refuse("ID token did not verify", err)
		case hasSession:
			same, err := h.svc.IdentityBelongsTo(ctx, id, session.user.ID)
			if err != nil {
				// Unknown is not "a different person": ending the session on a
				// store blip would sign every user out.
				log.FromContext(ctx).Error().Err(err).Msg("oauth2-proxy: comparing the ID token with the session failed")
				errs.WriteHTTPError(w, errs.Internal("could not verify the session identity"))
				return true
			}
			if same {
				return false
			}
			// A different person signed in to the proxy from this browser (or
			// the session predates the binding): end the old session rather
			// than keep serving its user under the new person's proxy login.
			log.FromContext(ctx).Info().Str("session_user", session.user.Email).Str("token_email", id.Email).
				Msg("oauth2-proxy: ID token is not the session's identity; replacing the session")
			if err := h.svc.Logout(ContextWithUser(ctx, session.user), session.token, "proxy_identity_changed"); err != nil {
				log.FromContext(ctx).Error().Err(err).Msg("oauth2-proxy: ending the replaced session failed")
				errs.WriteHTTPError(w, errs.Internal("could not end the previous session"))
				return true
			}
		}
	} else {
		// Shared-secret mode has no identity to compare: a session wins.
		if hasSessionCookie(r) {
			return false
		}
		id.Email = NormalizeEmail(r.Header.Get(oauth2ProxyEmailHeader))
		if h.oauth2ProxyTrustGroups {
			groups = splitGroups(r.Header.Get(oauth2ProxyGroupsHeader))
		}
	}

	ok, allowlisted := domainGate(id.Email, h.oauth2ProxyDomains, h.oauth2ProxyAnyDomain)
	if !ok {
		h.svc.RecordSignInFailure(ctx, "oauth2_proxy", id.Email, "", LoginReasonDomainNotAllowed)
		return false
	}
	// Groups are unknown in shared-secret mode without OAUTH2_PROXY_TRUST_GROUPS,
	// so a required group refuses every sign-in there.
	if !h.roles.Admits(groups) {
		h.svc.RecordSignInFailure(ctx, "oauth2_proxy", id.Email, "", LoginReasonGroupRequired)
		errs.WriteHTTPError(w, errs.Forbidden("your account is not in a group allowed to sign in"))
		return true
	}
	prov := h.roles.Provision(id.Email, groups, allowlisted)
	var token string
	var matched User
	var err error
	if id.Subject != "" {
		token, matched, err = h.svc.LoginOIDC(ctx, id, prov)
	} else {
		token, matched, err = h.svc.LoginOAuth(ctx, id.Email, prov)
	}
	switch {
	case errors.Is(err, ErrIdentityMismatch):
		log.FromContext(ctx).Warn().Str("email", id.Email).Str("subject", id.Subject).
			Msg("SECURITY: oauth2-proxy sign-in refused: account is bound to a different identity")
		h.svc.RecordSignInFailure(ctx, "oauth2_proxy", id.Email, matched.ID, LoginReasonIdentityMismatch)
		errs.WriteHTTPError(w, errs.Forbidden("this account is linked to a different identity"))
		return true
	case errors.Is(err, ErrUserDisabled):
		h.svc.RecordSignInFailure(ctx, "oauth2_proxy", id.Email, matched.ID, LoginReasonDisabled)
		return false
	case err != nil:
		log.FromContext(ctx).Error().Err(err).Str("email", id.Email).Msg("oauth2-proxy auto-login failed")
		return false
	}
	return h.continueWithSession(w, r, next, token)
}

func (v *idTokenVerifier) configured() bool { return v != nil }

type cookieSessionInfo struct {
	token string
	user  User
}

// cookieSession resolves the session cookie, if any, to its user. An invalid
// or expired session (or a store error) counts as no session: the caller then
// starts a fresh one from the ID token.
func (h *Handler) cookieSession(r *http.Request) (cookieSessionInfo, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return cookieSessionInfo{}, false
	}
	u, err := h.svc.Authenticate(r.Context(), c.Value)
	if err != nil {
		return cookieSessionInfo{}, false
	}
	return cookieSessionInfo{token: c.Value, user: u}, true
}

// hasSessionCookie is sessionToken without the Bearer fallback: in ID-token
// mode the Authorization header carries the IdP token, not a session.
func hasSessionCookie(r *http.Request) bool {
	c, err := r.Cookie(SessionCookie)
	return err == nil && c.Value != ""
}

// bearerJWT returns the Authorization Bearer value when it is shaped like a
// JWT (three dot-separated parts) rather than a session token or gph_ key.
func bearerJWT(r *http.Request) string {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "gph_") || strings.Count(v, ".") != 2 {
		return ""
	}
	return v
}

// HasNonJWTBearer reports whether the request carries a Bearer credential that
// a client chose to send — a gph_ API key or a session token — as opposed to a
// JWT-shaped IdP token a proxy may inject into every request.
func HasNonJWTBearer(r *http.Request) bool {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && strings.TrimSpace(v) != "" && bearerJWT(r) == ""
}

// iapSignIn handles a request carrying an IAP assertion; see oauth2ProxySignIn
// for the return value.
func (h *Handler) iapSignIn(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) bool {
	ctx := r.Context()
	id, err := h.iap.Validate(ctx, r.Header.Get(iapAssertionHeader))
	if err != nil {
		// In an IAP deployment the proxy injects this header, so a bad one means
		// a forged or replayed assertion or a request that bypassed IAP. Refuse
		// rather than fall back to whatever cookie or Bearer token also came.
		log.FromContext(ctx).Warn().Err(err).Msg("iap jwt invalid")
		errs.WriteHTTPErrorCtx(ctx, w, "invalid IAP assertion", http.StatusUnauthorized)
		return true
	}
	if _, hasCookie := sessionToken(r); hasCookie {
		return false
	}
	ok, allowlisted := domainGate(id.Email, h.iapDomains, h.iapAnyDomain)
	if !ok {
		h.svc.RecordSignInFailure(ctx, "iap", id.Email, "", LoginReasonDomainNotAllowed)
		errs.WriteHTTPErrorCtx(ctx, w, fmt.Sprintf("email domain %q is not allowed", emailDomain(id.Email)), http.StatusForbidden)
		return true
	}
	// IAP asserts no groups, so a required group refuses every IAP sign-in.
	if !h.roles.Admits(nil) {
		h.svc.RecordSignInFailure(ctx, "iap", id.Email, "", LoginReasonGroupRequired)
		errs.WriteHTTPError(w, errs.Forbidden("your account is not in a group allowed to sign in"))
		return true
	}
	token, matched, err := h.svc.LoginOIDC(ctx, id, h.roles.Provision(id.Email, nil, allowlisted))
	switch {
	case errors.Is(err, ErrUserDisabled):
		h.svc.RecordSignInFailure(ctx, "iap", id.Email, matched.ID, LoginReasonDisabled)
		errs.WriteHTTPError(w, errs.Forbidden("account disabled"))
		return true
	case errors.Is(err, ErrIdentityMismatch):
		log.FromContext(ctx).Warn().Str("email", id.Email).Str("subject", id.Subject).
			Msg("SECURITY: iap sign-in refused: account is bound to a different identity")
		h.svc.RecordSignInFailure(ctx, "iap", id.Email, matched.ID, LoginReasonIdentityMismatch)
		errs.WriteHTTPError(w, errs.Forbidden("this account is linked to a different identity"))
		return true
	case err != nil:
		log.FromContext(ctx).Error().Err(err).Msg("iap auto-login failed")
		errs.WriteHTTPError(w, errs.Internal("IAP sign-in failed"))
		return true
	}
	return h.continueWithSession(w, r, next, token)
}

// continueWithSession sets the cookie for a freshly issued session and serves
// the rest of this request as its user.
func (h *Handler) continueWithSession(w http.ResponseWriter, r *http.Request, next http.HandlerFunc, token string) bool {
	user, err := h.svc.Authenticate(r.Context(), token)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("authenticate new proxy session failed")
		return false
	}
	http.SetCookie(w, h.sessionCookie(token, sessionTTL))
	next(w, r.WithContext(ContextWithUser(r.Context(), user)))
	return true
}

// domainGate decides whether email may sign in through an SSO path, and
// whether it did so through a named allowlist (allowlisted) rather than the
// allow-any opt-out.
//
// An empty allowlist DENIES: "no restriction" and "never configured" are
// indistinguishable, and the unconfigured case let any account the IdP (or a
// forged proxy header) vouched for sign in. allowAny (*_ALLOW_ANY_DOMAIN) is
// the explicit, auditable opt-out.
func domainGate(email string, allowed []string, allowAny bool) (ok, allowlisted bool) {
	domain := emailDomain(email)
	if domain == "" {
		return false, false
	}
	if len(allowed) == 0 {
		return allowAny, false
	}
	if containsFold(allowed, domain) {
		return true, true
	}
	return false, false
}

// splitGroups parses oauth2-proxy's comma-separated X-Auth-Request-Groups.
func splitGroups(v string) []string {
	var out []string
	for _, g := range strings.Split(v, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
