package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	googleIssuer      = "https://accounts.google.com"
	googleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
)

// validOAuthState reports whether the callback's state matches the state
// cookie set when the flow started. An empty state never matches: a missing
// cookie and a missing parameter would otherwise compare equal.
func validOAuthState(r *http.Request) bool {
	c, err := r.Cookie(oauthStateCookie)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.URL.Query().Get("state")
	return got != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(got)) == 1
}

// oauthRedirectURL is the configured redirect URL, or — only with the dev
// opt-in — one built from the request's Host and X-Forwarded-Proto. Empty
// means not configured.
func oauthRedirectURL(r *http.Request, configured string, fromHost bool, callbackPath string) string {
	if configured != "" || !fromHost {
		return configured
	}
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	return scheme + "://" + r.Host + callbackPath
}

// validateRedirectURL requires an absolute http(s) redirect URL unless the
// dev-only host derivation is enabled.
func validateRedirectURL(envName, raw string, fromHost bool) error {
	if raw == "" {
		if fromHost {
			return nil
		}
		return fmt.Errorf("%s is unset (set it, or OAUTH_REDIRECT_FROM_HOST=true for local dev only): %w", envName, ErrRedirectURLRequired)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%s %q must be an absolute http(s) URL: %w", envName, raw, ErrRedirectURLRequired)
	}
	return nil
}

// userInfo is the subset of an OIDC userinfo response sign-in needs.
type userInfo struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified flexBool `json:"email_verified"`
	// VerifiedEmail is Google's legacy (oauth2/v2) spelling.
	VerifiedEmail flexBool `json:"verified_email"`
	// Groups is the IdP group claim (Okta, with the groups scope), mapped to a
	// role by RolePolicy on first sign-in. Google does not send one.
	Groups []string `json:"groups"`
	// HostedDomain is Google's hd claim: the Workspace domain that manages the
	// account. Absent for a consumer Google account, including one registered
	// on a company address.
	HostedDomain string `json:"hd"`
}

// flexBool accepts a JSON boolean or the strings "true"/"false": some IdPs
// serialise email_verified as a string.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("flexBool: %w", err)
	}
	switch t := v.(type) {
	case bool:
		*b = flexBool(t)
	case string:
		*b = t == "true"
	default:
		*b = false
	}
	return nil
}

// identityFromUserInfo turns a userinfo response into an OIDCIdentity, refusing
// one whose email the IdP has not verified: an unverified address is just a
// string the account holder typed, and matching on it hands over whichever
// local account owns that address.
func identityFromUserInfo(issuer string, info userInfo) (OIDCIdentity, error) {
	if info.Sub == "" || info.Email == "" {
		return OIDCIdentity{}, fmt.Errorf("identityFromUserInfo: userinfo lacks sub or email")
	}
	if !bool(info.EmailVerified) && !bool(info.VerifiedEmail) {
		return OIDCIdentity{}, ErrEmailNotVerified
	}
	return OIDCIdentity{Issuer: issuer, Subject: info.Sub, Email: NormalizeEmail(info.Email)}, nil
}

// fetchUserInfo calls an OIDC userinfo endpoint with the access token.
func fetchUserInfo(ctx context.Context, url, accessToken string) (userInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return userInfo{}, fmt.Errorf("fetchUserInfo: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := safenet.New(10 * time.Second).Do(req)
	if err != nil {
		return userInfo{}, fmt.Errorf("fetchUserInfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return userInfo{}, fmt.Errorf("fetchUserInfo: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return userInfo{}, fmt.Errorf("fetchUserInfo: read body: %w", err)
	}
	var info userInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return userInfo{}, fmt.Errorf("fetchUserInfo: unmarshal: %w", err)
	}
	return info, nil
}

// oidcSignIn names the provider a callback completes and its gates.
type oidcSignIn struct {
	provider, issuer string
	allowed          []string // *_ALLOWED_DOMAINS
	allowAny         bool     // *_ALLOW_ANY_DOMAIN
	// checkHostedDomain (Google) requires, when allowed is set, the hd claim
	// to be one of the allowed domains as well as the email's domain.
	checkHostedDomain bool
}

// completeOIDCSignIn is the shared tail of the Google and Okta callbacks:
// verify the identity, apply the domain allowlist (and for Google the hosted
// domain), the required groups, sign in (binding the account to the
// identity), and set the session cookie. Every refusal after the identity is
// known is logged and written as an auth.login_failed row.
func (h *Handler) completeOIDCSignIn(w http.ResponseWriter, r *http.Request, in oidcSignIn, info userInfo) {
	r = r.WithContext(ContextWithClientIP(r.Context(), h.clientAddr(r)))
	ctx := r.Context()
	provider := in.provider
	refuse := func(email, userID, reason, detail string) {
		h.svc.RecordSignInFailure(ctx, provider, email, userID, reason)
		errs.WriteHTTPError(w, errs.Forbidden(detail))
	}
	id, err := identityFromUserInfo(in.issuer, info)
	if errors.Is(err, ErrEmailNotVerified) {
		refuse(NormalizeEmail(info.Email), "", LoginReasonEmailUnverified, "email address is not verified by the identity provider")
		return
	}
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Str("provider", provider).Msg("oidc userinfo incomplete")
		errs.WriteHTTPError(w, errs.Internal("identity provider returned incomplete user info"))
		return
	}

	ok, allowlisted := domainGate(id.Email, in.allowed, in.allowAny)
	if !ok {
		refuse(id.Email, "", LoginReasonDomainNotAllowed, fmt.Sprintf("email domain %q is not allowed", emailDomain(id.Email)))
		return
	}
	// An allowlisted email suffix alone admits a consumer Google account
	// registered on a company address, or one an offboarded person kept.
	// Google's hd claim names the Workspace that manages the account; a
	// missing one is refused, never read as a match.
	if in.checkHostedDomain && len(in.allowed) > 0 && !containsFold(in.allowed, info.HostedDomain) {
		refuse(id.Email, "", LoginReasonHostedDomain, "this Google account is not managed by an allowed Google Workspace domain")
		return
	}
	if !h.roles.Admits(info.Groups) {
		refuse(id.Email, "", LoginReasonGroupRequired, "your account is not in a group allowed to sign in")
		return
	}

	token, matched, err := h.svc.LoginOIDC(ctx, id, h.roles.Provision(id.Email, info.Groups, allowlisted))
	switch {
	case errors.Is(err, ErrUserDisabled):
		refuse(id.Email, matched.ID, LoginReasonDisabled, "account disabled")
		return
	case errors.Is(err, ErrIdentityMismatch):
		log.FromContext(ctx).Warn().Str("provider", provider).Str("email", id.Email).
			Str("issuer", id.Issuer).Str("subject", id.Subject).
			Msg("SECURITY: oidc sign-in refused: account is bound to a different identity")
		refuse(id.Email, matched.ID, LoginReasonIdentityMismatch, "this account is linked to a different identity")
		return
	case err != nil:
		log.FromContext(ctx).Error().Err(err).Str("provider", provider).Msg("oidc login failed")
		errs.WriteHTTPError(w, errs.Internal("OAuth login failed"))
		return
	}
	http.SetCookie(w, h.sessionCookie(token, sessionTTL))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
