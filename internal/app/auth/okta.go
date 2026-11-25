package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"golang.org/x/oauth2"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// OktaOAuthConfig holds credentials for Okta OIDC sign-in. Okta is a
// standard OIDC provider, so it reuses the OAuth2 authorization-code flow —
// pointed at the org's Okta endpoints — exactly like the Google handler, rather
// than adding an OIDC-specific dependency.
type OktaOAuthConfig struct {
	ClientID       string
	ClientSecret   string
	Domain         string   // org domain, e.g. "dev-123.okta.com" (no scheme)
	RedirectURL    string   // OKTA_REDIRECT_URL; required unless RedirectFromHost
	AllowedDomains []string // only these email domains may sign in; empty denies unless AllowAnyDomain
	AllowAnyDomain bool     // explicit opt-out (OKTA_ALLOW_ANY_DOMAIN); new users become viewers
	// RedirectFromHost: see GoogleOAuthConfig.RedirectFromHost.
	RedirectFromHost bool
}

// Validate reports a config that would build its redirect URL from the request.
func (c OktaOAuthConfig) Validate() error {
	return validateRedirectURL("OKTA_REDIRECT_URL", c.RedirectURL, c.RedirectFromHost)
}

// WithOktaOAuth enables Okta OIDC sign-in on the handler.
func (h *Handler) WithOktaOAuth(cfg *OktaOAuthConfig) *Handler {
	h.oktaCfg = cfg
	return h
}

// OktaOAuthRedirect starts the OAuth2 flow by redirecting to Okta's consent screen.
func (h *Handler) OktaOAuthRedirect(w http.ResponseWriter, r *http.Request) {
	if h.rejectWhenBypassed(w) {
		return
	}
	if h.oktaCfg == nil {
		errs.WriteHTTPError(w, errs.InvalidInput("Okta OAuth not configured"))
		return
	}
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		errs.WriteHTTPError(w, errs.Internal("could not generate state"))
		return
	}
	cfg := h.oktaOauthConfig(r)
	if cfg.RedirectURL == "" {
		errs.WriteHTTPError(w, errs.Internal("Okta OAuth redirect URL not configured"))
		return
	}
	state := hex.EncodeToString(stateBytes)
	http.SetCookie(w, h.cookie(oauthStateCookie, state, 600))
	http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

// OktaOAuthCallback handles the redirect from Okta: validates state, exchanges
// the code, fetches the user's email from the OIDC userinfo endpoint, and issues
// a session — mapping the Okta identity onto the existing role model.
func (h *Handler) OktaOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if h.rejectWhenBypassed(w) {
		return
	}
	if h.oktaCfg == nil {
		errs.WriteHTTPError(w, errs.InvalidInput("Okta OAuth not configured"))
		return
	}
	if !validOAuthState(r) {
		errs.WriteHTTPErrorCtx(r.Context(), w, "invalid OAuth state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, h.cookie(oauthStateCookie, "", -1))

	token, err := h.oktaOauthConfig(r).Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("okta oauth exchange failed")
		errs.WriteHTTPError(w, errs.Internal("OAuth exchange failed"))
		return
	}
	info, err := fetchUserInfo(r.Context(), h.oktaBaseURL()+"/oauth2/v1/userinfo", token.AccessToken)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("okta userinfo failed")
		errs.WriteHTTPError(w, errs.Internal("could not fetch user info from Okta"))
		return
	}
	// The org authorization server (/oauth2/v1) issues as the org URL.
	h.completeOIDCSignIn(w, r, oidcSignIn{
		provider: "okta", issuer: h.oktaBaseURL(), allowed: h.oktaCfg.AllowedDomains, allowAny: h.oktaCfg.AllowAnyDomain,
	}, info)
}

func (h *Handler) oktaOauthConfig(r *http.Request) *oauth2.Config {
	base := h.oktaBaseURL()
	scopes := []string{"openid", "email", "profile"}
	if h.roles.WantsGroups() {
		// Okta returns the groups claim from userinfo only for this scope.
		scopes = append(scopes, "groups")
	}
	return &oauth2.Config{
		ClientID:     h.oktaCfg.ClientID,
		ClientSecret: h.oktaCfg.ClientSecret,
		RedirectURL:  oauthRedirectURL(r, h.oktaCfg.RedirectURL, h.oktaCfg.RedirectFromHost, "/api/auth/okta/callback"),
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  base + "/oauth2/v1/authorize",
			TokenURL: base + "/oauth2/v1/token",
		},
	}
}

// oktaBaseURL is the org URL, e.g. "https://dev-123.okta.com".
func (h *Handler) oktaBaseURL() string {
	return "https://" + strings.TrimSuffix(h.oktaCfg.Domain, "/")
}
