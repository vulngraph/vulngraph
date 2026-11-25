package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/apikey"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// newAuthHandler builds the auth handler from the environment: bypass mode,
// API keys, oauth2-proxy, Google/Okta OIDC, IAP, SSO roles, client-IP
// resolution and login rate limits. A configuration that would leave a
// credential path forgeable is an error, not a warning.
func newAuthHandler(ctx context.Context, getenv func(string) string, authSvc *auth.Service, apiKeySvc *apikey.Service, bypassAuth bool) (*auth.Handler, error) {
	// BYPASS_AUTH=true (plus BYPASS_AUTH_I_UNDERSTAND=yes) skips session checks
	// entirely — use when the app is behind a network-level ZTNA proxy so
	// app-level auth is redundant.
	var authHandler *auth.Handler
	if bypassAuth {
		// Loud on purpose: BYPASS_AUTH serves every request as a synthetic admin.
		// It is only safe behind a network-level auth gate (ZTNA/oauth2-proxy). If
		// this fires on an internet-reachable deploy, the app is wide open — the
		// warning is the tripwire for that misconfiguration.
		log.FromContext(ctx).Warn().Msg(
			"SECURITY: BYPASS_AUTH=true — all requests run as a synthetic admin with no session check; " +
				"this MUST sit behind a network-level auth gate (ZTNA/oauth2-proxy), never on a public endpoint")
		authHandler = auth.NewHandlerBypass()
	} else {
		authHandler = auth.NewHandler(authSvc)
	}
	// Wire API key auth: external agents authenticate with
	// `Authorization: Bearer gph_<key>` (keys from Settings → API Keys).
	authHandler = authHandler.WithAPIKeys(apiKeyAdapter{apiKeySvc})
	// OAUTH2_PROXY=true signs in users oauth2-proxy (nginx auth-url) vouched
	// for. The email header alone is forgeable by anything that reaches the pod,
	// so serve refuses to start without a way to verify it: the IdP-signed ID
	// token (OAUTH2_PROXY_OIDC_ISSUER + _AUDIENCE, preferred) and/or the shared
	// secret (defence in depth; see auth.WithOAuth2Proxy).
	if getenv("OAUTH2_PROXY") == "true" {
		secret := getenv("OAUTH2_PROXY_SHARED_SECRET")
		issuer, audience := getenv("OAUTH2_PROXY_OIDC_ISSUER"), getenv("OAUTH2_PROXY_OIDC_AUDIENCE")
		switch {
		case secret == "" && issuer == "":
			return nil, fmt.Errorf("OAUTH2_PROXY=true requires OAUTH2_PROXY_OIDC_ISSUER (+ OAUTH2_PROXY_OIDC_AUDIENCE) " +
				"and/or OAUTH2_PROXY_SHARED_SECRET; without one, X-Auth-Request-Email is forgeable by any caller that reaches serve")
		case secret != "" && len(secret) < minProxySecretLen:
			return nil, fmt.Errorf("OAUTH2_PROXY_SHARED_SECRET must be at least %d characters", minProxySecretLen)
		case issuer != "" && audience == "":
			return nil, fmt.Errorf("OAUTH2_PROXY_OIDC_ISSUER requires OAUTH2_PROXY_OIDC_AUDIENCE (the oauth2-proxy client id)")
		case issuer != "" && auth.ValidateOIDCIssuer(issuer) != nil:
			return nil, fmt.Errorf("OAUTH2_PROXY_OIDC_ISSUER: %w", auth.ValidateOIDCIssuer(issuer))
		case issuer == "":
			log.FromContext(ctx).Warn().Msg("SECURITY: OAUTH2_PROXY uses the shared secret only — anyone who can read " +
				auth.OAuth2ProxySecretHeader + " and reach serve can sign in as anyone. Set OAUTH2_PROXY_OIDC_ISSUER " +
				"to verify the IdP-signed ID token instead")
		}
		// OAUTH2_PROXY_ALLOWED_DOMAINS narrows which email domains the header path
		// accepts, mirroring GOOGLE_ALLOWED_DOMAINS. Unset denies the header path
		// unless OAUTH2_PROXY_ALLOW_ANY_DOMAIN=true says otherwise.
		proxyDomains := splitCSV(getenv("OAUTH2_PROXY_ALLOWED_DOMAINS"))
		allowAny := getenv("OAUTH2_PROXY_ALLOW_ANY_DOMAIN") == "true"
		warnIdentityDomains(ctx, "OAUTH2_PROXY", "OAUTH2_PROXY", "oauth2-proxy", proxyDomains, allowAny)
		// For IdPs that never send email_verified. The first token sign-in binds
		// an existing account by email, so this is only safe when the IdP does not
		// let users choose their address.
		allowUnverified := getenv("OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL") == "true"
		if allowUnverified {
			log.FromContext(ctx).Warn().Msg("SECURITY: OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL=true — ID tokens without " +
				"email_verified are accepted; an IdP that lets users set their email could bind them to an existing account")
		}
		// OAUTH2_PROXY_TRUST_GROUPS: only safe when X-Auth-Request-Groups is listed in
		// nginx auth-response-headers (otherwise the client sets it). Ignored in
		// ID-token mode, where groups come from the token.
		authHandler = authHandler.WithOAuth2Proxy(auth.OAuth2ProxyConfig{
			OIDCIssuer: issuer, OIDCAudience: audience, SharedSecret: secret,
			OIDCAllowUnverifiedEmail: allowUnverified,
			TrustGroupsHeader:        getenv("OAUTH2_PROXY_TRUST_GROUPS") == "true",
			AllowedDomains:           proxyDomains, AllowAnyDomain: allowAny,
		})
	}
	// ADMIN_EMAILS / OIDC_ADMIN_GROUPS / OIDC_ANALYST_GROUPS decide a first SSO
	// sign-in's role; everyone else starts as viewer (auth.RolePolicy).
	// OIDC_REQUIRED_GROUPS gates every SSO sign-in on group membership.
	authHandler = authHandler.WithRolePolicy(auth.RolePolicy{
		AdminEmails:    splitCSV(getenv("ADMIN_EMAILS")),
		AdminGroups:    splitCSV(getenv("OIDC_ADMIN_GROUPS")),
		AnalystGroups:  splitCSV(getenv("OIDC_ANALYST_GROUPS")),
		RequiredGroups: splitCSV(getenv("OIDC_REQUIRED_GROUPS")),
	})
	// OAUTH_REDIRECT_FROM_HOST=true (local dev only) lets an unset
	// GOOGLE_/OKTA_REDIRECT_URL be built from the request's Host header.
	redirectFromHost := getenv("OAUTH_REDIRECT_FROM_HOST") == "true"
	if redirectFromHost {
		log.FromContext(ctx).Warn().Msg("SECURITY: OAUTH_REDIRECT_FROM_HOST=true — an unset OAuth redirect URL is built from the " +
			"client-controlled Host header; local dev only, set GOOGLE_REDIRECT_URL / OKTA_REDIRECT_URL in production")
	}
	// GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET enable Google OAuth sign-in.
	if clientID := getenv("GOOGLE_CLIENT_ID"); clientID != "" {
		allowedDomains := splitCSV(getenv("GOOGLE_ALLOWED_DOMAINS"))
		allowAny := getenv("GOOGLE_ALLOW_ANY_DOMAIN") == "true"
		warnIdentityDomains(ctx, "GOOGLE", "GOOGLE_CLIENT_ID", "Google", allowedDomains, allowAny)
		cfg := &auth.GoogleOAuthConfig{
			ClientID:         clientID,
			ClientSecret:     getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:      getenv("GOOGLE_REDIRECT_URL"),
			AllowedDomains:   allowedDomains,
			AllowAnyDomain:   allowAny,
			RedirectFromHost: redirectFromHost,
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("google oauth: %w", err)
		}
		authHandler = authHandler.WithGoogleOAuth(cfg)
	}
	// OKTA_CLIENT_ID + OKTA_CLIENT_SECRET + OKTA_DOMAIN enable Okta OIDC sign-in.
	if clientID := getenv("OKTA_CLIENT_ID"); clientID != "" {
		allowedDomains := splitCSV(getenv("OKTA_ALLOWED_DOMAINS"))
		allowAny := getenv("OKTA_ALLOW_ANY_DOMAIN") == "true"
		warnIdentityDomains(ctx, "OKTA", "OKTA_CLIENT_ID", "Okta", allowedDomains, allowAny)
		cfg := &auth.OktaOAuthConfig{
			ClientID:         clientID,
			ClientSecret:     getenv("OKTA_CLIENT_SECRET"),
			Domain:           getenv("OKTA_DOMAIN"),
			RedirectURL:      getenv("OKTA_REDIRECT_URL"),
			AllowedDomains:   allowedDomains,
			AllowAnyDomain:   allowAny,
			RedirectFromHost: redirectFromHost,
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("okta oauth: %w", err)
		}
		authHandler = authHandler.WithOktaOAuth(cfg)
	}
	// IAP_AUDIENCE enables GCP Identity-Aware Proxy JWT validation.
	// When set, users arriving via IAP are auto-logged-in from the
	// X-Goog-IAP-JWT-Assertion header — no login page shown.
	// Format: /projects/{number}/global/backendServices/{id}  (GKE/LB)
	//         /projects/{number}/apps/{project_id}            (App Engine)
	// IAP_ALLOWED_DOMAINS / IAP_ALLOW_ANY_DOMAIN gate IAP identities exactly
	// like the Google/Okta allowlists (empty denies).
	if iapAudience := getenv("IAP_AUDIENCE"); iapAudience != "" {
		allowedDomains := splitCSV(getenv("IAP_ALLOWED_DOMAINS"))
		allowAny := getenv("IAP_ALLOW_ANY_DOMAIN") == "true"
		warnIdentityDomains(ctx, "IAP", "IAP_AUDIENCE", "IAP", allowedDomains, allowAny)
		authHandler = authHandler.WithIAP(iapAudience, allowedDomains, allowAny)
	}
	// Behind IAP/oauth2-proxy, password login is off unless explicitly kept as
	// a break-glass path.
	if getenv("PASSWORD_LOGIN_BREAK_GLASS") == "true" {
		log.FromContext(ctx).Warn().Msg("SECURITY: PASSWORD_LOGIN_BREAK_GLASS=true — password login stays enabled behind the authenticating proxy")
		authHandler = authHandler.WithPasswordBreakGlass(true)
	}
	// CLIENT_IP_HEADER names the header the ingress sets with the client
	// address, honoured only from TRUSTED_PROXY_CIDRS; without both, every
	// request behind a proxy shares the proxy's IP (one login bucket, and a
	// meaningless executor same-address audit flag).
	trusted, err := auth.ParseTrustedProxies(getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS: %w", err)
	}
	clientIPHeader := getenv("CLIENT_IP_HEADER")
	if clientIPHeader != "" && len(trusted) == 0 {
		log.FromContext(ctx).Error().Msg("SECURITY: CLIENT_IP_HEADER is set but TRUSTED_PROXY_CIDRS is empty — the header is IGNORED " +
			"and the TCP peer is used. Set TRUSTED_PROXY_CIDRS to the addresses of the proxy that sets it")
	}
	// Login brute-force limits are per minute (0 disables).
	perIP := envRate(getenv, "LOGIN_RATE_LIMIT_PER_IP", auth.DefaultLoginPerIPPerMinute)
	perAccount := envRate(getenv, "LOGIN_RATE_LIMIT_PER_ACCOUNT", auth.DefaultLoginPerAccountPerMinute)
	return authHandler.WithClientIPHeader(clientIPHeader, trusted...).WithLoginRateLimit(
		auth.NewKeyedLimiter(perIP, int(perIP)), auth.NewKeyedLimiter(perAccount, int(perAccount))), nil
}

// minProxySecretLen is the shortest OAUTH2_PROXY_SHARED_SECRET serve accepts:
// it stands in for every identity, so it must not be guessable.
const minProxySecretLen = 32

// envRate parses a non-negative per-minute rate; 0 disables the limit, and an
// unset or malformed value takes fallback.
func envRate(getenv func(string) string, key string, fallback float64) float64 {
	if n, err := strconv.ParseFloat(strings.TrimSpace(getenv(key)), 64); err == nil && n >= 0 {
		return n
	}
	return fallback
}

// warnIdentityDomains logs the startup tripwire for an identity provider
// (prefix is "GOOGLE", "OKTA", "IAP" or "OAUTH2_PROXY"; enabledBy is the variable that turned
// it on) whose domain allowlist is empty. An empty list denies every sign-in
// unless <prefix>_ALLOW_ANY_DOMAIN=true; see the auth package's domainGate.
func warnIdentityDomains(ctx context.Context, prefix, enabledBy, provider string, allowed []string, allowAny bool) {
	if len(allowed) > 0 {
		return
	}
	if allowAny {
		log.FromContext(ctx).Warn().Msgf(
			"SECURITY: %s_ALLOW_ANY_DOMAIN=true — any %s account can sign in; first-time users are viewers unless named in ADMIN_EMAILS or an OIDC_*_GROUPS group",
			prefix, provider)
		return
	}
	log.FromContext(ctx).Error().Msgf(
		"SECURITY: %[3]s is set but %[1]s_ALLOWED_DOMAINS is empty — %[2]s sign-in is DISABLED (every login is refused). "+
			"Set %[1]s_ALLOWED_DOMAINS, or %[1]s_ALLOW_ANY_DOMAIN=true to accept any account deliberately",
		prefix, provider, enabledBy)
}

// apiKeyAdapter adapts apikey.Service to the auth.apiKeyVerifier interface.
type apiKeyAdapter struct{ svc *apikey.Service }

func (a apiKeyAdapter) Verify(ctx context.Context, plaintext string) (auth.APIKeyRecord, error) {
	key, err := a.svc.Verify(ctx, plaintext)
	if err != nil {
		return auth.APIKeyRecord{}, err
	}
	rec := auth.APIKeyRecord{
		ID:              key.ID,
		UserID:          key.UserID,
		Name:            key.Name,
		Scope:           string(key.Scopes),
		OwnerEmail:      key.OwnerEmail,
		OwnerRole:       auth.Role(key.OwnerRole),
		OwnerCreatedAt:  key.OwnerCreatedAt,
		OwnerAdminSince: key.OwnerAdminSince,
	}
	if key.ExpiresAt != nil {
		rec.ExpiresAt = *key.ExpiresAt
	}
	return rec, nil
}
