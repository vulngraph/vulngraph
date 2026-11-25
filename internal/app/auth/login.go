package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Default login limits: tokens per minute, and the same number as burst.
const (
	DefaultLoginPerIPPerMinute      = 20
	DefaultLoginPerAccountPerMinute = 5
)

// loginFailedDetail is the single message for every failed login factor.
const loginFailedDetail = "invalid email, password or authenticator code"

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// WithLoginRateLimit replaces the default login brute-force limits. Every
// attempt takes a token from the caller's IP bucket (see WithClientIPHeader)
// and from the target account's bucket; an empty bucket answers 429 with
// Retry-After before the password is checked.
//
// The per-account bucket lets anyone slow down logins to a known address —
// the usual trade-off for stopping a distributed guesser.
func (h *Handler) WithLoginRateLimit(perIP, perAccount *KeyedLimiter) *Handler {
	h.loginPerIP = perIP
	h.loginPerAccount = perAccount
	return h
}

// WithClientIPHeader names the header a trusted proxy sets with the client
// address (CLIENT_IP_HEADER) and the proxy addresses it is honoured from
// (TRUSTED_PROXY_CIDRS); see ClientIP. Without trustedProxies the header is
// ignored and the TCP peer is used. The address keys the login per-IP bucket
// and is what RequireAuth attaches to the request context
// (ClientIPFromContext) for downstream audit checks.
func (h *Handler) WithClientIPHeader(header string, trustedProxies ...netip.Prefix) *Handler {
	h.clientIPHeader = header
	h.trustedProxies = trustedProxies
	return h
}

func (h *Handler) clientAddr(r *http.Request) string {
	return ClientIP(r, h.clientIPHeader, h.trustedProxies)
}

// Login verifies credentials and sets the session cookie. In bypass mode it
// immediately returns the synthetic admin without checking credentials.
//
// Password and TOTP code travel in one request. Any failed factor is the same
// 401 (loginFailedDetail): the response never says "totp code required",
// which would confirm the password.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if h.bypass {
		writeJSON(r.Context(), w, http.StatusOK, toUserResponse(bypassUser))
		return
	}
	if !h.passwordLoginEnabled() {
		errs.WriteHTTPError(w, errs.NotFound("password login is disabled behind the authenticating proxy"))
		return
	}
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON"))
		return
	}
	// The address goes on the context for the sign-in's audit row.
	r = r.WithContext(ContextWithClientIP(r.Context(), h.clientAddr(r)))

	if ok, wait := h.loginPerIP.Allow(h.clientAddr(r)); !ok {
		errs.WriteHTTPRateLimitError(r.Context(), w, retryAfterSeconds(wait))
		return
	}
	if ok, wait := h.loginPerAccount.Allow(NormalizeEmail(req.Email)); !ok {
		errs.WriteHTTPRateLimitError(r.Context(), w, retryAfterSeconds(wait))
		return
	}

	token, user, err := h.svc.Login(r.Context(), req.Email, req.Password, req.TOTPCode)
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		errs.WriteHTTPErrorCtx(r.Context(), w, loginFailedDetail, http.StatusUnauthorized)
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("login failed")
		errs.WriteHTTPError(w, errs.Internal("login failed"))
		return
	}

	http.SetCookie(w, h.sessionCookie(token, sessionTTL))
	writeJSON(r.Context(), w, http.StatusOK, toUserResponse(user))
}
