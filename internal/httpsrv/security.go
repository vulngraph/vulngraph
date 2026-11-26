package httpsrv

import (
	"fmt"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/errs"
)

// SecurityConfig carries the operator-tunable parts of the request-hardening
// middleware. The zero value is the strict default.
type SecurityConfig struct {
	// AllowedOrigins are extra origins ("https://graph.example.com") trusted to
	// send state-changing /api requests. Same-origin requests never need listing.
	AllowedOrigins []string
	// TLSProxy declares that TLS terminates at a proxy in front of the app, so
	// HSTS is sent on requests that reach the pod over plain HTTP. A direct TLS
	// request always gets HSTS.
	TLSProxy bool
	// AllowedHosts, when non-empty, rejects any request whose Host header (port
	// stripped) is not listed. Set only under BYPASS_AUTH, where a DNS-rebinding
	// page could otherwise drive the unauthenticated admin API from a browser.
	AllowedHosts []string
	// LLMLimiter budgets the LLM-backed routes per user. Nil uses
	// auth.DefaultLLMPerUserPerMinute.
	LLMLimiter *auth.KeyedLimiter
	// AlertContextLimiter budgets alert-context lookups (REST and MCP) per
	// user: each runs an unindexed attribute scan over assets. Nil uses
	// DefaultAlertContextPerUserPerMinute.
	AlertContextLimiter *auth.KeyedLimiter
	// CypherLimiter budgets the routes that run on the graph engine's small
	// caller-Cypher pool (REST and MCP run_cypher) per user. Nil uses
	// DefaultCypherPerUserPerMinute.
	CypherLimiter *auth.KeyedLimiter
}

// DefaultCypherPerUserPerMinute is the default per-user budget for caller
// Cypher (CYPHER_RATE_LIMIT_PER_USER).
const DefaultCypherPerUserPerMinute = 30

// DefaultAlertContextPerUserPerMinute is the default per-user budget for
// alert-context lookups (ALERT_CONTEXT_RATE_LIMIT_PER_USER).
const DefaultAlertContextPerUserPerMinute = 30

// Validate reports a malformed AllowedOrigins entry, so a typo fails startup
// rather than silently trusting nothing (or the wrong thing).
func (c SecurityConfig) Validate() error {
	cop := http.NewCrossOriginProtection()
	for _, o := range c.AllowedOrigins {
		if err := cop.AddTrustedOrigin(o); err != nil {
			return fmt.Errorf("allowed origin %q: %w", o, err)
		}
	}
	return nil
}

// contentSecurityPolicy locks the SPA to its own origin. style-src needs
// 'unsafe-inline': ChatPanel renders a <style> element and the JIT approval
// page uses style attributes. Scripts stay 'self' only — the Vite build
// emits no inline script (pinned by web.TestBuiltIndexHasNoInlineScript).
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; object-src 'none'; " +
	"base-uri 'self'; frame-ancestors 'none'; form-action 'self'"

const hstsValue = "max-age=31536000"

// withSecurityHeaders sets the browser hardening headers on every response,
// SPA and API alike. Referrer-Policy: no-referrer keeps the JIT approval token
// in /api/queue/approve-link/{token} out of Referer headers.
func withSecurityHeaders(tlsProxy bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if r.TLS != nil || tlsProxy {
			h.Set("Strict-Transport-Security", hstsValue)
		}
		next.ServeHTTP(w, r)
	})
}

// csrfExempt reports whether a state-changing /api request is authenticated by
// a credential in the request itself rather than an ambient browser one, so
// neither CSRF check applies to it.
func csrfExempt(r *http.Request) bool {
	p := r.URL.Path
	// GitHub is the caller; authenticity is the HMAC signature.
	if strings.HasPrefix(p, "/api/webhooks/") {
		return true
	}
	// The emailed HMAC token in the path is the credential, and the
	// confirmation page posts an HTML form (form-urlencoded) to it.
	if strings.HasPrefix(p, "/api/queue/approve-link/") || strings.HasPrefix(p, "/api/queue/deny-link/") {
		return true
	}
	return false
}

// withCSRF rejects cross-site state-changing /api requests. SameSite=Lax alone
// does not cover same-site subdomains, and the proxy/IAP modes mint a session
// for any request carrying the proxy header. Two checks:
//
//   - origin (always): Sec-Fetch-Site must be same-origin/none, or Origin must
//     match the Host (or a configured AllowedOrigins entry) —
//     http.CrossOriginProtection. Non-browser clients send neither header and
//     pass;
//   - content type: a request with a body must be application/json, which a
//     cross-site HTML form or no-cors fetch cannot send without a preflight.
//     Skipped only for an API-key or session Bearer (auth.HasNonJWTBearer): a
//     JWT-shaped Bearer may be an IdP token a proxy injects into every request
//     (oauth2-proxy --set-authorization-header), which a forged form post
//     would carry too.
//
// Login is covered too (login CSRF would sign a victim into the attacker's
// account).
func withCSRF(allowedOrigins []string, next http.Handler) http.Handler {
	cop := http.NewCrossOriginProtection()
	for _, o := range allowedOrigins {
		_ = cop.AddTrustedOrigin(o) // validated at startup by SecurityConfig.Validate
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || isSafeMethod(r.Method) || csrfExempt(r) {
			next.ServeHTTP(w, r)
			return
		}
		if err := cop.Check(r); err != nil {
			errs.WriteHTTPErrorCtx(r.Context(), w, "cross-origin request rejected", http.StatusForbidden)
			return
		}
		if !auth.HasNonJWTBearer(r) && !jsonOrEmptyBody(r) {
			errs.WriteHTTPErrorCtx(r.Context(), w, "Content-Type must be application/json", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// jsonOrEmptyBody accepts an application/json body, or no body at all (several
// actions are body-less POSTs).
func jsonOrEmptyBody(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return r.ContentLength == 0
	}
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "application/json"
}

// withHostAllowlist rejects requests whose Host is not in allowed (compared
// without port, case-insensitively). Probes are exempt: the kubelet dials the
// pod IP, and /healthz and /readyz reveal nothing.
func withHostAllowlist(allowed []string, next http.Handler) http.Handler {
	if len(allowed) == 0 {
		return next
	}
	set := make(map[string]bool, len(allowed))
	for _, h := range allowed {
		set[normalizeHost(h)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || set[normalizeHost(r.Host)] {
			next.ServeHTTP(w, r)
			return
		}
		errs.WriteHTTPErrorCtx(r.Context(), w, "host not allowed", http.StatusForbidden)
	})
}

// normalizeHost strips any port and IPv6 brackets and lowercases.
func normalizeHost(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
}
