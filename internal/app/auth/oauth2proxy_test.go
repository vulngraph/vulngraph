package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// probe is a handler that records the user RequireAuth resolved.
func probe(seen *User) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u, ok := UserFromContext(r.Context()); ok {
			*seen = u
		}
		w.WriteHeader(http.StatusOK)
	}
}

const testProxySecret = "proxy-shared-secret-0123456789abcdef"

// proxyCfg is a shared-secret-only oauth2-proxy configuration.
func proxyCfg(domains []string, allowAny bool) OAuth2ProxyConfig {
	return OAuth2ProxyConfig{SharedSecret: testProxySecret, AllowedDomains: domains, AllowAnyDomain: allowAny}
}

// oauth2ProxyRequest is a request as nginx forwards it after oauth2-proxy
// authenticated the user: identity header plus the proxy's shared secret.
func oauth2ProxyRequest(email string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.Header.Set("X-Auth-Request-Email", email)
	r.Header.Set(OAuth2ProxySecretHeader, testProxySecret)
	return r
}

// The oauth2-proxy header path used to auto-create unknown emails as RoleAdmin.
// The header is only trustworthy for traffic that actually traversed nginx, so
// any workload able to dial the pod directly could mint itself an admin by
// setting one header. A first-time email must land as a viewer.
func TestOAuth2Proxy_AutoCreatedUserIsNotAdmin(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	h := NewHandler(svc).WithOAuth2Proxy(proxyCfg(nil, true))

	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, oauth2ProxyRequest("stranger@example.com"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "stranger@example.com", seen.Email)
	require.Equal(t, RoleViewer, seen.Role, "oauth2-proxy header must never provision an admin")
}

// The domain allowlist must gate this path exactly as it gates the Google and
// Okta callbacks — including not creating the user at all.
func TestOAuth2Proxy_DisallowedDomainIsRejectedAndNotProvisioned(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	h := NewHandler(svc).WithOAuth2Proxy(proxyCfg([]string{"example.com"}, false))

	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, oauth2ProxyRequest("attacker@evil.com"))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Zero(t, seen)
	_, err := repo.GetUserCredentialsByEmail(context.Background(), "attacker@evil.com")
	require.ErrorIs(t, err, ErrNotFound, "a rejected email must not be provisioned")
}

func TestOAuth2Proxy_AllowedDomainIsAccepted(t *testing.T) {
	svc, _ := newTestService(t) // not an empty install: no first-user bootstrap
	h := NewHandler(svc).WithOAuth2Proxy(proxyCfg([]string{"example.com"}, false))

	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, oauth2ProxyRequest("dev@example.com"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, RoleViewer, seen.Role)
}

// The P0: any pod that could dial the Service set X-Auth-Request-Email to an
// existing admin's address and got an admin session. Without the proxy's
// shared secret the header is refused, whoever it names.
func TestOAuth2Proxy_HeaderWithoutSharedSecretIsRefused(t *testing.T) {
	svc, repo := newTestService(t) // admin@example.com is an admin
	h := NewHandler(svc).WithOAuth2Proxy(proxyCfg([]string{"example.com"}, false))

	for name, secret := range map[string]string{
		"missing": "", "wrong": "guess", "prefix": testProxySecret[:10], "longer": testProxySecret + "x",
	} {
		t.Run(name, func(t *testing.T) {
			r := oauth2ProxyRequest("admin@example.com")
			r.Header.Set(OAuth2ProxySecretHeader, secret)
			var seen User
			rec := httptest.NewRecorder()
			h.RequireAuth(probe(&seen))(rec, r)

			require.Equal(t, http.StatusUnauthorized, rec.Code)
			require.Zero(t, seen)
			require.Empty(t, rec.Result().Cookies(), "no session may be issued")
			require.Empty(t, repo.sessions)
		})
	}
}

// An unset secret (serve refuses to start that way, but the handler must not
// rely on it) refuses every header rather than matching an empty one.
func TestOAuth2Proxy_EmptySharedSecretRefusesEverything(t *testing.T) {
	svc, _ := newTestService(t)
	h := NewHandler(svc).WithOAuth2Proxy(OAuth2ProxyConfig{AllowedDomains: []string{"example.com"}})

	r := oauth2ProxyRequest("admin@example.com")
	r.Header.Del(OAuth2ProxySecretHeader)
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(new(User)))(rec, r)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// Behind a verified proxy the role policy applies like any SSO path, and an
// empty install with no role mapping bootstraps its admin.
func TestOAuth2Proxy_RolePolicy(t *testing.T) {
	h := NewHandler(NewService(newFakeRepo())).WithOAuth2Proxy(proxyCfg([]string{"example.com"}, false))
	var seen User
	h.RequireAuth(probe(&seen))(httptest.NewRecorder(), oauth2ProxyRequest("first@example.com"))
	require.Equal(t, RoleAdmin, seen.Role, "first user of an empty install")
	h.RequireAuth(probe(&seen))(httptest.NewRecorder(), oauth2ProxyRequest("dev@example.com"))
	require.Equal(t, RoleViewer, seen.Role)
}

// ingress-nginx only overwrites headers listed in auth-response-headers, so an
// unlisted X-Auth-Request-Groups is whatever the client sent. With an admin
// group mapped, honouring it by default let any proxied user self-grant admin.
func TestOAuth2Proxy_GroupsHeaderNeedsExplicitTrust(t *testing.T) {
	policy := RolePolicy{AdminGroups: []string{"graph-admins"}, AnalystGroups: []string{"secops"}}
	signIn := func(cfg OAuth2ProxyConfig, email, groups string) Role {
		h := NewHandler(NewService(newFakeRepo())).WithOAuth2Proxy(cfg).WithRolePolicy(policy)
		r := oauth2ProxyRequest(email)
		r.Header.Set("X-Auth-Request-Groups", groups)
		var seen User
		h.RequireAuth(probe(&seen))(httptest.NewRecorder(), r)
		return seen.Role
	}
	cfg := proxyCfg([]string{"example.com"}, false)
	require.Equal(t, RoleViewer, signIn(cfg, "eve@example.com", "graph-admins"),
		"untrusted groups header is ignored, and a group mapping disables the bootstrap")

	cfg.TrustGroupsHeader = true
	require.Equal(t, RoleAdmin, signIn(cfg, "boss@example.com", "eng, graph-admins"))
	require.Equal(t, RoleAnalyst, signIn(cfg, "ana@example.com", "secops"))
}

func TestOAuth2Proxy_DomainMatchIsCaseInsensitive(t *testing.T) {
	h := NewHandler(NewService(newFakeRepo())).WithOAuth2Proxy(proxyCfg([]string{"Example.com"}, false))

	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, oauth2ProxyRequest("Dev@EXAMPLE.COM"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "dev@example.com", seen.Email)
}

// An existing admin keeps their role: the least-privilege default applies only
// to first sign-in, it is not a demotion on every request.
func TestOAuth2Proxy_ExistingUserKeepsRole(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.CreateUser(context.Background(), "boss@example.com", testPassword, RoleAdmin)
	require.NoError(t, err)
	h := NewHandler(svc).WithOAuth2Proxy(proxyCfg([]string{"example.com"}, false))

	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, oauth2ProxyRequest("boss@example.com"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, RoleAdmin, seen.Role)
}

// Without WithOAuth2Proxy the header is inert — it must not authenticate anyone.
func TestOAuth2Proxy_HeaderIgnoredWhenDisabled(t *testing.T) {
	svc := NewService(newFakeRepo())
	h := NewHandler(svc)

	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, oauth2ProxyRequest("stranger@example.com"))

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Zero(t, seen)
}

func TestLoginOAuth_RejectsInvalidAutoCreateRole(t *testing.T) {
	svc := NewService(newFakeRepo())
	_, _, err := svc.LoginOAuth(context.Background(), "x@example.com", Provisioning{Role: Role("superuser")})
	require.Error(t, err)
}

func TestPurgeExpiredSessions_DeletesOnlyExpired(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	ctx := context.Background()

	require.NoError(t, repo.CreateSession(ctx, "live", "u1", time.Now().Add(time.Hour)))
	require.NoError(t, repo.CreateSession(ctx, "dead1", "u1", time.Now().Add(-time.Hour)))
	require.NoError(t, repo.CreateSession(ctx, "dead2", "u2", time.Now().Add(-24*time.Hour)))

	n, err := svc.PurgeExpiredSessions(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 2, n)
	require.Len(t, repo.sessions, 1)
	require.Contains(t, repo.sessions, "live")

	// Idempotent: a second pass finds nothing left to delete.
	n, err = svc.PurgeExpiredSessions(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 0, n)
}

// An unset allowlist must DENY, not accept everything. Consider a plausible
// misconfiguration: OAUTH2_PROXY=true, OAUTH2_PROXY_ALLOWED_DOMAINS never set
// (a chart with no template to emit it), and no NetworkPolicy in a shared
// cluster — accept-all would let any pod mint a viewer session and reach
// run_cypher over the whole security graph plus the chat tool's live cloud
// reads. A credential path must not become permissive by omission.
func TestOAuth2Proxy_UnsetAllowlistDeniesRatherThanAcceptsEveryone(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	h := NewHandler(svc).WithOAuth2Proxy(proxyCfg(nil, false))

	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, oauth2ProxyRequest("attacker@evil.example"))

	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"an unset allowlist must not accept an arbitrary X-Auth-Request-Email")
	require.Empty(t, seen.Email, "no user may be provisioned from a denied header")
	require.Empty(t, repo.users, "a denied header must not create a user row")
}

// Accepting any domain stays possible, but only as a stated decision.
func TestOAuth2Proxy_AllowAnyDomainIsAnExplicitOptOut(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	h := NewHandler(svc).WithOAuth2Proxy(proxyCfg(nil, true))

	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, oauth2ProxyRequest("anyone@wherever.example"))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, RoleViewer, seen.Role, "even the opt-out provisions only a viewer")
}
