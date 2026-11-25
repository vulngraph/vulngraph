package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

const testIDTokenAudience = "oauth2-proxy-client"

// fakeIdP serves OIDC discovery and a JWKS, and signs ID tokens.
type fakeIdP struct {
	srv           *httptest.Server
	issuer        string // what discovery and tokens claim; srv.URL unless overridden
	jwksHits      atomic.Int32
	discoveryHits atomic.Int32
	down          atomic.Bool // discovery answers 503

	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey // kid → key published in the JWKS
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{keys: map[string]*rsa.PrivateKey{"rsa1": newRSAKey(t)}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		idp.discoveryHits.Add(1)
		if idp.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": idp.issuer, "jwks_uri": idp.srv.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		idp.jwksHits.Add(1)
		idp.mu.Lock()
		defer idp.mu.Unlock()
		var keys []map[string]string
		for kid, k := range idp.keys {
			keys = append(keys, map[string]string{
				"kid": kid, "kty": "RSA", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	idp.srv = httptest.NewServer(mux)
	idp.issuer = idp.srv.URL
	t.Cleanup(idp.srv.Close)
	return idp
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func (idp *fakeIdP) verifier() *idTokenVerifier {
	return newIDTokenVerifier(idp.issuer, testIDTokenAudience, false)
}

// signKid signs claims (after edit) with the key published under kid.
func (idp *fakeIdP) signKid(t *testing.T, kid string, edit func(jwt.MapClaims)) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": idp.issuer, "aud": testIDTokenAudience, "sub": "sub-alice",
		"email": "Alice@Corp.Example", "email_verified": true, "groups": []string{"graph-admins"},
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	}
	if edit != nil {
		edit(claims)
	}
	idp.mu.Lock()
	key := idp.keys[kid]
	idp.mu.Unlock()
	if key == nil {
		key = newRSAKey(t) // a kid the IdP does not publish
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	require.NoError(t, err)
	return s
}

func (idp *fakeIdP) sign(t *testing.T, edit func(jwt.MapClaims)) string {
	return idp.signKid(t, "rsa1", edit)
}

func TestIDTokenVerifier(t *testing.T) {
	idp := newFakeIdP(t)
	v := idp.verifier()
	ctx := context.Background()

	id, groups, err := v.Verify(ctx, idp.sign(t, nil))
	require.NoError(t, err)
	require.Equal(t, OIDCIdentity{Issuer: idp.issuer, Subject: "sub-alice", Email: "alice@corp.example"}, id)
	require.Equal(t, []string{"graph-admins"}, groups)

	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": idp.issuer, "aud": testIDTokenAudience, "sub": "x", "email": "admin@corp.example",
		"email_verified": true, "exp": time.Now().Add(time.Minute).Unix(),
	})
	forged.Header["kid"] = "rsa1"
	forgedRaw, err := forged.SignedString(newRSAKey(t))
	require.NoError(t, err)

	bad := map[string]string{
		"wrong signer":          forgedRaw,
		"wrong audience":        idp.sign(t, func(c jwt.MapClaims) { c["aud"] = "someone-else" }),
		"wrong issuer":          idp.sign(t, func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }),
		"issuer + slash":        idp.sign(t, func(c jwt.MapClaims) { c["iss"] = idp.issuer + "/" }),
		"expired":               idp.sign(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"no sub":                idp.sign(t, func(c jwt.MapClaims) { delete(c, "sub") }),
		"unverified email":      idp.sign(t, func(c jwt.MapClaims) { c["email_verified"] = false }),
		"no email_verified":     idp.sign(t, func(c jwt.MapClaims) { delete(c, "email_verified") }),
		"multi-aud, no azp":     idp.sign(t, func(c jwt.MapClaims) { c["aud"] = []string{testIDTokenAudience, "other"} }),
		"azp is another client": idp.sign(t, func(c jwt.MapClaims) { c["azp"] = "other" }),
		"alg none":              "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.",
	}
	for name, raw := range bad {
		_, _, err := v.Verify(ctx, raw)
		require.Error(t, err, name)
	}

	good := map[string]string{
		"multi-aud with our azp": idp.sign(t, func(c jwt.MapClaims) {
			c["aud"] = []string{testIDTokenAudience, "other"}
			c["azp"] = testIDTokenAudience
		}),
		"expired within the skew leeway": idp.sign(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-10 * time.Second).Unix() }),
		"email_verified as a string":     idp.sign(t, func(c jwt.MapClaims) { c["email_verified"] = "true" }),
	}
	for name, raw := range good {
		_, _, err := v.Verify(ctx, raw)
		require.NoError(t, err, name)
	}
}

// Auth0 issues with a trailing slash ("https://tenant.auth0.com/"); the
// configured issuer must be compared verbatim, not normalised.
func TestIDTokenVerifier_TrailingSlashIssuer(t *testing.T) {
	idp := newFakeIdP(t)
	idp.issuer = idp.srv.URL + "/"
	_, _, err := idp.verifier().Verify(context.Background(), idp.sign(t, nil))
	require.NoError(t, err)
}

// The opt-out accepts a token with no email_verified claim, never an
// explicit false.
func TestIDTokenVerifier_AllowUnverifiedEmailOptOut(t *testing.T) {
	idp := newFakeIdP(t)
	v := newIDTokenVerifier(idp.issuer, testIDTokenAudience, true)
	_, _, err := v.Verify(context.Background(), idp.sign(t, func(c jwt.MapClaims) { delete(c, "email_verified") }))
	require.NoError(t, err)
	_, _, err = v.Verify(context.Background(), idp.sign(t, func(c jwt.MapClaims) { c["email_verified"] = false }))
	require.ErrorIs(t, err, ErrEmailNotVerified)
}

// Discovery must name the configured issuer exactly.
func TestIDTokenVerifier_DiscoveryIssuerMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	v := idp.verifier()
	idp.issuer = "https://other.example"
	_, _, err := v.Verify(context.Background(), idp.sign(t, nil))
	require.ErrorContains(t, err, "does not match")
}

// Exact means exact: a discovery document whose issuer differs only by a
// trailing slash is another issuer string, and tokens would never match it.
func TestIDTokenVerifier_DiscoveryTrailingSlashMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	v := idp.verifier() // configured without the slash
	idp.issuer = idp.srv.URL + "/"
	_, _, err := v.Verify(context.Background(), idp.sign(t, nil))
	require.ErrorContains(t, err, "does not match")
}

// With no keys and a fetch that just failed, requests fail fast instead of
// each hammering the IdP; once the gap passes the fetch is retried.
func TestIDTokenVerifier_NoKeysBackoff(t *testing.T) {
	idp := newFakeIdP(t)
	v := idp.verifier()
	ctx := context.Background()
	idp.down.Store(true)

	_, _, err := v.Verify(ctx, idp.sign(t, nil))
	require.Error(t, err)
	require.EqualValues(t, 1, idp.discoveryHits.Load())
	for range 5 {
		_, _, err := v.Verify(ctx, idp.sign(t, nil))
		require.ErrorContains(t, err, "unavailable")
	}
	require.EqualValues(t, 1, idp.discoveryHits.Load(), "no refetch within the gap")

	idp.down.Store(false)
	v.mu.Lock()
	v.attempted = time.Now().Add(-2 * idTokenRefetchMinGap)
	v.mu.Unlock()
	_, _, err = v.Verify(ctx, idp.sign(t, nil))
	require.NoError(t, err, "retried after the gap")
}

// Unknown kids must not turn every request into a JWKS fetch, but a real key
// rotation is picked up once the refetch gap has passed.
func TestIDTokenVerifier_RefetchIsRateLimited(t *testing.T) {
	idp := newFakeIdP(t)
	v := idp.verifier()
	ctx := context.Background()

	_, _, err := v.Verify(ctx, idp.sign(t, nil))
	require.NoError(t, err)
	require.EqualValues(t, 1, idp.jwksHits.Load())

	for range 5 {
		_, _, err := v.Verify(ctx, idp.signKid(t, "unknown", nil))
		require.Error(t, err)
	}
	require.EqualValues(t, 1, idp.jwksHits.Load(), "unknown kids within the gap cause no fetch")

	idp.mu.Lock()
	idp.keys["rsa2"] = newRSAKey(t)
	idp.mu.Unlock()
	v.mu.Lock()
	v.attempted = time.Now().Add(-2 * idTokenRefetchMinGap)
	v.mu.Unlock()
	_, _, err = v.Verify(ctx, idp.signKid(t, "rsa2", nil))
	require.NoError(t, err, "the rotated key is fetched after the gap")
	require.EqualValues(t, 2, idp.jwksHits.Load())
}

// A client that hangs up mid-fetch must not poison the key cache: the fetch
// runs on its own context.
func TestIDTokenVerifier_FetchSurvivesRequestCancellation(t *testing.T) {
	idp := newFakeIdP(t)
	v := idp.verifier()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := v.Verify(ctx, idp.sign(t, nil))
	require.NoError(t, err)
}

func TestValidateOIDCIssuer(t *testing.T) {
	for _, ok := range []string{"https://accounts.google.com", "https://tenant.auth0.com/", "http://127.0.0.1:5556/dex", "http://localhost:8080"} {
		require.NoError(t, ValidateOIDCIssuer(ok), ok)
	}
	for _, bad := range []string{"http://dex.auth.svc:5556", "ftp://idp.example", "idp.example", ""} {
		require.Error(t, ValidateOIDCIssuer(bad), bad)
	}
	_, _, err := newIDTokenVerifier("http://idp.example", testIDTokenAudience, false).Verify(context.Background(), "x.y.z")
	require.ErrorContains(t, err, "https")
}

func idTokenHandler(t *testing.T, idp *fakeIdP) (*Handler, *fakeRepo) {
	t.Helper()
	svc, repo := newTestService(t) // admin@example.com exists as admin
	h := NewHandler(svc).
		WithOAuth2Proxy(OAuth2ProxyConfig{
			OIDCIssuer: idp.issuer, OIDCAudience: testIDTokenAudience, SharedSecret: testProxySecret,
			AllowedDomains: []string{"corp.example", "example.com"},
		}).
		WithRolePolicy(RolePolicy{AdminGroups: []string{"graph-admins"}})
	return h, repo
}

func callAuth(h *Handler, r *http.Request) (*httptest.ResponseRecorder, User) {
	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, r)
	return rec, seen
}

func withIDToken(raw string) *http.Request {
	r := oauth2ProxyRequest("admin@example.com") // header claims the admin; ignored
	r.Header.Set("Authorization", "Bearer "+raw)
	return r
}

// ID-token mode: identity and groups come only from the verified token, so a
// forged X-Auth-Request-Email or groups header — even with the shared secret
// someone read from /oauth2/auth — proves nothing.
func TestOAuth2Proxy_IDTokenMode(t *testing.T) {
	idp := newFakeIdP(t)
	h, repo := idTokenHandler(t, idp)

	rec, seen := callAuth(h, oauth2ProxyRequest("admin@example.com"))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Zero(t, seen)

	rec, seen = callAuth(h, withIDToken(idp.sign(t, nil)))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "alice@corp.example", seen.Email, "identity comes from the token, not the header")
	require.Equal(t, RoleAdmin, seen.Role, "groups from the verified token")
	require.Equal(t, "sub-alice", repo.users["alice@corp.example"].OIDCSubject, "bound like an OIDC sign-in")

	rec, _ = callAuth(h, withIDToken(idp.sign(t, func(c jwt.MapClaims) { c["aud"] = "other" })))
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	noSecret := withIDToken(idp.sign(t, func(c jwt.MapClaims) { c["sub"] = "sub-bob"; c["email"] = "bob@corp.example" }))
	noSecret.Header.Del(OAuth2ProxySecretHeader)
	rec, _ = callAuth(h, noSecret)
	require.Equal(t, http.StatusUnauthorized, rec.Code, "a configured shared secret is still required")
}

// ID-token-only mode needs no shared secret, and a token alone (no email
// header) is enough to sign in.
func TestOAuth2Proxy_IDTokenOnly(t *testing.T) {
	idp := newFakeIdP(t)
	svc, _ := newTestService(t)
	h := NewHandler(svc).WithOAuth2Proxy(OAuth2ProxyConfig{
		OIDCIssuer: idp.issuer, OIDCAudience: testIDTokenAudience, AllowedDomains: []string{"corp.example"},
	})
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.Header.Set("Authorization", "Bearer "+idp.sign(t, func(c jwt.MapClaims) { delete(c, "groups") }))
	rec, seen := callAuth(h, r)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, RoleViewer, seen.Role)
	require.NotEmpty(t, rec.Result().Cookies(), "a session is issued so later requests need no token")
}

// sessionCookieFrom returns the session cookie a sign-in response set.
func sessionCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatal("no session cookie set")
	return nil
}

// The session cookie used to win unconditionally. Now: same identity keeps
// the session; a token for another person replaces it (shared browser); an
// expired token keeps a valid session; a dead session falls back to the token.
func TestOAuth2Proxy_IDTokenAndSession(t *testing.T) {
	idp := newFakeIdP(t)
	h, repo := idTokenHandler(t, idp)
	alice := idp.sign(t, nil)
	bob := idp.sign(t, func(c jwt.MapClaims) { c["sub"] = "sub-bob"; c["email"] = "bob@corp.example"; delete(c, "groups") })

	rec, _ := callAuth(h, withIDToken(alice))
	require.Equal(t, http.StatusOK, rec.Code)
	aliceCookie := sessionCookieFrom(t, rec)

	r := withIDToken(alice)
	r.AddCookie(aliceCookie)
	rec, seen := callAuth(h, r)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "alice@corp.example", seen.Email)
	require.Empty(t, rec.Result().Cookies(), "same identity: the session is kept, no new one")

	r = withIDToken(idp.sign(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }))
	r.AddCookie(aliceCookie)
	rec, seen = callAuth(h, r)
	require.Equal(t, http.StatusOK, rec.Code, "an expired token does not end a valid session")
	require.Equal(t, "alice@corp.example", seen.Email)

	sessionsBefore := len(repo.sessions)
	r = withIDToken(bob)
	r.AddCookie(aliceCookie)
	rec, seen = callAuth(h, r)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "bob@corp.example", seen.Email, "the proxy's current user wins")
	require.Equal(t, RoleViewer, seen.Role)
	sessionCookieFrom(t, rec)
	require.Len(t, repo.sessions, sessionsBefore, "alice's session was ended, bob's started")

	r = withIDToken(alice)
	r.AddCookie(aliceCookie) // ended above
	rec, seen = callAuth(h, r)
	require.Equal(t, http.StatusOK, rec.Code, "a dead session falls back to the token")
	require.Equal(t, "alice@corp.example", seen.Email)
}

// Binding an existing, unbound account by the email claim is the step an IdP
// letting users choose their address could abuse; it must still require a
// verified email (covered above) and leaves the account bound to that subject.
// "Same identity" means the session user's BOUND (issuer, sub), not a matching
// email and not "some identity is bound".
func TestOAuth2Proxy_IDTokenSessionComparesBinding(t *testing.T) {
	idp := newFakeIdP(t)
	h, repo := idTokenHandler(t, idp)
	alice := idp.sign(t, nil)
	bob := idp.sign(t, func(c jwt.MapClaims) { c["sub"] = "sub-bob"; c["email"] = "bob@corp.example"; delete(c, "groups") })

	rec, _ := callAuth(h, withIDToken(bob)) // bob signs in first: his identity is bound
	require.Equal(t, http.StatusOK, rec.Code)
	rec, _ = callAuth(h, withIDToken(alice))
	aliceCookie := sessionCookieFrom(t, rec)

	// (a) alice's session + bob's already-bound token → bob, alice's session ended.
	r := withIDToken(bob)
	r.AddCookie(aliceCookie)
	rec, seen := callAuth(h, r)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "bob@corp.example", seen.Email)
	_, err := h.svc.Authenticate(context.Background(), aliceCookie.Value)
	require.ErrorIs(t, err, ErrUnauthenticated, "alice's session was ended")

	// (b) a fresh alice session + a token with alice's email but another sub:
	// not alice, so her session is not kept, and the account refuses the
	// foreign subject.
	rec, _ = callAuth(h, withIDToken(alice))
	aliceCookie = sessionCookieFrom(t, rec)
	impostor := idp.sign(t, func(c jwt.MapClaims) { c["sub"] = "sub-impostor" })
	r = withIDToken(impostor)
	r.AddCookie(aliceCookie)
	rec, seen = callAuth(h, r)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Zero(t, seen)
	_, err = h.svc.Authenticate(context.Background(), aliceCookie.Value)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.Equal(t, "sub-alice", repo.users["alice@corp.example"].OIDCSubject)
}

// A store error while comparing the token with the session is not "a
// different person": the session must survive and the request gets 500.
func TestOAuth2Proxy_IDTokenSessionStoreErrorKeepsSession(t *testing.T) {
	idp := newFakeIdP(t)
	h, repo := idTokenHandler(t, idp)
	alice := idp.sign(t, nil)
	rec, _ := callAuth(h, withIDToken(alice))
	aliceCookie := sessionCookieFrom(t, rec)

	repo.oidcLookupErr = errors.New("db blip")
	r := withIDToken(alice)
	r.AddCookie(aliceCookie)
	rec, _ = callAuth(h, r)
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	repo.oidcLookupErr = nil
	_, err := h.svc.Authenticate(context.Background(), aliceCookie.Value)
	require.NoError(t, err, "the session was not ended")
}

// Binding an existing account by email logs a SECURITY line naming it; a
// freshly provisioned account does not.
func TestLoginOIDC_LogsBindingOfExistingAccount(t *testing.T) {
	var buf bytes.Buffer
	prev := zlog.Logger
	zlog.Logger = zerolog.New(&buf)
	t.Cleanup(func() { zlog.Logger = prev })

	svc, _ := newTestService(t) // admin@example.com exists, unbound
	ctx := context.Background()
	_, _, err := svc.LoginOIDC(ctx, OIDCIdentity{Issuer: "https://idp", Subject: "new", Email: "new@example.com"}, Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	require.NotContains(t, buf.String(), "bound to an SSO identity by email")

	_, _, err = svc.LoginOIDC(ctx, OIDCIdentity{Issuer: "https://idp", Subject: "s", Email: "admin@example.com"}, Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	out := buf.String()
	require.Contains(t, out, "SECURITY: existing account bound to an SSO identity by email")
	require.Contains(t, out, `"email":"admin@example.com"`)
	require.Contains(t, out, `"role":"admin"`)
}

func TestOAuth2Proxy_IDTokenBindsExistingAccountOnce(t *testing.T) {
	idp := newFakeIdP(t)
	h, repo := idTokenHandler(t, idp)
	admin := idp.sign(t, func(c jwt.MapClaims) { c["sub"] = "sub-admin"; c["email"] = "admin@example.com" })
	rec, seen := callAuth(h, withIDToken(admin))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, RoleAdmin, seen.Role)
	require.Equal(t, "sub-admin", repo.users["admin@example.com"].OIDCSubject)

	other := idp.sign(t, func(c jwt.MapClaims) { c["sub"] = "sub-mallory"; c["email"] = "admin@example.com" })
	rec, _ = callAuth(h, withIDToken(other))
	require.Equal(t, http.StatusForbidden, rec.Code, "a second subject with the same email is refused")
}
