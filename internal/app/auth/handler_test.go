package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestHandler returns a handler whose service is seeded with an admin and
// a viewer, plus a login helper returning the session cookie.
func newTestHandler(t *testing.T) (*Handler, func(email string) *http.Cookie) {
	t.Helper()
	repo := newFakeRepo()
	svc := NewService(repo)
	for email, role := range map[string]Role{
		"admin@example.com":  RoleAdmin,
		"viewer@example.com": RoleViewer,
	} {
		_, err := svc.CreateUser(context.Background(), email, testPassword, role)
		require.NoError(t, err)
	}
	h := NewHandler(svc)

	login := func(email string) *http.Cookie {
		token, _, err := svc.Login(context.Background(), email, testPassword, "")
		require.NoError(t, err)
		return &http.Cookie{Name: SessionCookie, Value: token}
	}
	return h, login
}

func TestLoginHandler_SetsHttpOnlyCookie(t *testing.T) {
	h, _ := newTestHandler(t)

	body := `{"email":"admin@example.com","password":"` + testPassword + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, SessionCookie, cookies[0].Name)
	require.True(t, cookies[0].HttpOnly)
	require.True(t, cookies[0].Secure)
	require.NotEmpty(t, cookies[0].Value)
}

func TestLoginHandler_BadCredentials_401(t *testing.T) {
	h, _ := newTestHandler(t)

	body := `{"email":"admin@example.com","password":"totally-wrong-pw"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Empty(t, rec.Result().Cookies())
}

func TestMe_WithoutSession_401(t *testing.T) {
	h, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	rec := httptest.NewRecorder()
	h.RequireAuth(h.Me)(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestMe_WithSession_ReturnsUser(t *testing.T) {
	h, login := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(login("admin@example.com"))
	rec := httptest.NewRecorder()
	h.RequireAuth(h.Me)(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "admin@example.com", got["email"])
	require.Equal(t, "admin", got["role"])
}

func TestRequireAuth_BearerToken_ResolvesUser(t *testing.T) {
	h, _ := newTestHandler(t)

	token, err := h.svc.IssueToken(context.Background(), "admin@example.com")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.RequireAuth(h.Me)(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "admin@example.com", got["email"])
}

func TestRequireAuth_BearerToken_InvalidIs401(t *testing.T) {
	h, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	h.RequireAuth(h.Me)(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireAuth_CookieTakesPrecedenceOverBearer(t *testing.T) {
	h, login := newTestHandler(t)

	// A valid admin cookie alongside a garbage Bearer header: the cookie wins.
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(login("admin@example.com"))
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	h.RequireAuth(h.Me)(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

func TestCreateUser_NonAdmin_403(t *testing.T) {
	h, login := newTestHandler(t)

	body := `{"email":"new@example.com","password":"long-enough-password","role":"viewer"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	req.AddCookie(login("viewer@example.com"))
	rec := httptest.NewRecorder()
	h.RequireAuth(RequireRole(RoleAdmin, h.CreateUser))(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCreateUser_AsAdmin_201(t *testing.T) {
	h, login := newTestHandler(t)

	body := `{"email":"new@example.com","password":"long-enough-password","role":"analyst"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(body))
	req.AddCookie(login("admin@example.com"))
	rec := httptest.NewRecorder()
	h.RequireAuth(RequireRole(RoleAdmin, h.CreateUser))(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	var got map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "analyst", got["role"])
}

func TestLogout_ClearsCookieAndSession(t *testing.T) {
	h, login := newTestHandler(t)
	cookie := login("admin@example.com")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.RequireAuth(h.Logout)(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)

	// The session is gone: the same cookie no longer authenticates.
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.RequireAuth(h.Me)(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// oauthStateCookieFrom runs an OAuth redirect handler and returns the state
// cookie it set.
func oauthStateCookieFrom(t *testing.T, handler http.HandlerFunc, req *http.Request) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	handler(rec, req)
	require.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthStateCookie {
			return c
		}
	}
	require.FailNow(t, "no OAuth state cookie set")
	return nil
}

// Every cookie is Secure by default, and a client-supplied
// X-Forwarded-Proto: http must not downgrade it.
func TestCookies_SecureByDefault_IgnoresForwardedProto(t *testing.T) {
	t.Setenv(CookieInsecureEnv, "")
	h := NewHandler(NewService(newFakeRepo())).
		WithGoogleOAuth(&GoogleOAuthConfig{ClientID: "id", RedirectURL: "https://graph.example/cb"}).
		WithOktaOAuth(&OktaOAuthConfig{ClientID: "id", Domain: "dev.okta.com", RedirectURL: "https://graph.example/cb"})

	for name, handler := range map[string]http.HandlerFunc{"google": h.GoogleOAuthRedirect, "okta": h.OktaOAuthRedirect} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/auth/"+name, nil)
			req.Header.Set("X-Forwarded-Proto", "http")
			c := oauthStateCookieFrom(t, handler, req)
			require.True(t, c.Secure)
			require.True(t, c.HttpOnly)
		})
	}
	require.True(t, h.sessionCookie("tok", sessionTTL).Secure)
	require.True(t, h.cookie(oauthStateCookie, "", -1).Secure, "clearing cookies must match the attributes they clear")
}

func TestCookies_InsecureOnlyWithExplicitEnv(t *testing.T) {
	for val, wantSecure := range map[string]bool{"": true, "1": true, "yes": true, "TRUE": true, "true": false} {
		t.Setenv(CookieInsecureEnv, val)
		require.Equal(t, wantSecure, NewHandler(nil).sessionCookie("tok", sessionTTL).Secure, "value %q", val)
		require.Equal(t, wantSecure, NewHandlerBypass().sessionCookie("tok", sessionTTL).Secure, "bypass, value %q", val)
	}
}

func TestLoginHandler_CookieInsecureEnv_DropsSecure(t *testing.T) {
	t.Setenv(CookieInsecureEnv, "true")
	h, _ := newTestHandler(t)

	body := `{"email":"admin@example.com","password":"` + testPassword + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	h.Login(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.False(t, cookies[0].Secure)
	require.True(t, cookies[0].HttpOnly)
}

// Only BYPASS_AUTH's synthetic admin is marked as bypass: the executor refuses
// changes on the mark, so a signed-in user must never carry it.
func TestBypassFromContext_MarksOnlyTheSyntheticAdmin(t *testing.T) {
	seen := func(h *Handler, req *http.Request) bool {
		var got, ran bool
		h.RequireAuth(func(_ http.ResponseWriter, r *http.Request) {
			ran = true
			got = BypassFromContext(r.Context())
		})(httptest.NewRecorder(), req)
		require.True(t, ran, "the request must reach the handler")
		return got
	}

	require.True(t, seen(NewHandlerBypass(), httptest.NewRequest(http.MethodGet, "/api/x", nil)))

	h, login := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.AddCookie(login("admin@example.com"))
	require.False(t, seen(h, req))
	require.False(t, BypassFromContext(context.Background()))
}

// A bypass handler has no Service; endpoints that need one must answer cleanly
// instead of panicking on a nil dereference.
func TestBypassHandler_ServiceEndpointsDoNotPanic(t *testing.T) {
	h := NewHandlerBypass().
		WithGoogleOAuth(&GoogleOAuthConfig{ClientID: "id", RedirectURL: "https://graph.example/cb", AllowedDomains: []string{"x.example"}}).
		WithOktaOAuth(&OktaOAuthConfig{ClientID: "id", Domain: "dev.okta.com", RedirectURL: "https://graph.example/cb", AllowedDomains: []string{"x.example"}})

	cases := map[string]struct {
		handler http.HandlerFunc
		method  string
		want    int
	}{
		"logout":          {h.RequireAuth(h.Logout), http.MethodPost, http.StatusNoContent},
		"google redirect": {h.GoogleOAuthRedirect, http.MethodGet, http.StatusNotFound},
		"google callback": {h.GoogleOAuthCallback, http.MethodGet, http.StatusNotFound},
		"okta redirect":   {h.OktaOAuthRedirect, http.MethodGet, http.StatusNotFound},
		"okta callback":   {h.OktaOAuthCallback, http.MethodGet, http.StatusNotFound},
		"list users":      {h.RequireAuth(h.ListUsers), http.MethodGet, http.StatusNotFound},
		"create users":    {h.RequireAuth(h.CreateUser), http.MethodPost, http.StatusNotFound},
		"update user":     {h.RequireAuth(h.UpdateUser), http.MethodPatch, http.StatusNotFound},
		"delete user":     {h.RequireAuth(h.DeleteUser), http.MethodDelete, http.StatusNotFound},
		"revoke sessions": {h.RequireAuth(h.RevokeUserSessions), http.MethodPost, http.StatusNotFound},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/x?state=s&code=c", strings.NewReader(`{}`))
			req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "tok"})
			req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "s"})
			rec := httptest.NewRecorder()
			require.NotPanics(t, func() { tc.handler(rec, req) })
			require.Equal(t, tc.want, rec.Code)
		})
	}
}
