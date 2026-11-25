package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidOAuthState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cookie *string
		query  string
		want   bool
	}{
		{"matching", ptr("abc"), "abc", true},
		{"mismatch", ptr("abc"), "abd", false},
		{"no cookie", nil, "abc", false},
		{"no cookie and no state", nil, "", false},
		{"empty cookie and empty state", ptr(""), "", false},
		{"cookie but empty state", ptr("abc"), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/cb?state="+tc.query, nil)
			if tc.cookie != nil {
				req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: *tc.cookie})
			}
			require.Equal(t, tc.want, validOAuthState(req))
		})
	}
}

// An empty state cookie and an empty state parameter must not complete the
// callback (login CSRF: the attacker's code signs the victim in).
func TestOAuthCallback_RejectsEmptyState(t *testing.T) {
	h := NewHandler(NewService(newFakeRepo())).
		WithGoogleOAuth(&GoogleOAuthConfig{ClientID: "id", RedirectURL: "https://graph.example/cb"}).
		WithOktaOAuth(&OktaOAuthConfig{ClientID: "id", Domain: "dev.okta.com", RedirectURL: "https://graph.example/cb"})
	for name, handler := range map[string]http.HandlerFunc{"google": h.GoogleOAuthCallback, "okta": h.OktaOAuthCallback} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/auth/"+name+"/callback?state=&code=x", nil)
			req.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: ""})
			rec := httptest.NewRecorder()
			handler(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

func TestOAuthRedirectURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/google", nil)
	req.Host = "attacker.example"
	req.Header.Set("X-Forwarded-Proto", "https")

	require.Equal(t, "https://graph.example/cb", oauthRedirectURL(req, "https://graph.example/cb", true, "/x"))
	require.Empty(t, oauthRedirectURL(req, "", false, "/x"), "never derived from Host without the dev opt-in")
	require.Equal(t, "https://attacker.example/x", oauthRedirectURL(req, "", true, "/x"))
}

func TestOAuthConfigValidate(t *testing.T) {
	require.ErrorIs(t, GoogleOAuthConfig{}.Validate(), ErrRedirectURLRequired)
	require.ErrorIs(t, OktaOAuthConfig{}.Validate(), ErrRedirectURLRequired)
	require.ErrorIs(t, GoogleOAuthConfig{RedirectURL: "graph.example/cb"}.Validate(), ErrRedirectURLRequired)
	require.ErrorIs(t, OktaOAuthConfig{RedirectURL: "javascript:alert(1)"}.Validate(), ErrRedirectURLRequired)
	require.NoError(t, GoogleOAuthConfig{RedirectURL: "https://graph.example/cb"}.Validate())
	require.NoError(t, OktaOAuthConfig{RedirectFromHost: true}.Validate())
}

// A handler wired without a redirect URL (Validate skipped) refuses to start
// the flow rather than send the provider an empty redirect_uri.
func TestOAuthRedirect_UnconfiguredRedirectURL(t *testing.T) {
	h := NewHandler(NewService(newFakeRepo())).
		WithGoogleOAuth(&GoogleOAuthConfig{ClientID: "id"}).
		WithOktaOAuth(&OktaOAuthConfig{ClientID: "id", Domain: "dev.okta.com"})
	for name, handler := range map[string]http.HandlerFunc{"google": h.GoogleOAuthRedirect, "okta": h.OktaOAuthRedirect} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, "/api/auth/"+name, nil))
			require.Equal(t, http.StatusInternalServerError, rec.Code)
			require.Empty(t, rec.Result().Cookies())
		})
	}
}
