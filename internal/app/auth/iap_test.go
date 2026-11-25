package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const testIAPAudience = "/projects/1/global/backendServices/2"

// iapHandler returns a handler whose IAP validator trusts a local key, plus a
// function that signs an assertion for an email.
func iapHandler(t *testing.T, domains []string, allowAny bool) (*Handler, *fakeRepo, func(email string, edit ...func(*iapClaims)) string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	repo := newFakeRepo()
	h := NewHandler(NewService(repo)).WithIAP(testIAPAudience, domains, allowAny)
	h.iap.keys = map[string]*ecdsa.PublicKey{"k": &priv.PublicKey}
	h.iap.fetched = time.Now()
	sign := func(email string, edit ...func(*iapClaims)) string {
		claims := iapClaims{
			Email: email,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    iapIssuer,
				Subject:   "accounts.google.com:" + email,
				Audience:  jwt.ClaimStrings{testIAPAudience},
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			},
		}
		for _, e := range edit {
			e(&claims)
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tok.Header["kid"] = "k"
		s, err := tok.SignedString(priv)
		require.NoError(t, err)
		return s
	}
	return h, repo, sign
}

func iapRequest(h *Handler, assertion string) (*httptest.ResponseRecorder, User) {
	var seen User
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("X-Goog-IAP-JWT-Assertion", assertion)
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, req)
	return rec, seen
}

// IAP used to provision ANY asserted email as admin, then every allowlisted
// one. Now only the first sign-in on an empty install is admin.
func TestIAP_DomainAllowlistAndRoles(t *testing.T) {
	h, repo, sign := iapHandler(t, []string{"corp.example"}, false)

	rec, seen := iapRequest(h, sign("alice@corp.example"))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, RoleAdmin, seen.Role, "the first sign-in on an empty install bootstraps the admin")

	rec, seen = iapRequest(h, sign("bob@corp.example"))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, RoleViewer, seen.Role, "an allowlisted domain alone no longer provisions admin")

	rec, _ = iapRequest(h, sign("eve@gmail.com"))
	require.Equal(t, http.StatusForbidden, rec.Code)
	_, err := repo.GetUserCredentialsByEmail(context.Background(), "eve@gmail.com")
	require.ErrorIs(t, err, ErrNotFound, "a refused identity is not provisioned")

	none, _, signNone := iapHandler(t, nil, false)
	rec, _ = iapRequest(none, signNone("alice@corp.example"))
	require.Equal(t, http.StatusForbidden, rec.Code, "an empty allowlist denies")

	anyH, _, signAny := iapHandler(t, nil, true)
	rec, seen = iapRequest(anyH, signAny("eve@gmail.com"))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, RoleViewer, seen.Role, "allow-any provisions viewer")
}

// Google requires checking iss: the key set alone does not pin a token to IAP.
func TestIAP_RejectsWrongIssuerAndMissingSubject(t *testing.T) {
	h, repo, sign := iapHandler(t, []string{"corp.example"}, false)

	rec, _ := iapRequest(h, sign("alice@corp.example", func(c *iapClaims) { c.Issuer = "https://evil.example" }))
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	rec, _ = iapRequest(h, sign("alice@corp.example", func(c *iapClaims) { c.Subject = "" }))
	require.Equal(t, http.StatusUnauthorized, rec.Code, "an assertion without sub cannot be bound")
	require.Empty(t, repo.users)
}

// IAP sign-in binds (issuer, sub) like OIDC: a different IAP subject later
// asserting the same email (a recycled address) does not get the account.
func TestIAP_BindsIdentity(t *testing.T) {
	h, repo, sign := iapHandler(t, []string{"corp.example"}, false)

	rec, first := iapRequest(h, sign("alice@corp.example"))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, iapIssuer, repo.users["alice@corp.example"].OIDCIssuer)
	require.Equal(t, "accounts.google.com:alice@corp.example", repo.users["alice@corp.example"].OIDCSubject)

	rec, _ = iapRequest(h, sign("alice@corp.example", func(c *iapClaims) { c.Subject = "accounts.google.com:other" }))
	require.Equal(t, http.StatusForbidden, rec.Code)

	rec, again := iapRequest(h, sign("Alice.Renamed@corp.example", func(c *iapClaims) {
		c.Subject = "accounts.google.com:alice@corp.example"
	}))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, first.ID, again.ID, "the bound subject keeps its account across an email change")
}

func TestPasswordLogin_DisabledBehindProxyUnlessBreakGlass(t *testing.T) {
	login := func(h *Handler) int {
		body := `{"email":"admin@example.com","password":"` + testPassword + `"}`
		rec := httptest.NewRecorder()
		h.Login(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body)))
		return rec.Code
	}
	providers := func(h *Handler) []string {
		rec := httptest.NewRecorder()
		h.Providers(rec, httptest.NewRequest(http.MethodGet, "/api/auth/providers", nil))
		var items []struct{ ID string }
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &items))
		var ids []string
		for _, i := range items {
			ids = append(ids, i.ID)
		}
		return ids
	}

	h, _ := newTestHandler(t)
	require.Equal(t, http.StatusOK, login(h))
	require.Contains(t, providers(h), "password")

	h, _ = newTestHandler(t)
	h.WithOAuth2Proxy(proxyCfg([]string{"example.com"}, false))
	require.Equal(t, http.StatusNotFound, login(h), "oauth2-proxy mode: no password door")
	require.NotContains(t, providers(h), "password")

	h, _ = newTestHandler(t)
	h.WithIAP(testIAPAudience, []string{"example.com"}, false)
	require.Equal(t, http.StatusNotFound, login(h), "IAP mode: no password door")

	h.WithPasswordBreakGlass(true)
	require.Equal(t, http.StatusOK, login(h), "explicit break-glass keeps it")
	require.Contains(t, providers(h), "password")
}
