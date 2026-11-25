package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequireSession_APIKey_403(t *testing.T) {
	svc, _ := newTestService(t)
	a := &fakeAudit{}
	svc.WithAudit(a)
	h := NewHandler(svc)
	called := false
	next := func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) }

	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/connectors/{id}/mode", h.RequireSession(next))

	key := APIKeyRecord{ID: "key-1", UserID: "u1", Scope: "admin"}
	ctx := ContextWithAPIKey(ContextWithUser(context.Background(), User{ID: "u1", Email: "admin@example.com", Role: RoleAdmin}), key)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/connectors/c1/mode", nil).WithContext(ctx))

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.False(t, called)
	require.Equal(t, []auditRow{{AuditActionAPIKeyRefused, AuditTargetAPIKey, "key-1", "admin@example.com",
		map[string]any{"route": "PUT /api/connectors/{id}/mode"}}}, a.rows)

	rec = httptest.NewRecorder()
	sessionCtx := ContextWithUser(context.Background(), User{ID: "u1", Role: RoleAdmin})
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/connectors/c1/mode", nil).WithContext(sessionCtx))
	require.Equal(t, http.StatusNoContent, rec.Code, "a session passes")
	require.True(t, called)
}

func TestRolePolicy_Admits(t *testing.T) {
	cases := []struct {
		name     string
		required []string
		groups   []string
		want     bool
	}{
		{"no gate", nil, nil, true},
		{"member", []string{"vulngraph-users"}, []string{"eng", "Vulngraph-Users"}, true},
		{"non-member", []string{"vulngraph-users"}, []string{"eng"}, false},
		{"provider sends no groups", []string{"vulngraph-users"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, RolePolicy{RequiredGroups: tc.required}.Admits(tc.groups))
		})
	}
}

// oidcSignInRecorder runs completeOIDCSignIn with a fixed userinfo.
func oidcSignInRecorder(h *Handler, in oidcSignIn, info userInfo) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.completeOIDCSignIn(rec, httptest.NewRequest(http.MethodGet, "/api/auth/google/callback", nil), in, info)
	return rec
}

func TestGoogleSignIn_HostedDomain(t *testing.T) {
	google := oidcSignIn{provider: "google", issuer: googleIssuer, allowed: []string{"corp.example"}, checkHostedDomain: true}
	info := func(email, hd string) userInfo {
		return userInfo{Sub: "sub-" + email, Email: email, EmailVerified: true, HostedDomain: hd}
	}
	cases := []struct {
		name string
		in   oidcSignIn
		info userInfo
		want int
	}{
		{"Workspace account of the allowed domain", google, info("a@corp.example", "corp.example"), http.StatusSeeOther},
		{"hosted domain compared case-insensitively", google, info("b@corp.example", "Corp.Example"), http.StatusSeeOther},
		{"consumer account on a company address (no hd)", google, info("c@corp.example", ""), http.StatusForbidden},
		{"account managed by another Workspace", google, info("d@corp.example", "other.example"), http.StatusForbidden},
		{"allow-any without an allowlist has nothing to compare",
			oidcSignIn{provider: "google", issuer: googleIssuer, allowAny: true, checkHostedDomain: true},
			info("e@gmail.example", ""), http.StatusSeeOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo := newTestService(t)
			a := &fakeAudit{}
			svc.WithAudit(a)
			rec := oidcSignInRecorder(NewHandler(svc), tc.in, tc.info)
			require.Equal(t, tc.want, rec.Code)
			if tc.want == http.StatusForbidden {
				_, err := repo.GetUserCredentialsByEmail(context.Background(), tc.info.Email)
				require.ErrorIs(t, err, ErrNotFound, "a refused identity is not provisioned")
				failed := rowsWithAction(a.rows, AuditActionLoginFailed)
				require.Len(t, failed, 1)
				require.Equal(t, LoginReasonHostedDomain, failed[0].details["reason"])
				require.Equal(t, "google", failed[0].details["method"])
			}
		})
	}
}

func TestOIDCSignIn_RequiredGroups(t *testing.T) {
	okta := oidcSignIn{provider: "okta", issuer: "https://org.okta.example", allowed: []string{"corp.example"}}
	cases := []struct {
		name   string
		groups []string
		want   int
	}{
		{"member", []string{"vulngraph-users"}, http.StatusSeeOther},
		{"non-member", []string{"eng"}, http.StatusForbidden},
		{"no groups claim", nil, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			a := &fakeAudit{}
			svc.WithAudit(a)
			h := NewHandler(svc).WithRolePolicy(RolePolicy{RequiredGroups: []string{"vulngraph-users"}})
			rec := oidcSignInRecorder(h, okta, userInfo{Sub: "s1", Email: "a@corp.example", EmailVerified: true, Groups: tc.groups})
			require.Equal(t, tc.want, rec.Code)
			if tc.want == http.StatusForbidden {
				failed := rowsWithAction(a.rows, AuditActionLoginFailed)
				require.Len(t, failed, 1)
				require.Equal(t, LoginReasonGroupRequired, failed[0].details["reason"])
			}
		})
	}

	// The gate is not provisioning-only: an existing account outside the
	// groups is refused too.
	svc, _ := newTestService(t)
	h := NewHandler(svc).WithRolePolicy(RolePolicy{RequiredGroups: []string{"vulngraph-users"}})
	rec := oidcSignInRecorder(h, oidcSignIn{provider: "okta", issuer: "https://org.okta.example", allowed: []string{"example.com"}},
		userInfo{Sub: "s2", Email: "admin@example.com", EmailVerified: true, Groups: []string{"eng"}})
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestIAP_RequiredGroupsRefuseEverySignIn(t *testing.T) {
	h, repo, sign := iapHandler(t, []string{"corp.example"}, false)
	h.WithRolePolicy(RolePolicy{RequiredGroups: []string{"vulngraph-users"}})

	rec, _ := iapRequest(h, sign("alice@corp.example"))
	require.Equal(t, http.StatusForbidden, rec.Code, "IAP asserts no groups, so a required group admits nobody")
	_, err := repo.GetUserCredentialsByEmail(context.Background(), "alice@corp.example")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestOAuth2Proxy_RequiredGroups(t *testing.T) {
	cfg := proxyCfg([]string{"example.com"}, false)
	cfg.TrustGroupsHeader = true
	cases := []struct {
		name   string
		groups string
		want   int
	}{
		{"member", "eng,vulngraph-users", http.StatusOK},
		{"non-member", "eng", http.StatusForbidden},
		{"no groups header", "", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			h := NewHandler(svc).WithOAuth2Proxy(cfg).WithRolePolicy(RolePolicy{RequiredGroups: []string{"vulngraph-users"}})
			req := oauth2ProxyRequest("dev@example.com")
			if tc.groups != "" {
				req.Header.Set("X-Auth-Request-Groups", tc.groups)
			}
			var seen User
			rec := httptest.NewRecorder()
			h.RequireAuth(probe(&seen))(rec, req)
			require.Equal(t, tc.want, rec.Code)
		})
	}
}

func TestOktaRequestsGroupsScopeForRequiredGroups(t *testing.T) {
	h := NewHandler(nil).WithOktaOAuth(&OktaOAuthConfig{ClientID: "id", Domain: "org.okta.example", RedirectURL: "https://graph.example/api/auth/okta/callback"}).
		WithRolePolicy(RolePolicy{RequiredGroups: []string{"vulngraph-users"}})
	cfg := h.oktaOauthConfig(httptest.NewRequest(http.MethodGet, "/api/auth/okta", nil))
	require.Contains(t, cfg.Scopes, "groups")
}

// An SSO refusal that matched an account names it in target_id, as a password
// refusal does; the gates before the account lookup leave it empty.
func TestSSOSignInRefusal_NamesMatchedAccount(t *testing.T) {
	okta := oidcSignIn{provider: "okta", issuer: "https://org.okta.example", allowed: []string{"example.com"}}
	admin := func(sub string) userInfo {
		return userInfo{Sub: sub, Email: "admin@example.com", EmailVerified: true}
	}
	failedTarget := func(t *testing.T, a *fakeAudit, reason string) string {
		t.Helper()
		failed := rowsWithAction(a.rows, AuditActionLoginFailed)
		require.Len(t, failed, 1)
		require.Equal(t, reason, failed[0].details["reason"])
		return failed[0].targetID
	}

	t.Run("okta identity mismatch", func(t *testing.T) {
		svc, repo := newTestService(t)
		a := &fakeAudit{}
		svc.WithAudit(a)
		h := NewHandler(svc)
		require.Equal(t, http.StatusSeeOther, oidcSignInRecorder(h, okta, admin("s1")).Code)
		require.Equal(t, http.StatusForbidden, oidcSignInRecorder(h, okta, admin("s2")).Code)
		require.Equal(t, repo.users["admin@example.com"].ID, failedTarget(t, a, LoginReasonIdentityMismatch))
	})
	t.Run("okta disabled, bound and unbound", func(t *testing.T) {
		for _, bindFirst := range []bool{true, false} {
			svc, repo := newTestService(t)
			h := NewHandler(svc)
			if bindFirst {
				require.Equal(t, http.StatusSeeOther, oidcSignInRecorder(h, okta, admin("s1")).Code)
			}
			repo.disable("admin@example.com")
			a := &fakeAudit{}
			svc.WithAudit(a)
			require.Equal(t, http.StatusForbidden, oidcSignInRecorder(h, okta, admin("s1")).Code)
			require.Equal(t, repo.users["admin@example.com"].ID, failedTarget(t, a, LoginReasonDisabled))
		}
	})
	t.Run("okta domain refusal has no account", func(t *testing.T) {
		svc, _ := newTestService(t)
		a := &fakeAudit{}
		svc.WithAudit(a)
		h := NewHandler(svc)
		in := oidcSignIn{provider: "okta", issuer: "https://org.okta.example", allowed: []string{"corp.example"}}
		require.Equal(t, http.StatusForbidden, oidcSignInRecorder(h, in, admin("s1")).Code)
		require.Empty(t, failedTarget(t, a, LoginReasonDomainNotAllowed))
	})
	t.Run("iap disabled", func(t *testing.T) {
		h, repo, sign := iapHandler(t, []string{"corp.example"}, false)
		rec, _ := iapRequest(h, sign("alice@corp.example"))
		require.Equal(t, http.StatusOK, rec.Code)
		repo.disable("alice@corp.example")
		a := &fakeAudit{}
		h.svc.WithAudit(a)
		rec, _ = iapRequest(h, sign("alice@corp.example"))
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Equal(t, repo.users["alice@corp.example"].ID, failedTarget(t, a, LoginReasonDisabled))
	})
	t.Run("oauth2-proxy disabled", func(t *testing.T) {
		svc, repo := newTestService(t)
		repo.disable("admin@example.com")
		a := &fakeAudit{}
		svc.WithAudit(a)
		h := NewHandler(svc).WithOAuth2Proxy(proxyCfg([]string{"example.com"}, false))
		var seen User
		h.RequireAuth(probe(&seen))(httptest.NewRecorder(), oauth2ProxyRequest("admin@example.com"))
		require.Empty(t, seen.ID)
		require.Equal(t, repo.users["admin@example.com"].ID, failedTarget(t, a, LoginReasonDisabled))
	})
}
