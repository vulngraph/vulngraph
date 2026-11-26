package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIAP_ReplacesMismatchedSession(t *testing.T) {
	h, repo, sign := iapHandler(t, []string{"corp.example"}, false)
	first, admin := iapRequest(h, sign("admin@corp.example"))
	require.Equal(t, RoleAdmin, admin.Role)
	var cookie *http.Cookie
	for _, c := range first.Result().Cookies() {
		if c.Name == SessionCookie {
			cookie = c
		}
	}
	require.NotNil(t, cookie)
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(cookie)
	req.Header.Set(iapAssertionHeader, sign("different-person@corp.example"))
	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEqual(t, admin.ID, seen.ID)
	require.Equal(t, RoleViewer, seen.Role)
	_, err := repo.GetUserBySessionToken(context.Background(), hashToken(cookie.Value))
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestLogout_RevokesBearerSession(t *testing.T) {
	svc, _ := newTestService(t)
	token, err := svc.IssueToken(context.Background(), "admin@example.com")
	require.NoError(t, err)
	h := NewHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.RequireAuth(h.Logout)(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
	_, err = svc.Authenticate(context.Background(), token)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestOAuth2Proxy_ReplacesMismatchedSession(t *testing.T) {
	svc, _ := newTestService(t)
	old, err := svc.IssueToken(context.Background(), "admin@example.com")
	require.NoError(t, err)
	h := NewHandler(svc).WithOAuth2Proxy(proxyCfg([]string{"example.com"}, false))
	req := oauth2ProxyRequest("viewer@example.com")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: old})
	var seen User
	rec := httptest.NewRecorder()
	h.RequireAuth(probe(&seen))(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "viewer@example.com", seen.Email)
	require.Equal(t, RoleViewer, seen.Role)
	_, err = svc.Authenticate(context.Background(), old)
	require.ErrorIs(t, err, ErrUnauthenticated)
}

func TestUserAdministration_ConcurrentDemotionsKeepAnAdmin(t *testing.T) {
	ctx := context.Background()
	repo := newFakeRepo()
	a, err := repo.CreateUser(ctx, "a@example.com", "unused", RoleAdmin)
	require.NoError(t, err)
	b, err := repo.CreateUser(ctx, "b@example.com", "unused", RoleAdmin)
	require.NoError(t, err)
	svc := NewService(repo)
	viewer := RoleViewer
	start := make(chan struct{})
	outcomes := make(chan error, 2)
	for _, pair := range [][2]string{{a.ID, b.ID}, {b.ID, a.ID}} {
		go func(actor, target string) {
			defer func() {
				if p := recover(); p != nil {
					outcomes <- fmt.Errorf("panic: %v", p)
				}
			}()
			<-start
			_, err := svc.UpdateUser(ctx, actor, target, UserUpdate{Role: &viewer})
			outcomes <- err
		}(pair[0], pair[1])
	}
	close(start)
	first, second := <-outcomes, <-outcomes
	require.True(t, (first == nil && errors.Is(second, ErrLastAdmin)) || (second == nil && errors.Is(first, ErrLastAdmin)))
	count, err := repo.CountActiveAdmins(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}
