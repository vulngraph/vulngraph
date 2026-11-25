package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func (f *fakeRepo) byID(id string) (string, UserCredentials, bool) {
	for email, c := range f.users {
		if c.ID == id {
			return email, c, true
		}
	}
	return "", UserCredentials{}, false
}

func (f *fakeRepo) GetUserByID(_ context.Context, id string) (User, error) {
	if _, c, ok := f.byID(id); ok {
		return c.User, nil
	}
	return User{}, ErrNotFound
}

func (f *fakeRepo) SetUserRole(ctx context.Context, id string, role Role, revokeSessions bool) (int64, error) {
	return f.updateUser(ctx, id, revokeSessions, func(c *UserCredentials) { c.Role = role })
}

func (f *fakeRepo) SetUserDisabledAt(ctx context.Context, id string, t *time.Time, revokeSessions bool) (int64, error) {
	return f.updateUser(ctx, id, revokeSessions, func(c *UserCredentials) { c.DisabledAt = t })
}

// updateUser mirrors PGRepo's transaction: on userWriteErr nothing changes.
func (f *fakeRepo) updateUser(ctx context.Context, id string, revokeSessions bool, update func(*UserCredentials)) (int64, error) {
	if f.userWriteErr != nil {
		return 0, f.userWriteErr
	}
	email, c, ok := f.byID(id)
	if !ok {
		return 0, ErrNotFound
	}
	update(&c)
	f.users[email] = c
	if !revokeSessions {
		return 0, nil
	}
	return f.DeleteUserSessions(ctx, id)
}

func (f *fakeRepo) DeleteUser(_ context.Context, id string) error {
	email, _, ok := f.byID(id)
	if !ok {
		return ErrNotFound
	}
	delete(f.users, email)
	_, _ = f.DeleteUserSessions(context.Background(), id)
	return nil
}

func (f *fakeRepo) DeleteUserSessions(_ context.Context, userID string) (int64, error) {
	var n int64
	for h, s := range f.sessions {
		if s.userID == userID {
			delete(f.sessions, h)
			n++
		}
	}
	return n, nil
}

func (f *fakeRepo) CountActiveAdmins(_ context.Context) (int64, error) {
	var n int64
	for _, c := range f.users {
		if c.Role == RoleAdmin && c.DisabledAt == nil {
			n++
		}
	}
	return n, nil
}

func ptr[T any](v T) *T { return &v }

// userAdminFixture seeds two admins and a viewer with uuid ids.
func userAdminFixture(t *testing.T) (*Service, *fakeRepo, map[string]string) {
	t.Helper()
	repo := newFakeRepo()
	svc := NewService(repo)
	ids := map[string]string{}
	for email, role := range map[string]Role{"a1@x.example": RoleAdmin, "a2@x.example": RoleAdmin, "v@x.example": RoleViewer} {
		_, err := svc.CreateUser(context.Background(), email, testPassword, role)
		require.NoError(t, err)
		c := repo.users[email]
		c.ID = uuid.NewString()
		repo.users[email] = c
		ids[email] = c.ID
	}
	return svc, repo, ids
}

func TestUpdateUser_DisableEndsSessionsAndEnableRestores(t *testing.T) {
	svc, repo, ids := userAdminFixture(t)
	ctx := context.Background()
	token, _, err := svc.Login(ctx, "v@x.example", testPassword, "")
	require.NoError(t, err)

	u, err := svc.UpdateUser(ctx, ids["a1@x.example"], ids["v@x.example"], UserUpdate{Disabled: ptr(true)})
	require.NoError(t, err)
	require.NotNil(t, u.DisabledAt)
	require.Empty(t, repo.sessions, "disabling deletes the user's sessions")
	_, err = svc.Authenticate(ctx, token)
	require.ErrorIs(t, err, ErrUnauthenticated)

	u, err = svc.UpdateUser(ctx, ids["a1@x.example"], ids["v@x.example"], UserUpdate{Disabled: ptr(false)})
	require.NoError(t, err)
	require.Nil(t, u.DisabledAt)
	_, _, err = svc.Login(ctx, "v@x.example", testPassword, "")
	require.NoError(t, err)
}

func TestUpdateUser_Guards(t *testing.T) {
	svc, _, ids := userAdminFixture(t)
	ctx := context.Background()
	a1, a2, v := ids["a1@x.example"], ids["a2@x.example"], ids["v@x.example"]

	_, err := svc.UpdateUser(ctx, a1, a1, UserUpdate{Role: ptr(RoleViewer)})
	require.ErrorIs(t, err, ErrSelfAction)
	_, err = svc.UpdateUser(ctx, a1, a1, UserUpdate{Disabled: ptr(true)})
	require.ErrorIs(t, err, ErrSelfAction)
	require.ErrorIs(t, svc.DeleteUser(ctx, a1, a1), ErrSelfAction)
	_, err = svc.RevokeSessions(ctx, a1, a1)
	require.ErrorIs(t, err, ErrSelfAction)

	_, err = svc.UpdateUser(ctx, a1, v, UserUpdate{Role: ptr(Role("root"))})
	require.ErrorIs(t, err, ErrInvalidRole)
	_, err = svc.UpdateUser(ctx, a1, uuid.NewString(), UserUpdate{Role: ptr(RoleViewer)})
	require.ErrorIs(t, err, ErrNotFound)

	// Two admins: demoting one is fine; the survivor is then the last admin.
	u, err := svc.UpdateUser(ctx, a1, a2, UserUpdate{Role: ptr(RoleAnalyst)})
	require.NoError(t, err)
	require.Equal(t, RoleAnalyst, u.Role)
	_, err = svc.UpdateUser(ctx, a2, a1, UserUpdate{Role: ptr(RoleViewer)})
	require.ErrorIs(t, err, ErrLastAdmin)
	_, err = svc.UpdateUser(ctx, a2, a1, UserUpdate{Disabled: ptr(true)})
	require.ErrorIs(t, err, ErrLastAdmin)
	require.ErrorIs(t, svc.DeleteUser(ctx, a2, a1), ErrLastAdmin)
}

func TestDeleteUserAndRevokeSessions(t *testing.T) {
	svc, repo, ids := userAdminFixture(t)
	ctx := context.Background()
	for range 2 {
		_, _, err := svc.Login(ctx, "v@x.example", testPassword, "")
		require.NoError(t, err)
	}
	n, err := svc.RevokeSessions(ctx, ids["a1@x.example"], ids["v@x.example"])
	require.NoError(t, err)
	require.Equal(t, int64(2), n)

	require.NoError(t, svc.DeleteUser(ctx, ids["a1@x.example"], ids["v@x.example"]))
	_, ok := repo.users["v@x.example"]
	require.False(t, ok)
	require.ErrorIs(t, svc.DeleteUser(ctx, ids["a1@x.example"], ids["v@x.example"]), ErrNotFound)
}

// userAdminRequest runs an admin route through RequireAuth + RequireRole as
// the router does, authenticated as asEmail.
func userAdminRequest(t *testing.T, h *Handler, svc *Service, handler http.HandlerFunc, asEmail, method, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	token, _, err := svc.Login(context.Background(), asEmail, testPassword, "")
	require.NoError(t, err)
	req := httptest.NewRequest(method, "/api/users/"+id, strings.NewReader(body))
	req.SetPathValue("id", id)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	rec := httptest.NewRecorder()
	h.RequireAuth(RequireRole(RoleAdmin, handler))(rec, req)
	return rec
}

func TestUserAdminHandlers_NonAdmin_403(t *testing.T) {
	svc, _, ids := userAdminFixture(t)
	h := NewHandler(svc)
	for name, handler := range map[string]http.HandlerFunc{
		"update": h.UpdateUser, "delete": h.DeleteUser, "revoke": h.RevokeUserSessions,
	} {
		rec := userAdminRequest(t, h, svc, handler, "v@x.example", http.MethodPost, ids["a1@x.example"], `{"disabled":true}`)
		require.Equal(t, http.StatusForbidden, rec.Code, name)
	}
}

// A leaked admin key must not outlive its revocation: creating, promoting,
// disabling or deleting accounts takes a session. Every write would succeed
// for this admin's session (TestUserAdminHandlers_StatusMapping).
func TestUserAdminHandlers_APIKey_403(t *testing.T) {
	svc, repo, ids := userAdminFixture(t)
	a1 := repo.users["a1@x.example"]
	h := NewHandler(svc).WithAPIKeys(fakeKeys{"gph_admin": {ID: "k1", UserID: a1.ID, Scope: "admin",
		OwnerEmail: "a1@x.example", OwnerRole: RoleAdmin, OwnerCreatedAt: time.Now().Add(-24 * time.Hour)}})
	v := ids["v@x.example"]

	for name, tc := range map[string]struct {
		handler http.HandlerFunc
		path    string
		body    string
	}{
		"create":  {h.CreateUser, "", `{"email":"backdoor@x.example","password":"` + testPassword + `","role":"admin"}`},
		"promote": {h.UpdateUser, v, `{"role":"admin"}`},
		"disable": {h.UpdateUser, ids["a2@x.example"], `{"disabled":true}`},
		"delete":  {h.DeleteUser, v, ``},
		"revoke":  {h.RevokeUserSessions, v, ``},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/users/"+tc.path, strings.NewReader(tc.body))
		req.SetPathValue("id", tc.path)
		req.Header.Set("Authorization", "Bearer gph_admin")
		rec := httptest.NewRecorder()
		h.RequireAuth(RequireRole(RoleAdmin, tc.handler))(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", name, rec.Body.String())
	}
	_, created := repo.users["backdoor@x.example"]
	require.False(t, created)
	require.Equal(t, RoleViewer, repo.users["v@x.example"].Role)
	require.Nil(t, repo.users["a2@x.example"].DisabledAt)
}

func TestUserAdminHandlers_StatusMapping(t *testing.T) {
	svc, _, ids := userAdminFixture(t)
	h := NewHandler(svc)
	a1, v := ids["a1@x.example"], ids["v@x.example"]

	rec := userAdminRequest(t, h, svc, h.UpdateUser, "a1@x.example", http.MethodPatch, v, `{"role":"analyst","disabled":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "analyst", got["role"])
	require.Equal(t, true, got["disabled"])
	require.NotNil(t, got["disabled_at"])

	for name, tc := range map[string]struct {
		handler http.HandlerFunc
		id      string
		body    string
		want    int
	}{
		"self update":        {h.UpdateUser, a1, `{"disabled":true}`, http.StatusForbidden},
		"self delete":        {h.DeleteUser, a1, ``, http.StatusForbidden},
		"empty update":       {h.UpdateUser, v, `{}`, http.StatusBadRequest},
		"bad role":           {h.UpdateUser, v, `{"role":"root"}`, http.StatusBadRequest},
		"malformed id":       {h.UpdateUser, "not-a-uuid", `{"disabled":true}`, http.StatusNotFound},
		"unknown id":         {h.DeleteUser, uuid.NewString(), ``, http.StatusNotFound},
		"revoke unknown":     {h.RevokeUserSessions, uuid.NewString(), ``, http.StatusNotFound},
		"revoke ok":          {h.RevokeUserSessions, v, ``, http.StatusNoContent},
		"demote other admin": {h.UpdateUser, ids["a2@x.example"], `{"role":"viewer"}`, http.StatusOK},
	} {
		rec := userAdminRequest(t, h, svc, tc.handler, "a1@x.example", http.MethodPost, tc.id, tc.body)
		require.Equal(t, tc.want, rec.Code, "%s: %s", name, rec.Body.String())
		if tc.want >= 400 {
			require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"), name)
		}
	}

	rec = userAdminRequest(t, h, svc, h.DeleteUser, "a1@x.example", http.MethodDelete, v, ``)
	require.Equal(t, http.StatusNoContent, rec.Code)
}
