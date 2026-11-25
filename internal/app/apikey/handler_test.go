package apikey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

// The /api/keys routes require RequireAuth (any authenticated user); key
// ownership and the scope-privilege clamp are enforced inside the handler.
// These tests verify the handler's own validation, including that a caller
// cannot mint a key more privileged than their own role.

// fakeRepo is a no-op Repository that never touches a DB.
type fakeRepo struct{}

func (f *fakeRepo) Create(_ context.Context, _, _ string, _ Scope, _ *time.Time) (APIKey, string, error) {
	return APIKey{}, "", nil
}
func (f *fakeRepo) List(_ context.Context, _ string) ([]APIKey, error) { return nil, nil }
func (f *fakeRepo) Delete(_ context.Context, _, _ string) error        { return nil }
func (f *fakeRepo) Verify(_ context.Context, _ string) (APIKey, error) { return APIKey{}, nil }

func newTestHandler() *Handler {
	return NewHandler(NewService(&fakeRepo{}))
}

// withUser injects a test user (analyst) into the request context.
func withUser(r *http.Request) *http.Request {
	return withRole(r, auth.RoleAnalyst)
}

// withRole injects a test user with the given role into the request context.
func withRole(r *http.Request, role auth.Role) *http.Request {
	ctx := auth.ContextWithUser(r.Context(), auth.User{ID: "u-test", Email: "test@example.com", Role: role})
	return r.WithContext(ctx)
}

func createReq(role auth.Role, scope string) *http.Request {
	body := `{"name":"k","scopes":"` + scope + `"}`
	r := httptest.NewRequest(http.MethodPost, "/api/keys", strings.NewReader(body))
	return withRole(r, role)
}

// A caller must not be able to mint a key more privileged than their own role.
func TestAPIKeyCreate_ScopeExceedsRole_403(t *testing.T) {
	h := newTestHandler()
	cases := []struct {
		role  auth.Role
		scope string
	}{
		{auth.RoleViewer, "write"},
		{auth.RoleViewer, "admin"},
		{auth.RoleAnalyst, "admin"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.Create(rec, createReq(tc.role, tc.scope))
		require.Equal(t, http.StatusForbidden, rec.Code, "%s minting %s key must be forbidden", tc.role, tc.scope)
	}
}

// A caller may mint a key at or below their own role.
func TestAPIKeyCreate_ScopeWithinRole_OK(t *testing.T) {
	h := newTestHandler()
	cases := []struct {
		role  auth.Role
		scope string
	}{
		{auth.RoleViewer, "read"},
		{auth.RoleAnalyst, "write"},
		{auth.RoleAdmin, "admin"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.Create(rec, createReq(tc.role, tc.scope))
		require.Equal(t, http.StatusCreated, rec.Code, "%s minting %s key must be allowed", tc.role, tc.scope)
	}
}

func TestAPIKeyCreate_MissingName_400(t *testing.T) {
	h := newTestHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/keys", strings.NewReader(`{}`))
	req = withUser(req)
	h.Create(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// viaKey marks a request as authenticated with an API key, as RequireAuth's
// Bearer gph_* path does.
func viaKey(r *http.Request, scope string) *http.Request {
	return r.WithContext(auth.ContextWithAPIKey(r.Context(),
		auth.APIKeyRecord{ID: "caller", Scope: scope, ExpiresAt: time.Now().Add(time.Hour)}))
}

// A read-scoped key used to mint successor keys and delete the owner's admin
// keys: the request principal is the owner. Key management needs a session.
func TestAPIKeyWrites_RefusedForAPIKeyPrincipal_403(t *testing.T) {
	h := newTestHandler()
	for _, scope := range []string{"read", "write", "admin"} {
		rec := httptest.NewRecorder()
		h.Create(rec, viaKey(createReq(auth.RoleAdmin, "read"), scope))
		require.Equal(t, http.StatusForbidden, rec.Code, "a %s key must not create keys: %s", scope, rec.Body.String())

		del := withRole(httptest.NewRequest(http.MethodDelete, "/api/keys/k2", nil), auth.RoleAdmin)
		del.SetPathValue("id", "k2")
		rec = httptest.NewRecorder()
		h.Delete(rec, viaKey(del, scope))
		require.Equal(t, http.StatusForbidden, rec.Code, "a %s key must not delete keys", scope)
	}
}

// Listing stays available to a key (read-only, the caller's own keys).
func TestAPIKeyList_AllowedForAPIKeyPrincipal(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestHandler().List(rec, viaKey(withUser(httptest.NewRequest(http.MethodGet, "/api/keys", nil)), "read"))
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestAPIKeyDelete_SessionOK(t *testing.T) {
	del := withUser(httptest.NewRequest(http.MethodDelete, "/api/keys/k2", nil))
	del.SetPathValue("id", "k2")
	rec := httptest.NewRecorder()
	newTestHandler().Delete(rec, del)
	require.Equal(t, http.StatusNoContent, rec.Code)
}

func TestAPIKeyCreate_BeyondMaxLifetime_400(t *testing.T) {
	h := newTestHandler()
	tooLate := time.Now().Add(DefaultMaxLifetime + 24*time.Hour).UTC().Format(time.RFC3339)
	body := `{"name":"k","scopes":"read","expires_at":"` + tooLate + `"}`
	req := withRole(httptest.NewRequest(http.MethodPost, "/api/keys", strings.NewReader(body)), auth.RoleAdmin)
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAPIKeyList_OK(t *testing.T) {
	h := newTestHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
	req = withUser(req)
	h.List(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

// An inventory key maps to viewer, so the privilege clamp alone would let any
// viewer mint one. Only an admin may.
func TestAPIKeyCreate_InventoryScopeIsAdminOnly(t *testing.T) {
	h := newTestHandler()
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleAnalyst} {
		rec := httptest.NewRecorder()
		h.Create(rec, createReq(role, "inventory"))
		require.Equal(t, http.StatusForbidden, rec.Code, "%s must not mint an inventory key", role)
	}
	rec := httptest.NewRecorder()
	h.Create(rec, createReq(auth.RoleAdmin, "inventory"))
	require.Equal(t, http.StatusCreated, rec.Code)
}

func TestScope_Valid(t *testing.T) {
	for _, s := range []Scope{ScopeRead, ScopeWrite, ScopeAdmin, ScopeInventory} {
		require.True(t, s.Valid(), s)
	}
	for _, s := range []Scope{"", "inventory ", "Inventory", "root"} {
		require.False(t, s.Valid(), s)
	}
}

func TestScopeInventoryMatchesAuth(t *testing.T) {
	require.Equal(t, auth.ScopeInventory, string(ScopeInventory))
}
