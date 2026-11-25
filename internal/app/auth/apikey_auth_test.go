package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeKeys map[string]APIKeyRecord

func (f fakeKeys) Verify(_ context.Context, plaintext string) (APIKeyRecord, error) {
	if k, ok := f[plaintext]; ok {
		return k, nil
	}
	return APIKeyRecord{}, errors.New("not found")
}

func TestRequireAuth_APIKeyPrincipalIsTheOwner(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	ownerCreated := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	ownerAdminSince := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	h := NewHandler(NewService(newFakeRepo())).WithAPIKeys(fakeKeys{
		"gph_admin_key": {ID: "k1", UserID: "u1", Name: "admin@victim.example", Scope: "admin",
			OwnerEmail: "alice@corp.example", OwnerRole: RoleAdmin, OwnerCreatedAt: ownerCreated, OwnerAdminSince: ownerAdminSince, ExpiresAt: exp},
		"gph_demoted": {ID: "k2", UserID: "u2", Name: "ci", Scope: "admin",
			OwnerEmail: "bob@corp.example", OwnerRole: RoleViewer, ExpiresAt: exp},
	})

	run := func(key string) (User, APIKeyRecord, int) {
		var seen User
		var seenKey APIKeyRecord
		req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		h.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = UserFromContext(r.Context())
			seenKey, _ = APIKeyFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})(rec, req)
		return seen, seenKey, rec.Code
	}

	u, k, code := run("gph_admin_key")
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, "u1", u.ID)
	require.Equal(t, "alice@corp.example", u.Email, "audit identity is the owner, not the user-chosen key name")
	require.Equal(t, RoleAdmin, u.Role)
	require.Equal(t, ownerCreated, u.CreatedAt, "the owner's account age, which gates executor approvals")
	require.Equal(t, ownerAdminSince, u.AdminSince, "when the owner became admin, which restarts the approval age floor")
	require.Equal(t, "k1", k.ID)

	u, _, _ = run("gph_demoted")
	require.Equal(t, RoleViewer, u.Role, "a key never exceeds its owner's current role")

	_, _, code = run("gph_unknown")
	require.Equal(t, http.StatusUnauthorized, code)
}

func TestAPIKeyScopeToRole_InventoryIsViewer(t *testing.T) {
	require.Equal(t, RoleViewer, APIKeyScopeToRole(ScopeInventory))
	require.Equal(t, RoleViewer, APIKeyScopeToRole("nonsense"))
}

// An inventory key reads as viewer, which alone would let it read everything a
// viewer can. RequireAuth refuses it on every route but the inventory ones.
func TestRequireAuth_InventoryKeyIsConfinedToInventoryRoutes(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	h := NewHandler(NewService(newFakeRepo())).WithAPIKeys(fakeKeys{
		"gph_inv": {ID: "k1", UserID: "u1", Scope: ScopeInventory, OwnerEmail: "a@corp.example", OwnerRole: RoleAdmin, ExpiresAt: exp},
		"gph_ro":  {ID: "k2", UserID: "u1", Scope: "read", OwnerEmail: "a@corp.example", OwnerRole: RoleAdmin, ExpiresAt: exp},
	})
	run := func(key, pattern, method, path string) (int, User) {
		var seen User
		mux := http.NewServeMux()
		mux.HandleFunc(pattern, h.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = UserFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code, seen
	}

	for _, rt := range []struct{ pattern, method, path string }{
		{"PUT /api/assets/{id}/package-inventory", http.MethodPut, "/api/assets/i-1/package-inventory"},
		{"PUT /api/package-inventory", http.MethodPut, "/api/package-inventory"},
		{"POST /api/mcp", http.MethodPost, "/api/mcp"},
	} {
		code, u := run("gph_inv", rt.pattern, rt.method, rt.path)
		require.Equal(t, http.StatusOK, code, rt.pattern)
		require.Equal(t, RoleViewer, u.Role, "still clamped: viewer, whatever the owner's role")
	}
	for _, rt := range []struct{ pattern, method, path string }{
		{"GET /api/assets", http.MethodGet, "/api/assets"},
		{"GET /api/findings", http.MethodGet, "/api/findings"},
		{"GET /api/auth/me", http.MethodGet, "/api/auth/me"},
		{"POST /api/scans", http.MethodPost, "/api/scans"},
		{"PUT /api/assets/{id}", http.MethodPut, "/api/assets/i-1"},
	} {
		code, _ := run("gph_inv", rt.pattern, rt.method, rt.path)
		require.Equal(t, http.StatusForbidden, code, rt.pattern)
	}
	code, _ := run("gph_ro", "GET /api/assets", http.MethodGet, "/api/assets")
	require.Equal(t, http.StatusOK, code, "other scopes are unaffected")
}
