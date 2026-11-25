package pkginv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

const goodBody = `{"os":{"id":"ubuntu","version_id":"22.04"},"observed_at":"2026-11-25T11:00:00Z",
"scanner":{"name":"acme-agent","version":"1.4.2"},"complete":true,
"packages":[{"name":"libssl3","version":"3.0.2-0ubuntu1.10","source_name":"openssl"}]}`

func keyCtx(scope string, owner auth.Role) context.Context {
	ctx := auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Email: "owner@x.example", Role: auth.RoleViewer})
	return auth.ContextWithAPIKey(ctx, auth.APIKeyRecord{ID: "key-a", UserID: "u1", Scope: scope, OwnerRole: owner})
}

func sessionCtx(role auth.Role) context.Context {
	return auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Email: "u@x.example", Role: role})
}

func serve(t *testing.T, h *Handler, ctx context.Context, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/assets/{id}/package-inventory", h.PutForAsset)
	mux.HandleFunc("PUT /api/package-inventory", h.Put)
	req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/api/assets/"+vmID+"/package-inventory", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func handlerRig(t *testing.T) (*Handler, *rig) {
	t.Helper()
	r := newRig(t)
	r.svc.now = func() time.Time { return clock }
	return NewHandler(r.svc), r
}

func TestPackageInventory_NonAdmin_403(t *testing.T) {
	h, r := handlerRig(t)
	for name, ctx := range map[string]context.Context{
		"viewer session":  sessionCtx(auth.RoleViewer),
		"analyst session": sessionCtx(auth.RoleAnalyst),
		"admin session":   sessionCtx(auth.RoleAdmin),
		"no principal":    context.Background(),
	} {
		t.Run(name, func(t *testing.T) {
			rec := serve(t, h, ctx, goodBody)
			require.Equal(t, http.StatusForbidden, rec.Code)
		})
	}
	require.Zero(t, r.assets.ingest)
}

func TestPackageInventory_WrongScope_403(t *testing.T) {
	h, r := handlerRig(t)
	for _, scope := range []string{"read", "write", "admin", ""} {
		t.Run("scope "+scope, func(t *testing.T) {
			rec := serve(t, h, keyCtx(scope, auth.RoleAdmin), goodBody)
			require.Equal(t, http.StatusForbidden, rec.Code)
		})
	}
	t.Run("inventory key whose owner is no longer an admin", func(t *testing.T) {
		require.Equal(t, http.StatusForbidden, serve(t, h, keyCtx("inventory", auth.RoleAnalyst), goodBody).Code)
		require.Equal(t, http.StatusForbidden, serve(t, h, keyCtx("inventory", auth.RoleViewer), goodBody).Code)
	})
	require.Zero(t, r.assets.ingest)
	require.NotEmpty(t, r.audit.rows)
	for _, row := range r.audit.rows {
		require.Equal(t, "rejected", row.details["outcome"], "every refusal is audited")
	}
}

func TestPackageInventory_Accepted(t *testing.T) {
	h, _ := handlerRig(t)
	rec := serve(t, h, keyCtx("inventory", auth.RoleAdmin), goodBody)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, true, got["accepted"])
	require.Equal(t, vmID, got["asset_id"])
	require.Equal(t, "byoa:key-a:acme-agent", got["source"])
	require.Equal(t, true, got["inventory_known"])
	require.Equal(t, true, got["cve_matchable_known"])
	require.Equal(t, "", got["gap"])
	require.Equal(t, float64(1), got["package_count"])
}

func TestPackageInventory_Errors(t *testing.T) {
	ctx := keyCtx("inventory", auth.RoleAdmin)
	cases := []struct {
		name  string
		body  string
		setup func(*rig)
		code  int
	}{
		{"unknown field", `{"inventory_known":true}`, nil, http.StatusBadRequest},
		{"invalid scanner", `{"scanner":{"name":"X","version":"1"},"observed_at":"2026-11-25T11:00:00Z"}`, nil, http.StatusBadRequest},
		{"not json", `nope`, nil, http.StatusBadRequest},
		{"unknown asset", goodBody, func(r *rig) { delete(r.assets.assets, vmID) }, http.StatusNotFound},
		{"deleted asset", goodBody, func(r *rig) { r.deleted[vmID] = clock }, http.StatusNotFound},
		{"rate limited", goodBody, func(r *rig) { r.limiter.left = 0 }, http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, r := handlerRig(t)
			if tc.setup != nil {
				tc.setup(r)
			}
			rec := serve(t, h, ctx, tc.body)
			require.Equal(t, tc.code, rec.Code, rec.Body.String())
			if tc.code == http.StatusTooManyRequests {
				require.NotEmpty(t, rec.Header().Get("Retry-After"))
			}
		})
	}
	t.Run("stale is 409", func(t *testing.T) {
		h, _ := handlerRig(t)
		require.Equal(t, http.StatusOK, serve(t, h, ctx, goodBody).Code)
		older := strings.Replace(goodBody, "11:00:00Z", "09:00:00Z", 1)
		require.Equal(t, http.StatusConflict, serve(t, h, ctx, older).Code)
	})
	t.Run("an oversized body is 413", func(t *testing.T) {
		h, _ := handlerRig(t)
		mux := http.NewServeMux()
		mux.HandleFunc("PUT /api/package-inventory", h.Put)
		req := httptest.NewRequestWithContext(ctx, http.MethodPut, "/api/package-inventory", strings.NewReader(goodBody))
		req.Body = http.MaxBytesReader(httptest.NewRecorder(), req.Body, 20)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})
}

func TestPackageInventory_BodyRouteNamesTheAsset(t *testing.T) {
	h, _ := handlerRig(t)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/package-inventory", h.Put)
	body := strings.Replace(goodBody, `{"os"`, `{"cloud_resource_id":"i-other","os"`, 1)
	req := httptest.NewRequestWithContext(keyCtx("inventory", auth.RoleAdmin), http.MethodPut, "/api/package-inventory", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `"asset_id":"i-other"`)
}
