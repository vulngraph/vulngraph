package suppress

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

func asRole(r *http.Request, role auth.Role) *http.Request {
	ctx := auth.ContextWithUser(r.Context(), auth.User{ID: "u2", Email: "someone@b.example", Role: role})
	return r.WithContext(ctx)
}

// Every suppression write is admin-only; RequireRole is what the router wraps
// them in, so drive the handlers through it exactly as server.go does.
func TestSuppressWrites_NonAdmin_403(t *testing.T) {
	h, repo := newTestHandler()
	repo.rows["f1"] = Suppression{FindingID: "f1", ExpiresAt: testNow.Add(day)}

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
		body    string
	}{
		{"suppress", h.Suppress, http.MethodPost, "/api/findings/f1/suppress", `{"reason":"r","expires_at":"` + validExpiry + `"}`},
		{"review", h.Review, http.MethodPost, "/api/findings/f1/suppress/review", `{"expires_at":"` + validExpiry + `"}`},
		{"unsuppress", h.Unsuppress, http.MethodDelete, "/api/findings/f1/suppress", ""},
		{"bulk suppress", h.BulkSuppress, http.MethodPost, "/api/suppressions/bulk", `{"finding_ids":["f2"],"reason":"r","expires_at":"` + validExpiry + `"}`},
		{"bulk unsuppress", h.BulkUnsuppress, http.MethodPost, "/api/suppressions/bulk-remove", `{"finding_ids":["f1"]}`},
	} {
		for _, role := range []auth.Role{auth.RoleViewer, auth.RoleAnalyst} {
			t.Run(tc.name+"/"+string(role), func(t *testing.T) {
				req := asRole(httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)), role)
				req.SetPathValue("id", "f1")
				rec := httptest.NewRecorder()
				auth.RequireRole(auth.RoleAdmin, tc.handler)(rec, req)
				require.Equal(t, http.StatusForbidden, rec.Code)
			})
		}
	}
	require.Equal(t, testNow.Add(day), repo.rows["f1"].ExpiresAt, "a forbidden write changes nothing")
	require.NotContains(t, repo.rows, "f2")
}

func TestReviewHandler_NonAdmin_403(t *testing.T) {
	h, repo := newTestHandler()
	repo.rows["f1"] = Suppression{FindingID: "f1", ExpiresAt: testNow.Add(day)}

	req := asRole(httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress/review",
		strings.NewReader(`{"expires_at":"`+validExpiry+`"}`)), auth.RoleViewer)
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	auth.RequireRole(auth.RoleAdmin, h.Review)(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Empty(t, repo.rows["f1"].ReviewedBy)
}

func TestSuppressHandler_ExpiryValidation_400(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"missing expires_at", `{"reason":"r"}`},
		{"expires_at in the past", `{"reason":"r","expires_at":"2026-01-01T00:00:00Z"}`},
		{"expires_at past the 365d cap", `{"reason":"r","expires_at":"2028-01-01T00:00:00Z"}`},
		{"expires_at not RFC 3339", `{"reason":"r","expires_at":"next tuesday"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, repo := newTestHandler()
			req := authed(httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress", strings.NewReader(tc.body)))
			req.SetPathValue("id", "f1")
			rec := httptest.NewRecorder()
			h.Suppress(rec, req)

			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			require.Empty(t, repo.rows)
		})
	}
}

func TestBulkSuppressHandler_RequiresExpiry(t *testing.T) {
	h, repo := newTestHandler()
	req := authed(httptest.NewRequest(http.MethodPost, "/api/suppressions/bulk",
		strings.NewReader(`{"finding_ids":["f1","f2"],"reason":"r"}`)))
	rec := httptest.NewRecorder()
	h.BulkSuppress(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, repo.rows)

	req = authed(httptest.NewRequest(http.MethodPost, "/api/suppressions/bulk",
		strings.NewReader(`{"finding_ids":["f1","f2"],"reason":"r","expires_at":"`+validExpiry+`"}`)))
	rec = httptest.NewRecorder()
	h.BulkSuppress(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, repo.rows, 2)
	require.Equal(t, validExpiry, repo.rows["f2"].ExpiresAt.UTC().Format(time.RFC3339))
}

func TestReviewHandler(t *testing.T) {
	h, repo := newTestHandler()
	repo.rows["f1"] = Suppression{FindingID: "f1", Reason: "r", ExpiresAt: testNow.Add(-day)}

	req := authed(httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress/review",
		strings.NewReader(`{"expires_at":"`+validExpiry+`"}`)))
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Review(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, validExpiry, got["expires_at"])
	require.Equal(t, false, got["expired"], "renewal re-instates an expired suppression")
	require.Equal(t, "admin@b.example", got["reviewed_by"], "reviewer comes from the session")
	require.NotNil(t, got["last_reviewed_at"])
}

func TestReviewHandler_Errors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		repo   *fakeRepo
		body   string
		status int
	}{
		{"not suppressed", newFakeRepo(), `{"expires_at":"` + validExpiry + `"}`, http.StatusNotFound},
		{"bad json", newFakeRepo(), `nope`, http.StatusBadRequest},
		{"missing expiry", seeded(), `{}`, http.StatusBadRequest},
		{"store error", &fakeRepo{rows: seeded().rows, reviewErr: errors.New("pg down")}, `{"expires_at":"` + validExpiry + `"}`, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(clockedService(tc.repo))
			req := authed(httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress/review", strings.NewReader(tc.body)))
			req.SetPathValue("id", "f1")
			rec := httptest.NewRecorder()
			h.Review(rec, req)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
		})
	}
}

func TestListHandler_FlagsExpired(t *testing.T) {
	h, repo := newTestHandler()
	repo.rows["live"] = Suppression{FindingID: "live", ExpiresAt: testNow.Add(day)}
	repo.rows["lapsed"] = Suppression{FindingID: "lapsed", ExpiresAt: testNow.Add(-day),
		ReviewedBy: "carol@b.example", LastReviewedAt: testNow.Add(-30 * day)}

	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/suppressions", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var got []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	byID := map[string]map[string]any{}
	for _, s := range got {
		byID[s["finding_id"].(string)] = s
	}
	require.Equal(t, false, byID["live"]["expired"])
	require.Equal(t, true, byID["lapsed"]["expired"])
	require.Equal(t, "carol@b.example", byID["lapsed"]["reviewed_by"])
}

func seeded() *fakeRepo {
	repo := newFakeRepo()
	repo.rows["f1"] = Suppression{FindingID: "f1", ExpiresAt: testNow.Add(day)}
	return repo
}
