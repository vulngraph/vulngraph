package suppress

import (
	"context"
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

func newTestHandler() (*Handler, *fakeRepo) {
	repo := newFakeRepo()
	return NewHandler(clockedService(repo)), repo
}

// validExpiry is 55 days after testNow — inside every bound.
const validExpiry = "2026-12-01T00:00:00Z"

// authed attaches an admin user, mirroring RequireAuth in production. The actor
// is read from the session, never the body.
func authed(r *http.Request) *http.Request {
	ctx := auth.ContextWithUser(r.Context(), auth.User{ID: "u1", Email: "admin@b.example", Role: auth.RoleAdmin})
	return r.WithContext(ctx)
}

func TestSuppressHandler_Created(t *testing.T) {
	h, repo := newTestHandler()

	req := authed(httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress", strings.NewReader(`{"reason":"false positive","expires_at":"`+validExpiry+`"}`)))
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Suppress(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "f1", got["finding_id"])
	require.Equal(t, "admin@b.example", got["suppressed_by"], "actor comes from the session")
	require.Equal(t, "false positive", repo.rows["f1"].Reason)
	require.Equal(t, validExpiry, got["expires_at"])
	require.Equal(t, false, got["expired"])
	require.Nil(t, got["last_reviewed_at"], "never reviewed is null, not a zero timestamp")
}

func TestSuppressHandler_MissingReason_400(t *testing.T) {
	h, repo := newTestHandler()

	req := authed(httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress", strings.NewReader(`{"reason":""}`)))
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Suppress(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, repo.rows)
}

func TestSuppressHandler_BadJSON_400(t *testing.T) {
	h, _ := newTestHandler()

	req := authed(httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress", strings.NewReader(`not json`)))
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Suppress(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestUnsuppressHandler_NoContent(t *testing.T) {
	h, repo := newTestHandler()
	_, err := h.svc.SuppressUntil(context.Background(), "f1", "reason", "admin@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/findings/f1/suppress", nil)
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Unsuppress(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Empty(t, repo.rows)
}

func TestUnsuppressHandler_NotFound_404(t *testing.T) {
	h, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodDelete, "/api/findings/ghost/suppress", nil)
	req.SetPathValue("id", "ghost")
	rec := httptest.NewRecorder()
	h.Unsuppress(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestListHandler(t *testing.T) {
	h, _ := newTestHandler()
	_, err := h.svc.SuppressUntil(context.Background(), "f1", "reason", "admin@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/suppressions", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got, 1)
	require.Equal(t, "f1", got[0]["finding_id"])
}

// A store failure on each route surfaces as a 500, not a panic or partial write.
func TestHandler_StoreErrors_500(t *testing.T) {
	boom := errors.New("pg down")

	h := NewHandler(clockedService(&fakeRepo{upsertErr: boom}))
	req := authed(httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress", strings.NewReader(`{"reason":"r","expires_at":"`+validExpiry+`"}`)))
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Suppress(rec, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	h = NewHandler(NewService(&fakeRepo{deleteErr: boom}))
	req = httptest.NewRequest(http.MethodDelete, "/api/findings/f1/suppress", nil)
	req.SetPathValue("id", "f1")
	rec = httptest.NewRecorder()
	h.Unsuppress(rec, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code)

	h = NewHandler(NewService(&fakeRepo{listErr: boom}))
	rec = httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/suppressions", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

// actor falls back to the user ID when the session carries no email, and is empty
// when there is no authenticated user on the context.
func TestActor_Fallbacks(t *testing.T) {
	withID := auth.ContextWithUser(context.Background(), auth.User{ID: "u7", Role: auth.RoleAdmin})
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(withID)
	require.Equal(t, "u7", actor(r))

	anon := httptest.NewRequest(http.MethodGet, "/", nil)
	require.Equal(t, "", actor(anon))
}
