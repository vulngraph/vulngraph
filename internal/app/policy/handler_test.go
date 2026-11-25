package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

type fakeStore struct {
	p       Policy
	updates int
	missing bool
}

func (f *fakeStore) Get(context.Context) (Policy, error) { return f.p, nil }

func (f *fakeStore) Update(_ context.Context, p Policy) (Policy, error) {
	if f.missing {
		return Policy{}, ErrNotFound
	}
	f.updates++
	prev := f.p
	f.p = p
	return prev, nil
}

func asRole(r *http.Request, role auth.Role) *http.Request {
	return r.WithContext(auth.ContextWithUser(r.Context(), auth.User{ID: "u1", Email: "a@b.example", Role: role}))
}

// The policy write is admin-only; RequireRole is what the router wraps it in,
// so drive the handler through it exactly as server.go does.
func TestUpdate_NonAdmin_403(t *testing.T) {
	store := &fakeStore{p: Policy{ID: "default", SuggestThreshold: 60}}
	h := NewHandler(NewService(store))

	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleAnalyst} {
		t.Run(string(role), func(t *testing.T) {
			req := asRole(httptest.NewRequest(http.MethodPut, "/api/policy",
				strings.NewReader(`{"suggest_threshold":10,"action_rules":{}}`)), role)
			rec := httptest.NewRecorder()
			auth.RequireRole(auth.RoleAdmin, h.Update)(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code)
		})
	}
	require.Zero(t, store.updates, "a forbidden write changes nothing")
}

func TestUpdate_StoresRequiresApprovalAndGuidanceOnly(t *testing.T) {
	store := &fakeStore{}
	h := NewHandler(NewService(store))

	req := asRole(httptest.NewRequest(http.MethodPut, "/api/policy",
		strings.NewReader(`{"suggest_threshold":55,"action_rules":{"destroy":"disabled","remediate":"jit"}}`)), auth.RoleAdmin)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Equal(t, 55, store.p.SuggestThreshold)
	require.Equal(t, map[string]ActionMode{"destroy": ModeDisabled, "remediate": ModeJIT}, store.p.ActionRules)
	require.Equal(t, "a@b.example", store.p.UpdatedBy)
}

// "auto" was a mode until ADR 087. A client still sending it must be refused,
// not stored: nothing in the product may be configured to run on its own.
func TestUpdate_RejectsAutoMode(t *testing.T) {
	store := &fakeStore{}
	h := NewHandler(NewService(store))

	req := asRole(httptest.NewRequest(http.MethodPut, "/api/policy",
		strings.NewReader(`{"suggest_threshold":55,"action_rules":{"remediate":"auto"}}`)), auth.RoleAdmin)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Zero(t, store.updates)
}

// A missing policy row is the documented 404, not a 500.
func TestUpdate_MissingRow_404(t *testing.T) {
	h := NewHandler(NewService(&fakeStore{missing: true}))

	req := asRole(httptest.NewRequest(http.MethodPut, "/api/policy",
		strings.NewReader(`{"suggest_threshold":55,"action_rules":{}}`)), auth.RoleAdmin)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGet_HasNoAutonomyKnobs(t *testing.T) {
	store := &fakeStore{p: Policy{ID: "default", SuggestThreshold: 60, ActionRules: nil}}
	h := NewHandler(NewService(store))

	rec := httptest.NewRecorder()
	h.Get(rec, httptest.NewRequest(http.MethodGet, "/api/policy", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.EqualValues(t, 60, got["suggest_threshold"])
	require.Equal(t, map[string]any{}, got["action_rules"], "nil rules render as an empty object")
	require.NotContains(t, got, "auto_threshold")
	require.NotContains(t, got, "blast_radius_cap")
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    Policy
		want error
	}{
		{"defaults", Policy{SuggestThreshold: 60}, nil},
		{"bounds inclusive", Policy{SuggestThreshold: 100, ActionRules: map[string]ActionMode{"isolate": ModeJIT}}, nil},
		{"negative threshold", Policy{SuggestThreshold: -1}, ErrBadThreshold},
		{"threshold over 100", Policy{SuggestThreshold: 101}, ErrBadThreshold},
		{"auto mode", Policy{ActionRules: map[string]ActionMode{"remediate": "auto"}}, ErrBadMode},
		{"empty mode", Policy{ActionRules: map[string]ActionMode{"remediate": ""}}, ErrBadMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validate(tc.p)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
		})
	}
}
