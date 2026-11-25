package govern

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
)

// TestQueue_InvalidActionClass400s mirrors
// respond.TestListDecisions_InvalidActionClass400s: an unrecognized
// action_class must reject the request, not silently match zero rows (the
// classic bug shape — a degraded input indistinguishable from a genuine empty
// result).
func TestQueue_InvalidActionClass400s(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Outcome: "parked_for_approval"},
	}}
	h := NewHandler(svc(&fakeVerdicts{}, pending, fakeFindings{}, &fakeOutcomes{}, &fakeAudit{}))

	rec := httptest.NewRecorder()
	h.Queue(rec, httptest.NewRequest(http.MethodGet, "/api/queue?action_class=nuke", nil))

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestQueue_FiltersByActionClass pins that the handler threads a valid
// action_class query param down to the Pending store's query (not a
// client-visible filter over an already-fetched slice) — the same
// truncation-bug shape respond.ListDecisions' action_class filter already
// fixed for the decisions list.
func TestQueue_FiltersByActionClass(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Outcome: "parked_for_approval"},
		{FindingID: "f2", ActionClass: "isolate", Outcome: "escalated"},
	}}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", ResourceID: "u1"},
		"f2": {ID: "f2", CheckID: "ssh-brute", ResourceID: "i-1"},
	}}
	h := NewHandler(svc(&fakeVerdicts{}, pending, finds, &fakeOutcomes{}, &fakeAudit{}))

	rec := httptest.NewRecorder()
	h.Queue(rec, httptest.NewRequest(http.MethodGet, "/api/queue?action_class=modify", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var resp queueResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Items, 1)
	require.Equal(t, "modify", resp.Items[0].ActionClass)
}

// writeLinkError maps each link outcome to its own status: an unwired link
// store is 503 (the operator's configuration, not a server fault), the expected
// refusals are a 409 page, and anything else is a 500.
func TestWriteLinkError_StatusByCause(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{ErrLinksDisabled, http.StatusServiceUnavailable},
		{fmt.Errorf("ResolveByLink: %w", ErrLinksDisabled), http.StatusServiceUnavailable},
		{ErrAlreadyResolved, http.StatusConflict},
		{ErrNotPending, http.StatusConflict},
		{ErrLinkCannotApprove, http.StatusConflict},
		{errors.New("clickhouse down"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/decisions/link", nil)
			(&Handler{}).writeLinkError(rec, req, tc.err)
			require.Equal(t, tc.want, rec.Code)
		})
	}
}

// An API key may be held by an agent, so it never records a verdict: the
// request is refused before the body is read, and nothing reaches the
// verdict store, the memory ledger or the audit trail.
func TestResolve_APIKey_403(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Outcome: "parked_for_approval"},
	}}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", ResourceID: "u1", ResourceType: "iam_user"},
	}}
	verdicts, outcomes, audit := &fakeVerdicts{}, &fakeOutcomes{}, &fakeAudit{}
	h := NewHandler(svc(verdicts, pending, finds, outcomes, audit))

	for _, body := range []string{`{"finding_ids":["f1"],"action_class":"modify","verdict":"denied"}`, `not json`} {
		ctx := auth.ContextWithUser(context.Background(), auth.User{Email: "admin@example.com", Role: auth.RoleAdmin})
		ctx = auth.ContextWithAPIKey(ctx, auth.APIKeyRecord{ID: "k1", OwnerEmail: "admin@example.com", OwnerRole: auth.RoleAdmin})
		req := httptest.NewRequest(http.MethodPost, "/api/queue/resolve", strings.NewReader(body)).WithContext(ctx)
		rec := httptest.NewRecorder()
		h.Resolve(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, body)
	}
	require.Empty(t, verdicts.upserts)
	require.Empty(t, outcomes.recorded)
	require.Empty(t, audit.events)

	// The same verdict from the owner's session is recorded.
	ctx := auth.ContextWithUser(context.Background(), auth.User{Email: "admin@example.com", Role: auth.RoleAdmin})
	req := httptest.NewRequest(http.MethodPost, "/api/queue/resolve",
		strings.NewReader(`{"finding_ids":["f1"],"action_class":"modify","verdict":"denied"}`)).WithContext(ctx)
	rec := httptest.NewRecorder()
	h.Resolve(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	require.NotEmpty(t, verdicts.upserts)
	require.Equal(t, "admin@example.com", audit.events[0].Actor)
}
