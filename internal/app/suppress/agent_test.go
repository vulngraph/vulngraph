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

// fakeGate answers AgentRefusals from a fixed table; ids absent from it do
// not exist.
type fakeGate struct {
	refusals map[string]string
	err      error
	asked    [][]string
}

func (g *fakeGate) AgentRefusals(_ context.Context, ids []string) (map[string]string, error) {
	g.asked = append(g.asked, ids)
	if g.err != nil {
		return nil, g.err
	}
	out := map[string]string{}
	for _, id := range ids {
		if why, ok := g.refusals[id]; ok {
			out[id] = why
		}
	}
	return out, nil
}

func keyCtx() context.Context {
	ctx := auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Email: "admin@b.example", Role: auth.RoleAdmin})
	return auth.ContextWithAPIKey(ctx, auth.APIKeyRecord{ID: "k1", UserID: "u1", Scope: "admin"})
}

func gatedService(gate FindingGate) (*Service, *fakeRepo, *fakeAuditor) {
	repo := newFakeRepo()
	audit := &fakeAuditor{}
	svc := clockedService(repo).WithAudit(audit)
	if gate != nil {
		svc = svc.WithFindingGate(gate)
	}
	return svc, repo, audit
}

func TestAgentCheck_APIKey(t *testing.T) {
	gate := &fakeGate{refusals: map[string]string{"low": "", "crit": "critical severity", "unscored": "not yet scored"}}
	cases := []struct {
		name    string
		gate    FindingGate
		ids     []string
		expiry  time.Time
		wantErr error
	}{
		{"low-urgency finding within 30 days", gate, []string{"low"}, testNow.Add(30 * day), nil},
		{"critical finding", gate, []string{"crit"}, testNow.Add(7 * day), ErrNeedsPerson},
		{"unscored finding", gate, []string{"unscored"}, testNow.Add(7 * day), ErrNeedsPerson},
		{"past 30 days", gate, []string{"low"}, testNow.Add(60 * day), ErrAgentExpiryTooFar},
		{"unknown finding", gate, []string{"ghost"}, testNow.Add(7 * day), ErrUnknownFinding},
		{"no gate wired", nil, []string{"low"}, testNow.Add(7 * day), ErrNeedsPerson},
		{"one refused finding refuses the batch", gate, []string{"low", "crit"}, testNow.Add(7 * day), ErrNeedsPerson},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, repo, _ := gatedService(tc.gate)
			_, err := svc.SuppressMany(keyCtx(), tc.ids, "noise", "admin@b.example", tc.expiry)
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.Len(t, repo.rows, len(tc.ids))
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			require.Empty(t, repo.rows, "a refused API-key request writes nothing")
		})
	}
}

func TestAgentCheck_SessionIsUnchanged(t *testing.T) {
	svc, repo, _ := gatedService(&fakeGate{refusals: map[string]string{"crit": "critical severity"}})
	ctx := auth.ContextWithUser(context.Background(), auth.User{ID: "u1", Role: auth.RoleAdmin})

	_, err := svc.SuppressUntil(ctx, "crit", "accepted risk", "admin@b.example", testNow.Add(300*day))
	require.NoError(t, err, "a signed-in person may suppress anything for up to a year")
	require.Contains(t, repo.rows, "crit")
}

func TestAgentCheck_RefusalIsAudited(t *testing.T) {
	svc, _, audit := gatedService(&fakeGate{refusals: map[string]string{"crit": "critical severity"}})

	_, err := svc.SuppressUntil(keyCtx(), "crit", "noise", "admin@b.example", testNow.Add(7*day))
	require.ErrorIs(t, err, ErrNeedsPerson)

	require.Len(t, audit.events, 1)
	e := audit.events[0]
	require.Equal(t, AuditActionRefused, e.Action)
	require.Equal(t, "crit", e.TargetID)
	require.Equal(t, "admin@b.example", e.Actor)
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(e.Details), &d))
	require.Equal(t, "critical severity", d["reason"])
	require.Equal(t, "suppress", d["operation"])
}

func TestAgentCheck_ReviewOnKeyIsCapped(t *testing.T) {
	svc, repo, _ := gatedService(&fakeGate{refusals: map[string]string{"f1": "", "crit": "classed must-fix"}})
	repo.rows["f1"] = Suppression{FindingID: "f1", ExpiresAt: testNow.Add(day)}
	repo.rows["crit"] = Suppression{FindingID: "crit", ExpiresAt: testNow.Add(day)}

	_, err := svc.Review(keyCtx(), "f1", "admin@b.example", testNow.Add(90*day))
	require.ErrorIs(t, err, ErrAgentExpiryTooFar)
	_, err = svc.Review(keyCtx(), "crit", "admin@b.example", testNow.Add(7*day))
	require.ErrorIs(t, err, ErrNeedsPerson, "a key cannot renew a suppression a person made on an urgent finding")
	_, err = svc.Review(keyCtx(), "f1", "admin@b.example", testNow.Add(7*day))
	require.NoError(t, err)
}

func TestAgentCheck_GateErrorRefuses(t *testing.T) {
	svc, repo, _ := gatedService(&fakeGate{err: errors.New("clickhouse down")})
	_, err := svc.SuppressUntil(keyCtx(), "f1", "noise", "admin@b.example", testNow.Add(7*day))
	require.Error(t, err)
	require.Empty(t, repo.rows, "an unread urgency is not a low one")
}

func TestSuppressHandler_APIKey_403(t *testing.T) {
	svc, repo, _ := gatedService(&fakeGate{refusals: map[string]string{"crit": "critical severity"}})
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/findings/crit/suppress",
		strings.NewReader(`{"reason":"noise","expires_at":"`+testNow.Add(7*day).Format(time.RFC3339)+`"}`)).WithContext(keyCtx())
	req.SetPathValue("id", "crit")
	rec := httptest.NewRecorder()
	h.Suppress(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Contains(t, rec.Body.String(), "critical severity")
	require.Empty(t, repo.rows)
}

func TestBulkSuppressHandler_APIKey_403(t *testing.T) {
	svc, repo, _ := gatedService(&fakeGate{refusals: map[string]string{"low": "", "crit": "urgent score band"}})
	h := NewHandler(svc)

	body := `{"finding_ids":["low","crit"],"reason":"noise","expires_at":"` + testNow.Add(7*day).Format(time.RFC3339) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/suppressions/bulk", strings.NewReader(body)).WithContext(keyCtx())
	rec := httptest.NewRecorder()
	h.BulkSuppress(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Empty(t, repo.rows, "the batch is all or nothing on a key")
}

func TestSuppressHandler_APIKey_ExpiryPast30Days_400(t *testing.T) {
	svc, _, _ := gatedService(&fakeGate{refusals: map[string]string{"f1": ""}})
	h := NewHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/api/findings/f1/suppress",
		strings.NewReader(`{"reason":"noise","expires_at":"`+validExpiry+`"}`)).WithContext(keyCtx())
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Suppress(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Contains(t, rec.Body.String(), "30 days")
}
