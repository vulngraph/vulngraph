package executor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

func decisionReq(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.SetPathValue("id", "d-1")
	return req
}

func asRole(req *http.Request, role auth.Role) *http.Request {
	return req.WithContext(auth.ContextWithUser(req.Context(), auth.User{ID: "u-" + string(role), Email: string(role) + "@example.com", Role: role}))
}

// Every approve-and-run route is admin-only; drive each through RequireRole
// exactly as server.go wraps it. A refused call never reaches the service.
func TestDecisionExecutionRoutes_NonAdmin_403(t *testing.T) {
	svc := &fakeService{}
	h := newHandlerWithFake(svc)
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
	}{
		{"plan", h.PlanDecision, http.MethodGet, "/api/decisions/d-1/execution"},
		{"dry run", h.DryRunDecision, http.MethodPost, "/api/decisions/d-1/execution/dry-run"},
		{"request", h.RequestDecisionApproval, http.MethodPost, "/api/decisions/d-1/execution/request"},
		{"run", h.RunDecision, http.MethodPost, "/api/decisions/d-1/execution/run"},
		{"mark failed", h.MarkStalledRunFailed, http.MethodPost, "/api/decisions/d-1/execution/mark-failed"},
	} {
		for _, role := range []auth.Role{auth.RoleViewer, auth.RoleAnalyst} {
			t.Run(tc.name+"/"+string(role), func(t *testing.T) {
				rec := httptest.NewRecorder()
				auth.RequireRole(auth.RoleAdmin, tc.handler)(rec, asRole(decisionReq(tc.method, tc.path, `{"confirm":"i-abc","note":"n"}`), role))
				require.Equal(t, http.StatusForbidden, rec.Code)
			})
		}
	}
	require.Empty(t, svc.gotConfirm, "no forbidden call reached the service")
	require.Empty(t, svc.gotNote, "no forbidden call reached the service")
	require.Empty(t, svc.gotReq.DecisionID)
}

// The request the transport builds carries the decision id (the audit tag),
// the bound plan and, for a confirmation, the grant.
func TestRunDecision_BuildsTheRequestFromTheBoundPlan(t *testing.T) {
	svc := &fakeService{
		bound: BoundPlan{
			DecisionPlan: DecisionPlan{Target: DecisionTarget{DecisionID: "d-1"}, ConnectorID: "c1", Action: ActionEC2Stop,
				Params: map[string]string{ParamInstanceID: "i-abc"}},
			GrantToken: "grant",
		},
		run:    DecisionRun{Status: RunSucceeded, Action: ActionEC2Stop, RequestedByID: "u-admin", UpdatedAt: time.Now()},
		result: ExecutionResult{ConnectorID: "c1", Action: ActionEC2Stop, Detail: "stopped EC2 instance i-abc in eu-west-1"},
	}
	rec := httptest.NewRecorder()
	newHandlerWithFake(svc).RunDecision(rec, asRole(decisionReq(http.MethodPost, "/api/decisions/d-1/execution/run",
		`{"inputs":{"region":"eu-west-1"},"confirm":"i-abc"}`), auth.RoleAdmin))
	require.Equal(t, http.StatusOK, rec.Code)

	require.Equal(t, "d-1", svc.gotReq.DecisionID)
	require.Equal(t, "grant", svc.gotReq.ApprovalToken)
	require.Equal(t, "c1", svc.gotReq.ConnectorID)
	require.False(t, svc.gotReq.DryRun)
	require.Equal(t, "i-abc", svc.gotConfirm)
	require.Equal(t, map[string]string{"region": "eu-west-1"}, svc.gotInputs)

	var resp decisionRunResultResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "succeeded", resp.Run.Status)
	require.True(t, resp.Run.RequestedByYou)
	require.Equal(t, "stopped EC2 instance i-abc in eu-west-1", resp.Result.Detail)
}

func TestDryRunDecision_IsADryRunAndAcceptsAnEmptyBody(t *testing.T) {
	svc := &fakeService{
		bound:  BoundPlan{DecisionPlan: DecisionPlan{Target: DecisionTarget{DecisionID: "d-1"}}, ConfirmText: "i-abc", Destructive: true},
		result: ExecutionResult{DryRun: true, Detail: "DRY RUN — nothing was changed."},
	}
	rec := httptest.NewRecorder()
	newHandlerWithFake(svc).DryRunDecision(rec, decisionReq(http.MethodPost, "/api/decisions/d-1/execution/dry-run", ""))
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, svc.gotReq.DryRun)

	var resp decisionDryRunResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "i-abc", resp.ConfirmText)
	require.True(t, resp.Destructive)
}

func TestDecisionRoutes_MapErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{ErrDecisionNotFound, http.StatusNotFound},
		{ErrNotRunnable, http.StatusConflict},
		{ErrRunConflict, http.StatusConflict},
		{ErrRunNotStalled, http.StatusConflict},
		{ErrCloudStateUnverified, http.StatusConflict},
		{ErrConfirmationMismatch, http.StatusBadRequest},
		{ErrBadParams, http.StatusBadRequest},
		{ErrApprovalRequired, http.StatusForbidden},
		{ErrApprovalInvalid, http.StatusForbidden},
		{ErrNoPrincipal, http.StatusForbidden},
		{ErrBypassAuth, http.StatusForbidden},
		{ErrNoExecutionRole, http.StatusBadRequest},
		{ErrAuditUnavailable, http.StatusServiceUnavailable},
		{ErrDecisionsUnwired, http.StatusServiceUnavailable},
		{ErrExecutionFailed, http.StatusInternalServerError},
	} {
		rec := httptest.NewRecorder()
		newHandlerWithFake(&fakeService{err: tc.err}).RunDecision(rec, decisionReq(http.MethodPost, "/api/decisions/d-1/execution/run", "{}"))
		require.Equal(t, tc.want, rec.Code, tc.err.Error())
	}

	rec := httptest.NewRecorder()
	newHandlerWithFake(&fakeService{}).RunDecision(rec, decisionReq(http.MethodPost, "/api/decisions/d-1/execution/run", "not-json"))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestMarkStalledRunFailed_PassesTheAttestationThrough(t *testing.T) {
	svc := &fakeService{run: DecisionRun{Status: RunFailed, Action: ActionEC2Stop, Error: "marked failed"}}
	rec := httptest.NewRecorder()
	newHandlerWithFake(svc).MarkStalledRunFailed(rec, asRole(decisionReq(http.MethodPost,
		"/api/decisions/d-1/execution/mark-failed", `{"verified":true,"note":"instance still running"}`), auth.RoleAdmin))
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, svc.gotVerify)
	require.Equal(t, "instance still running", svc.gotNote)
	var resp decisionRunResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "failed", resp.Status)

	svc = &fakeService{}
	rec = httptest.NewRecorder()
	newHandlerWithFake(svc).MarkStalledRunFailed(rec, decisionReq(http.MethodPost, "/api/decisions/d-1/execution/mark-failed", ""))
	require.Equal(t, http.StatusOK, rec.Code, "an empty body is an unverified release")
	require.False(t, svc.gotVerify)
}

func TestPlanDecision_ResponseShape(t *testing.T) {
	expires := time.Date(2026, 10, 8, 12, 10, 0, 0, time.UTC)
	svc := &fakeService{plan: DecisionPlan{
		Target: DecisionTarget{DecisionID: "d-1"}, State: PlanReady, Action: ActionEC2Stop,
		ConnectorID: "c1", ConnectorName: "prod", Params: map[string]string{ParamInstanceID: "i-abc"},
		RequiresSecondAdmin: true, Guidance: &Guidance{Change: "stop EC2 instance i-abc", Reversible: true},
		Run: &DecisionRun{Status: RunAwaitingSecondAdmin, Action: ActionEC2Stop, RequestedBy: "alice", RequestedByID: "u-alice",
			Params: map[string]string{ParamInstanceID: "i-abc"}, GrantToken: "secret-grant", GrantExpiresAt: expires},
		Audit:      []AuditEvent{{TS: expires, Actor: "alice", Action: AuditActionApprove, Details: `{"decision_id":"d-1"}`}},
		AuditKnown: true,
	}}
	rec := httptest.NewRecorder()
	newHandlerWithFake(svc).PlanDecision(rec, asRole(decisionReq(http.MethodGet, "/api/decisions/d-1/execution", ""), auth.RoleAdmin))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotContains(t, rec.Body.String(), "secret-grant", "the grant never leaves the server")

	var resp decisionPlanResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "ready", resp.State)
	require.Equal(t, []string{}, resp.Inputs)
	require.True(t, resp.RequiresSecondAdmin)
	require.Equal(t, "awaiting_second_admin", resp.Run.Status)
	require.False(t, resp.Run.RequestedByYou)
	require.Equal(t, "2026-10-08T12:10:00Z", resp.Run.GrantExpiresAt)
	require.Equal(t, "i-abc", resp.Run.ConfirmText, "what the second admin types")
	require.Len(t, resp.Audit, 1)
}
