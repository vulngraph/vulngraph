package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

// Admin-role enforcement is at the router layer (httpsrv/server.go:145 —
// auth.RequireRole(auth.RoleAdmin, h.Executor.SGRuleRemove)). These unit tests
// verify the handler's own logic: param validation, service dispatch, and error mapping.

// fakeService satisfies the executorSvc interface used by the handler.
type fakeService struct {
	result     ExecutionResult
	err        error
	approval   Approval
	approveErr error
	gotReq     ExecutionRequest
	gotCtx     context.Context

	plan       DecisionPlan
	bound      BoundPlan
	run        DecisionRun
	gotInputs  map[string]string
	gotConfirm string
	gotVerify  bool
	gotNote    string
}

func (f *fakeService) Execute(ctx context.Context, req ExecutionRequest) (ExecutionResult, error) {
	f.gotReq, f.gotCtx = req, ctx
	return f.result, f.err
}

func (f *fakeService) Approve(ctx context.Context, req ExecutionRequest) (Approval, error) {
	f.gotReq, f.gotCtx = req, ctx
	return f.approval, f.approveErr
}

func (f *fakeService) PlanDecision(context.Context, string) (DecisionPlan, error) {
	return f.plan, f.err
}

func (f *fakeService) DryRunDecision(_ context.Context, _ string, inputs map[string]string, build RequestBuilder) (BoundPlan, ExecutionResult, error) {
	f.gotInputs, f.gotReq = inputs, build(f.bound, true)
	return f.bound, f.result, f.err
}

func (f *fakeService) RequestDecisionApproval(_ context.Context, _ string, inputs map[string]string, confirm string, build RequestBuilder) (DecisionRun, error) {
	f.gotInputs, f.gotConfirm, f.gotReq = inputs, confirm, build(f.bound, false)
	return f.run, f.err
}

func (f *fakeService) RunDecision(_ context.Context, _ string, inputs map[string]string, confirm string, build RequestBuilder) (DecisionRun, ExecutionResult, error) {
	f.gotInputs, f.gotConfirm, f.gotReq = inputs, confirm, build(f.bound, false)
	return f.run, f.result, f.err
}

func (f *fakeService) MarkStalledRunFailed(_ context.Context, _ string, verified bool, note string) (DecisionRun, error) {
	f.gotVerify, f.gotNote = verified, note
	return f.run, f.err
}

func newHandlerWithFake(svc *fakeService) *Handler {
	return &Handler{svc: svc}
}

func TestSGRuleRemove_MissingConnectorID_400(t *testing.T) {
	h := newHandlerWithFake(&fakeService{})
	body, _ := json.Marshal(sgRuleRemoveRequest{GroupID: "sg-123", Region: "eu-west-1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/sg-rule-remove", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.SGRuleRemove(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSGRuleRemove_BadJSON_400(t *testing.T) {
	h := newHandlerWithFake(&fakeService{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/sg-rule-remove", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	h.SGRuleRemove(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSGRuleRemove_ServiceError_500(t *testing.T) {
	h := newHandlerWithFake(&fakeService{err: ErrExecutionFailed})
	body, _ := json.Marshal(sgRuleRemoveRequest{ConnectorID: "c1", GroupID: "sg-123", Region: "eu-west-1", Protocol: "tcp", FromPort: "443", ToPort: "443", CIDR: "0.0.0.0/0"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/sg-rule-remove", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.SGRuleRemove(rec, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSGRuleRemove_CapabilityMissing_400(t *testing.T) {
	h := newHandlerWithFake(&fakeService{err: ErrCapabilityMissing})
	body, _ := json.Marshal(sgRuleRemoveRequest{ConnectorID: "c1", GroupID: "sg-123", Region: "eu-west-1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/sg-rule-remove", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.SGRuleRemove(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSGRuleRemove_Success_200(t *testing.T) {
	h := newHandlerWithFake(&fakeService{result: ExecutionResult{ConnectorID: "c1", Action: ActionSGRuleRemove, Detail: "removed rule"}})
	body, _ := json.Marshal(sgRuleRemoveRequest{ConnectorID: "c1", GroupID: "sg-123", Region: "eu-west-1", Protocol: "tcp", FromPort: "443", ToPort: "443", CIDR: "0.0.0.0/0"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/sg-rule-remove", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.SGRuleRemove(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp executionResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "sg_rule_remove", resp.Action)
}

func TestIAMKeyDisable_MissingConnectorID_400(t *testing.T) {
	h := newHandlerWithFake(&fakeService{})
	body, _ := json.Marshal(iamKeyDisableRequest{KeyID: "AKIA123", Username: "deploy"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/iam-key-disable", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.IAMKeyDisable(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestIAMKeyDisable_Success_200(t *testing.T) {
	h := newHandlerWithFake(&fakeService{result: ExecutionResult{ConnectorID: "c1", Action: ActionIAMKeyDisable, Detail: "key disabled"}})
	body, _ := json.Marshal(iamKeyDisableRequest{ConnectorID: "c1", KeyID: "AKIA123", Username: "deploy"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/iam-key-disable", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.IAMKeyDisable(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

// ---- POST /api/executor/approvals ----
//
// Admin-role enforcement for this route lives in the router
// (httpsrv/server.go — auth.RequireRole(auth.RoleAdmin, h.Executor.Approve)),
// is DERIVED from the source by httpsrv.adminGatedRoutes, and is probed for
// viewer-403 / anon-401 by TestServerRouting_AllWritesRequireAdmin. These tests
// cover the handler's own logic.

func TestApprove_MissingFields_400(t *testing.T) {
	h := newHandlerWithFake(&fakeService{})
	body, _ := json.Marshal(approvalRequest{ConnectorID: "c1"}) // no action
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/approvals", bytes.NewReader(body))
	h.Approve(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestApprove_BadJSON_400(t *testing.T) {
	h := newHandlerWithFake(&fakeService{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/approvals", bytes.NewReader([]byte("not-json")))
	h.Approve(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// Asking to approve something that needs no approval is a 400, not a grant:
// handing back a token nobody will check would read as a control and be none.
func TestApprove_NotRequired_400(t *testing.T) {
	h := newHandlerWithFake(&fakeService{approveErr: ErrApprovalNotRequired})
	body, _ := json.Marshal(approvalRequest{ConnectorID: "c1", Action: "s3_block_public"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/approvals", bytes.NewReader(body))
	h.Approve(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestApprove_Success_200_ReturnsThePlanItBinds(t *testing.T) {
	h := newHandlerWithFake(&fakeService{approval: Approval{
		Token: "tok", Plan: "stop EC2 instance i-abc in eu-west-1", Approver: "alice@example.com",
		ExpiresAt: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC),
	}})
	body, _ := json.Marshal(approvalRequest{ConnectorID: "c1", Action: "ec2_stop"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/approvals", bytes.NewReader(body))
	h.Approve(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp approvalResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, "tok", resp.ApprovalToken)
	require.Equal(t, "stop EC2 instance i-abc in eu-west-1", resp.Plan,
		"the approver must see in the response exactly what they authorised")
	require.Equal(t, "2026-08-04T12:00:00Z", resp.ExpiresAt)
}

// A missing approval is an authorisation problem, not a malformed request.
func TestExecute_ApprovalRequired_403(t *testing.T) {
	h := newHandlerWithFake(&fakeService{err: ErrApprovalRequired})
	body, _ := json.Marshal(executeRequest{ConnectorID: "c1", Action: "ec2_stop"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/execute", bytes.NewReader(body))
	h.Execute(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestExecute_ApprovalInvalid_403(t *testing.T) {
	h := newHandlerWithFake(&fakeService{err: ErrApprovalInvalid})
	body, _ := json.Marshal(executeRequest{ConnectorID: "c1", Action: "ec2_stop", ApprovalToken: "stale"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/execute", bytes.NewReader(body))
	h.Execute(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

// dry_run and approval_token must reach the service — a handler that dropped
// dry_run would silently perform the mutation the caller asked to preview.
func TestExecute_PassesDryRunAndApprovalTokenThrough(t *testing.T) {
	svc := &fakeService{result: ExecutionResult{ConnectorID: "c1", Action: ActionEC2Stop, DryRun: true, Destructive: true}}
	h := newHandlerWithFake(svc)
	body, _ := json.Marshal(executeRequest{ConnectorID: "c1", Action: "ec2_stop", DryRun: true, ApprovalToken: "tok"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/execute", bytes.NewReader(body))
	h.Execute(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, svc.gotReq.DryRun, "dry_run was dropped by the handler")
	require.Equal(t, "tok", svc.gotReq.ApprovalToken)

	var resp executionResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.True(t, resp.DryRun)
	require.True(t, resp.Destructive)
}

func TestIAMKeyDisable_PassesDryRunAndApprovalTokenThrough(t *testing.T) {
	svc := &fakeService{result: ExecutionResult{ConnectorID: "c1", Action: ActionIAMKeyDisable}}
	h := newHandlerWithFake(svc)
	body, _ := json.Marshal(iamKeyDisableRequest{
		ConnectorID: "c1", KeyID: "AKIA1", Username: "deploy",
		DeleteKey: true, DryRun: true, ApprovalToken: "tok",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/iam-key-disable", bytes.NewReader(body))
	h.IAMKeyDisable(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, svc.gotReq.DryRun)
	require.Equal(t, "tok", svc.gotReq.ApprovalToken)
	require.Equal(t, "true", svc.gotReq.Params[ParamDeleteKey])
}

func TestSGRuleRemove_PassesDryRunThrough(t *testing.T) {
	svc := &fakeService{result: ExecutionResult{ConnectorID: "c1", Action: ActionSGRuleRemove}}
	h := newHandlerWithFake(svc)
	body, _ := json.Marshal(sgRuleRemoveRequest{ConnectorID: "c1", GroupID: "sg-1", DryRun: true})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/executor/aws/sg-rule-remove", bytes.NewReader(body))
	h.SGRuleRemove(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, svc.gotReq.DryRun)
}

// The agent flag mints the grant an MCP execution needs.
func TestApprove_PassesAgentFlag(t *testing.T) {
	svc := &fakeService{}
	h := newHandlerWithFake(svc)
	body, _ := json.Marshal(approvalRequest{ConnectorID: "c1", Action: "ec2_start", Agent: true})
	h.Approve(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/executor/approvals", bytes.NewReader(body)))
	require.True(t, svc.gotReq.RequireGrant)
}

type ownerKeys map[string]auth.APIKeyRecord

func (k ownerKeys) Verify(_ context.Context, plaintext string) (auth.APIKeyRecord, error) {
	if rec, ok := k[plaintext]; ok {
		return rec, nil
	}
	return auth.APIKeyRecord{}, errors.New("unknown key")
}

// Behind a proxy every request shares the proxy's TCP address, so the
// same-address flag must use the client address RequireAuth resolved from the
// trusted CLIENT_IP_HEADER. Wired end to end: RequireAuth → Handler → Service.
func TestSameAddressFlag_UsesTheTrustedClientIP(t *testing.T) {
	old := time.Now().Add(-365 * 24 * time.Hour)
	keys := ownerKeys{
		"gph_bob": {ID: "k2", UserID: "u-bob", Scope: "admin", OwnerEmail: "bob@example.com", OwnerRole: auth.RoleAdmin, OwnerCreatedAt: old},
	}
	authH := auth.NewHandler(auth.NewService(nil)).WithAPIKeys(keys).WithClientIPHeader("X-Forwarded-For", netip.MustParsePrefix("10.0.0.1/32"))
	audit := &fakeAuditor{}
	h := NewHandler(NewService(awsRW()).WithAudit(audit).WithApprovals(testApprover(t)))
	params := map[string]string{ParamInstanceID: "i-1"}

	// The approver signs in with a session (an API key cannot mint a grant);
	// RequireAuth's session path attaches the user and the resolved client IP.
	approve := func(clientIP string) approvalResponse {
		b, _ := json.Marshal(approvalRequest{ConnectorID: "conn-1", Action: string(ActionEC2Stop), Params: params})
		ctx := auth.ContextWithClientIP(adminCtx("alice@example.com"), clientIP)
		rec := httptest.NewRecorder()
		h.Approve(rec, httptest.NewRequest(http.MethodPost, "/api/executor/approvals", bytes.NewReader(b)).WithContext(ctx))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var grant approvalResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &grant))
		return grant
	}
	call := func(handler http.HandlerFunc, key, clientIP string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/executor", bytes.NewReader(b))
		req.RemoteAddr = "10.0.0.1:443" // the proxy, identical for every caller
		req.Header.Set("X-Forwarded-For", clientIP)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		authH.RequireAuth(handler)(rec, req)
		return rec
	}

	execute := executeRequest{ConnectorID: "conn-1", Action: string(ActionEC2Stop), Params: params, ApprovalToken: approve("203.0.113.7").ApprovalToken}
	audit.events = nil
	call(h.Execute, "gph_bob", "198.51.100.9", execute)
	require.NotEmpty(t, audit.events)
	for _, e := range audit.events {
		require.NotContains(t, details(t, e), "approver_same_ip", "different clients behind one proxy are not flagged")
	}

	// A grant runs one execution, so the same-address case needs a fresh one.
	execute.ApprovalToken = approve("203.0.113.7").ApprovalToken
	audit.events = nil
	call(h.Execute, "gph_bob", "203.0.113.7", execute)
	require.NotEmpty(t, audit.events)
	for _, e := range audit.events {
		require.Equal(t, true, details(t, e)["approver_same_ip"], e.Action)
	}
}

// A refused intent write is an availability problem, not a server bug.
func TestExecute_AuditUnavailable_503(t *testing.T) {
	h := newHandlerWithFake(&fakeService{err: ErrAuditUnavailable})
	body, _ := json.Marshal(executeRequest{ConnectorID: "c1", Action: "ec2_start"})
	rec := httptest.NewRecorder()
	h.Execute(rec, httptest.NewRequest(http.MethodPost, "/api/executor/execute", bytes.NewReader(body)))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
