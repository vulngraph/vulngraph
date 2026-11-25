package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/connector"
)

// An API key may be held by an agent, so over REST it gets exactly what the MCP
// execute_action tool gets (ADR 087): no change runs on it without a grant a
// DIFFERENT admin minted from a session, and it can never mint one itself.

const (
	aliceKey = "gph_alice"
	bobKey   = "gph_bob"
)

func adminKeys() ownerKeys {
	old := time.Now().Add(-365 * 24 * time.Hour)
	return ownerKeys{
		aliceKey: {ID: "k1", UserID: "uid:alice@example.com", Scope: "admin", OwnerEmail: "alice@example.com", OwnerRole: auth.RoleAdmin, OwnerCreatedAt: old},
		bobKey:   {ID: "k2", UserID: "uid:bob@example.com", Scope: "admin", OwnerEmail: "bob@example.com", OwnerRole: auth.RoleAdmin, OwnerCreatedAt: old},
	}
}

// keyCtx is adminCtx authenticated with an API key instead of a session.
func keyCtx(email string) context.Context {
	return auth.ContextWithAPIKey(adminCtx(email), auth.APIKeyRecord{ID: "k:" + email, UserID: "uid:" + email})
}

// countingCall stubs the cloud call and counts how often it is reached.
func countingCall(svc *Service) *int {
	n := 0
	svc.call = func(context.Context, connector.Connector, Action, map[string]string) (ExecutionResult, error) {
		n++
		return ExecutionResult{ConnectorID: "conn-1", Detail: "done"}, nil
	}
	return &n
}

func TestExecutorREST_APIKeyNeedsADifferentAdminsGrant(t *testing.T) {
	authH := auth.NewHandler(auth.NewService(nil)).WithAPIKeys(adminKeys())
	svc := NewService(&fakeConnectors{c: execConnector()}).WithAudit(&fakeAuditor{}).WithApprovals(testApprover(t))
	calls := countingCall(svc)
	h := NewHandler(svc)

	post := func(body any) *http.Request {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		return httptest.NewRequest(http.MethodPost, "/api/executor", bytes.NewReader(b))
	}
	keyed := func(handler http.HandlerFunc, key string, body any) *httptest.ResponseRecorder {
		req := post(body)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		authH.RequireAuth(handler)(rec, req)
		return rec
	}
	// session is what RequireAuth's session path attaches: the user, no key.
	session := func(handler http.HandlerFunc, email string, body any) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler(rec, post(body).WithContext(adminCtx(email)))
		return rec
	}

	start := executeRequest{ConnectorID: "conn-1", Action: string(ActionS3BlockPublic), Params: map[string]string{ParamBucketName: "logs-bucket"}}
	sgRule := sgRuleRemoveRequest{ConnectorID: "conn-1", GroupID: "sg-1", Region: "eu-west-1", Protocol: "tcp",
		FromPort: "22", ToPort: "22", CIDR: "0.0.0.0/0"}
	iamKey := iamKeyDisableRequest{ConnectorID: "conn-1", KeyID: "AKIA123", Username: "svc"}

	// Non-destructive actions, no grant: refused on every route.
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"execute":         keyed(h.Execute, aliceKey, start),
		"sg-rule-remove":  keyed(h.SGRuleRemove, aliceKey, sgRule),
		"iam-key-disable": keyed(h.IAMKeyDisable, aliceKey, iamKey),
	} {
		require.Equalf(t, http.StatusForbidden, rec.Code, "%s: %s", name, rec.Body.String())
		require.Containsf(t, rec.Body.String(), "approval grant", name)
	}
	require.Zero(t, *calls, "nothing reached the cloud")

	// A key cannot mint a grant, for itself or for anyone else — and it gets
	// the same 403 for a non-destructive action without agent, not the 400 a
	// session gets for asking for a grant nothing checks.
	rec := keyed(h.Approve, aliceKey, approvalRequest{ConnectorID: "conn-1", Action: start.Action, Params: start.Params, Agent: true})
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	rec = keyed(h.Approve, aliceKey, approvalRequest{ConnectorID: "conn-1", Action: start.Action, Params: start.Params})
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	rec = session(h.Approve, "alice@example.com", approvalRequest{ConnectorID: "conn-1", Action: start.Action, Params: start.Params})
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// The key holder's own session grant does not let their key run it.
	rec = session(h.Approve, "alice@example.com", approvalRequest{ConnectorID: "conn-1", Action: start.Action, Params: start.Params, Agent: true})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var grant approvalResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &grant))
	withOwnGrant := start
	withOwnGrant.ApprovalToken = grant.ApprovalToken
	rec = keyed(h.Execute, aliceKey, withOwnGrant)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	require.Zero(t, *calls)

	// A different admin's session grant: the key's execution runs.
	rec = session(h.Approve, "bob@example.com", approvalRequest{ConnectorID: "conn-1", Action: start.Action, Params: start.Params, Agent: true})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &grant))
	granted := start
	granted.ApprovalToken = grant.ApprovalToken
	rec = keyed(h.Execute, aliceKey, granted)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 1, *calls)

	rec = session(h.Approve, "bob@example.com", approvalRequest{ConnectorID: "conn-1", Action: string(ActionSGRuleRemove), Agent: true,
		Params: map[string]string{ParamGroupID: "sg-1", ParamRegion: "eu-west-1", ParamProtocol: "tcp",
			ParamFromPort: "22", ParamToPort: "22", ParamCIDR: "0.0.0.0/0"}})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &grant))
	sgRule.ApprovalToken = grant.ApprovalToken
	rec = keyed(h.SGRuleRemove, aliceKey, sgRule)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 2, *calls)

	// A session admin is unchanged: a non-destructive action runs on their yes.
	rec = session(h.Execute, "alice@example.com", start)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 3, *calls)
}

// Approve-and-run holds the same line: a key cannot run a one-admin fix, cannot
// be the first admin of a two-admin one, and may only confirm a request a
// different admin made from a session.
func TestRunDecision_APIKeyNeedsADifferentAdminsRequest(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	calls := countingCall(f.svc)

	_, _, err := f.svc.RunDecision(keyCtx("alice@example.com"), "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalRequired)
	require.Empty(t, f.runs.rows, "the decision was not claimed")

	_, err = f.svc.RequestDecisionApproval(keyCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalInvalid, "a key cannot mint the grant")
	require.Empty(t, f.runs.rows)
	require.Zero(t, *calls)

	_, err = f.svc.RequestDecisionApproval(adminCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.NoError(t, err)
	run, _, err := f.svc.RunDecision(keyCtx("bob@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.NoError(t, err)
	require.Equal(t, RunSucceeded, run.Status)
	require.Equal(t, 1, *calls)

	// A session admin still runs a one-admin fix on their own yes.
	run, _, err = f.svc.RunDecision(adminCtx("alice@example.com"), "d-s3", nil, "", decisionRequest)
	require.NoError(t, err)
	require.Equal(t, RunSucceeded, run.Status)
	require.Equal(t, 2, *calls)
}

// A key gets 403 on both decision routes whatever the decision: a fix that
// needs no second admin, a wrong confirmation, an unknown decision. Request
// checks the key before anything about the decision, so it never answers a
// key with the 400 or 404 a session would get.
func TestRunDecisionREST_APIKey_403(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	calls := countingCall(f.svc)
	authH := auth.NewHandler(auth.NewService(nil)).WithAPIKeys(adminKeys())
	h := NewHandler(f.svc)

	cases := []struct {
		name, route, decision, confirm string
		handler                        http.HandlerFunc
	}{
		{"run one-admin fix", "run", "d-s3", "", h.RunDecision},
		{"request destructive fix", "request", "d-stop", "i-abc", h.RequestDecisionApproval},
		{"request one-admin fix", "request", "d-s3", "", h.RequestDecisionApproval},
		{"request wrong confirmation", "request", "d-stop", "wrong", h.RequestDecisionApproval},
		{"request unknown decision", "request", "d-missing", "", h.RequestDecisionApproval},
	}
	for _, tc := range cases {
		body, err := json.Marshal(map[string]string{"confirm": tc.confirm})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/decisions/"+tc.decision+"/execution/"+tc.route, bytes.NewReader(body))
		req.SetPathValue("id", tc.decision)
		req.Header.Set("Authorization", "Bearer "+aliceKey)
		rec := httptest.NewRecorder()
		authH.RequireAuth(tc.handler)(rec, req)
		require.Equalf(t, http.StatusForbidden, rec.Code, "%s: %s", tc.name, rec.Body.String())
	}
	require.Empty(t, f.runs.rows)
	require.Zero(t, *calls)
}

// Every refusal of who asked leaves an executor.refused row naming the actor,
// the stage and the decision, so an agent's key probing for a grant is as
// visible in the trail as an execution.
func TestRefusalsAreAudited(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	countingCall(f.svc)

	refusals := func() []map[string]any {
		var out []map[string]any
		for _, e := range f.audit.events {
			if e.Action != AuditActionRefused {
				continue
			}
			var d map[string]any
			require.NoError(t, json.Unmarshal([]byte(e.Details), &d))
			d["actor"] = e.Actor
			out = append(out, d)
		}
		return out
	}

	_, err := f.svc.Approve(keyCtx("alice@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-abc"}})
	require.ErrorIs(t, err, ErrApprovalInvalid)
	_, err = f.svc.Approve(youngAdminCtx("carol@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-abc"}})
	require.ErrorIs(t, err, ErrApprovalInvalid)
	_, err = f.svc.RequestDecisionApproval(keyCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalInvalid)
	_, _, err = f.svc.RunDecision(keyCtx("alice@example.com"), "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalRequired)
	_, _, err = f.svc.RunDecision(adminCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalRequired)
	_, err = f.svc.RequestDecisionApproval(adminCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.NoError(t, err)
	_, _, err = f.svc.RunDecision(adminCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalInvalid)

	got := refusals()
	require.Len(t, got, 6)
	want := []struct{ actor, stage, decision string }{
		{"alice@example.com", "approve", ""},
		{"carol@example.com", "approve", ""},
		{"alice@example.com", "request_decision_approval", "d-stop"},
		{"alice@example.com", "run_decision", "d-s3"},
		{"alice@example.com", "run_decision", "d-stop"},
		{"alice@example.com", "run_decision", "d-stop"},
	}
	for i, w := range want {
		require.Equalf(t, w.actor, got[i]["actor"], "row %d", i)
		require.Equalf(t, w.stage, got[i]["stage"], "row %d", i)
		if w.decision != "" {
			require.Equalf(t, w.decision, got[i]["decision_id"], "row %d", i)
		}
		require.NotEmptyf(t, got[i]["error"], "row %d", i)
		require.NotEmptyf(t, got[i]["actor_user_id"], "row %d", i)
	}

	// An input error is not a refusal of who asked: no row.
	_, err = f.svc.RequestDecisionApproval(adminCtx("bob@example.com"), "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalNotRequired)
	require.Len(t, refusals(), 6)
}
