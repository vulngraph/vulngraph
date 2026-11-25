package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// executorSvc is the narrow interface Handler needs — *Service satisfies it.
type executorSvc interface {
	Execute(ctx context.Context, req ExecutionRequest) (ExecutionResult, error)
	Approve(ctx context.Context, req ExecutionRequest) (Approval, error)
	PlanDecision(ctx context.Context, decisionID string) (DecisionPlan, error)
	DryRunDecision(ctx context.Context, decisionID string, inputs map[string]string, build RequestBuilder) (BoundPlan, ExecutionResult, error)
	RequestDecisionApproval(ctx context.Context, decisionID string, inputs map[string]string, confirm string, build RequestBuilder) (DecisionRun, error)
	RunDecision(ctx context.Context, decisionID string, inputs map[string]string, confirm string, build RequestBuilder) (DecisionRun, ExecutionResult, error)
	MarkStalledRunFailed(ctx context.Context, decisionID string, verified bool, note string) (DecisionRun, error)
}

// Handler exposes executor actions over HTTP. All routes require admin role
// (enforced by auth.RequireRole in the router — see httpsrv/server.go).
type Handler struct {
	svc executorSvc
}

// NewHandler constructs an executor Handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// sgRuleRemoveRequest is the JSON body for POST /api/executor/aws/sg-rule-remove.
type sgRuleRemoveRequest struct {
	ConnectorID string `json:"connector_id"`
	GroupID     string `json:"group_id"`
	Region      string `json:"region"`
	Protocol    string `json:"protocol"`
	FromPort    string `json:"from_port"`
	ToPort      string `json:"to_port"`
	CIDR        string `json:"cidr"`
	// DryRun reports what would change without changing it.
	DryRun bool `json:"dry_run,omitempty"`
	// ApprovalToken is a grant from POST /api/executor/approvals, minted by a
	// different admin. Required when the request authenticates with an API key.
	ApprovalToken string `json:"approval_token,omitempty"`
}

// iamKeyDisableRequest is the JSON body for POST /api/executor/aws/iam-key-disable.
type iamKeyDisableRequest struct {
	ConnectorID string `json:"connector_id"`
	KeyID       string `json:"key_id"`
	Username    string `json:"username"`
	// Region is optional — falls back to the connector's configured region.
	Region string `json:"region,omitempty"`
	// DeleteKey=true physically deletes the key after disabling it. That
	// variant is destructive and needs an approval grant.
	DeleteKey bool `json:"delete_key,omitempty"`
	// DryRun reports what would change without changing it.
	DryRun bool `json:"dry_run,omitempty"`
	// ApprovalToken is a grant from POST /api/executor/approvals, minted by a
	// different admin. Required when delete_key is true, and for any request
	// authenticated with an API key.
	ApprovalToken string `json:"approval_token,omitempty"`
}

// executionResponse is the JSON shape returned on success.
type executionResponse struct {
	ConnectorID string `json:"connector_id"`
	Action      string `json:"action"`
	Detail      string `json:"detail"`
	// DryRun is true when nothing was changed.
	DryRun bool `json:"dry_run"`
	// Destructive is true when this action needs a second admin's approval.
	Destructive bool `json:"destructive"`
}

// SGRuleRemove handles POST /api/executor/aws/sg-rule-remove.
// Requires admin role (enforced in router via auth.RequireRole).
func (h *Handler) SGRuleRemove(w http.ResponseWriter, r *http.Request) {
	var req sgRuleRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	if req.ConnectorID == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("connector_id is required"))
		return
	}

	result, err := h.svc.Execute(r.Context(), ExecutionRequest{
		ConnectorID: req.ConnectorID,
		Action:      ActionSGRuleRemove,
		Params: map[string]string{
			ParamGroupID:  req.GroupID,
			ParamRegion:   req.Region,
			ParamProtocol: req.Protocol,
			ParamFromPort: req.FromPort,
			ParamToPort:   req.ToPort,
			ParamCIDR:     req.CIDR,
		},
		DryRun:        req.DryRun,
		ApprovalToken: req.ApprovalToken,
	})
	h.writeResult(w, r, result, err)
}

// IAMKeyDisable handles POST /api/executor/aws/iam-key-disable.
// Requires admin role (enforced in router via auth.RequireRole).
func (h *Handler) IAMKeyDisable(w http.ResponseWriter, r *http.Request) {
	var req iamKeyDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	if req.ConnectorID == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("connector_id is required"))
		return
	}

	deleteKeyStr := "false"
	if req.DeleteKey {
		deleteKeyStr = "true"
	}

	result, err := h.svc.Execute(r.Context(), ExecutionRequest{
		ConnectorID: req.ConnectorID,
		Action:      ActionIAMKeyDisable,
		Params: map[string]string{
			ParamKeyID:     req.KeyID,
			ParamUsername:  req.Username,
			ParamRegion:    req.Region,
			ParamDeleteKey: deleteKeyStr,
		},
		DryRun:        req.DryRun,
		ApprovalToken: req.ApprovalToken,
	})
	h.writeResult(w, r, result, err)
}

// writeResult maps domain errors to HTTP status codes and writes the response.
func (h *Handler) writeResult(w http.ResponseWriter, r *http.Request, result ExecutionResult, err error) {
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toExecutionResponse(result))
}

func toExecutionResponse(result ExecutionResult) executionResponse {
	return executionResponse{
		ConnectorID: result.ConnectorID,
		Action:      string(result.Action),
		Detail:      result.Detail,
		DryRun:      result.DryRun,
		Destructive: result.Destructive,
	}
}

// writeError maps a domain error to its problem response.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrDecisionNotFound):
		errs.WriteHTTPError(w, errs.NotFound("decision not found"))
	case errors.Is(err, ErrNotRunnable), errors.Is(err, ErrRunConflict), errors.Is(err, ErrRunNotStalled),
		errors.Is(err, ErrCloudStateUnverified):
		errs.WriteHTTPError(w, errs.Conflict(err.Error()))
	case errors.Is(err, ErrConfirmationMismatch), errors.Is(err, ErrApprovalNotRequired):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
	case errors.Is(err, ErrDecisionsUnwired):
		errs.WriteHTTPError(w, errs.Unavailable("approve-and-run is not configured on this server"))
	case errors.Is(err, ErrBadParams):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
	case errors.Is(err, ErrCapabilityMissing):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
	case errors.Is(err, ErrNoExecutionRole):
		// A configuration gap, not a caller mistake — but the caller is the one
		// who can fix it, and the message names the missing config key.
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
	case errors.Is(err, ErrApprovalRequired), errors.Is(err, ErrApprovalInvalid), errors.Is(err, ErrNoPrincipal),
		errors.Is(err, ErrBypassAuth):
		// 403: the request is well-formed — what is missing is a person's
		// authorisation (a second admin's grant, or an identified principal).
		errs.WriteHTTPError(w, errs.Forbidden(err.Error()))
	case errors.Is(err, ErrAuditUnavailable):
		log.FromContext(r.Context()).Error().Err(err).Msg("executor: refused, audit trail unavailable")
		errs.WriteHTTPError(w, errs.Unavailable("the audit trail is unavailable, so nothing was executed"))
	case errors.Is(err, ErrOutcomeUnknown):
		log.FromContext(r.Context()).Error().Err(err).Msg("executor: cloud call cut off; outcome unknown")
		errs.WriteHTTPError(w, errs.Internal(ErrOutcomeUnknown.Error()))
	case errors.Is(err, ErrExecutionFailed):
		log.FromContext(r.Context()).Error().Err(err).Msg("executor: execution failed")
		errs.WriteHTTPError(w, errs.Internal("execution failed"))
	default:
		log.FromContext(r.Context()).Error().Err(err).Msg("executor: unexpected error")
		errs.WriteHTTPError(w, errs.Internal("internal error"))
	}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("executor: write response failed")
	}
}

// executeRequest is the JSON body for POST /api/executor/execute (the generic A2A endpoint).
type executeRequest struct {
	ConnectorID string            `json:"connector_id"`
	Action      string            `json:"action"`
	Params      map[string]string `json:"params"`
	// DryRun resolves and describes the change without performing it.
	DryRun bool `json:"dry_run,omitempty"`
	// ApprovalToken is a grant from POST /api/executor/approvals, minted by a
	// different admin. Required for the destructive subset of actions, and for
	// every action when the request authenticates with an API key.
	ApprovalToken string `json:"approval_token,omitempty"`
}

// Execute handles POST /api/executor/execute — the generic admin endpoint for
// explicit execution of any registered action; an API-key caller (which may
// be an agent) also needs a grant minted by a different admin.
//
// This is an explicit operator surface, deliberately role-gated (admin) rather
// than policy-gated: the policy gate + CoVe decide how the decision
// pipeline (respond.Decide) PROPOSES a fix, while this endpoint is a person
// issuing the explicit command that carries one out — the human "yes" ADR 087
// requires. What applies: an authenticated principal, admin role, read_write
// connector mode, a known action with validated params, an EXECUTION principal
// distinct from the collection credential, an approval grant for the
// destructive subset (for every action on an API key, which an agent may
// hold), and an audit row for every attempt including dry runs.
func (h *Handler) Execute(w http.ResponseWriter, r *http.Request) {
	var req executeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	if req.ConnectorID == "" || req.Action == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("connector_id and action are required"))
		return
	}
	result, err := h.svc.Execute(r.Context(), ExecutionRequest{
		ConnectorID:   req.ConnectorID,
		Action:        Action(req.Action),
		Params:        req.Params,
		DryRun:        req.DryRun,
		ApprovalToken: req.ApprovalToken,
	})
	h.writeResult(w, r, result, err)
}

// approvalRequest is the JSON body for POST /api/executor/approvals. It names
// the exact execution being approved — same shape as executeRequest minus the
// fields an approval cannot carry.
type approvalRequest struct {
	ConnectorID string            `json:"connector_id"`
	Action      string            `json:"action"`
	Params      map[string]string `json:"params"`
	// Agent mints a grant for an agent's execution (the MCP execute_action
	// tool), which needs one for every action, destructive or not.
	Agent bool `json:"agent,omitempty"`
}

// approvalResponse hands back the grant plus the plan it is bound to, so the
// approving admin sees in the response exactly what they authorised.
type approvalResponse struct {
	ApprovalToken string `json:"approval_token"`
	Plan          string `json:"plan"`
	Approver      string `json:"approver"`
	ExpiresAt     string `json:"expires_at"`
}

// Approve handles POST /api/executor/approvals — mint a grant for one
// destructive or agent execution.
//
// The approving admin comes from the session, never from the body, and the
// executing admin must be someone else: this endpoint is the second half of a
// two-person control, so a caller who could name their own approver would have
// built nothing. Requires admin role (enforced in the router) and a session:
// the service refuses an API key, which an agent may hold.
func (h *Handler) Approve(w http.ResponseWriter, r *http.Request) {
	var req approvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	if req.ConnectorID == "" || req.Action == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("connector_id and action are required"))
		return
	}
	approval, err := h.svc.Approve(r.Context(), ExecutionRequest{
		ConnectorID:  req.ConnectorID,
		Action:       Action(req.Action),
		Params:       req.Params,
		RequireGrant: req.Agent,
	})
	switch {
	case errors.Is(err, ErrBadParams), errors.Is(err, ErrCapabilityMissing), errors.Is(err, ErrApprovalNotRequired):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	case errors.Is(err, ErrApprovalRequired), errors.Is(err, ErrApprovalInvalid):
		errs.WriteHTTPError(w, errs.Forbidden(err.Error()))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("executor: mint approval failed")
		errs.WriteHTTPError(w, errs.Internal("internal error"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, approvalResponse{
		ApprovalToken: approval.Token,
		Plan:          approval.Plan,
		Approver:      approval.Approver,
		ExpiresAt:     approval.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// ── Approve-and-run from a decision ──────────────────────────────────────────
//
// /api/decisions/{id}/execution*: the decision panel's flow over the same
// Execute/Approve path as the endpoints above. Every route is admin-gated in
// the router; RunDecision additionally refuses without a principal and, for a
// fix that needs two people, without a different admin's live request.

// decisionRequest builds the ExecutionRequest for a decision's bound plan. It
// lives here, in the HTTP transport, so a request is still only ever built
// where a person stands behind it (TestOnlyHumanTransportsBuildExecutionRequests).
func decisionRequest(p BoundPlan, dryRun bool) ExecutionRequest {
	return ExecutionRequest{
		ConnectorID:   p.ConnectorID,
		Action:        p.Action,
		Params:        p.Params,
		DryRun:        dryRun,
		ApprovalToken: p.GrantToken,
		DecisionID:    p.Target.DecisionID,
		Reason:        "approve and run from decision " + p.Target.DecisionID,
	}
}

// decisionRunRequest is the body of the dry-run, request and run routes.
type decisionRunRequest struct {
	// Inputs are the parameters the finding does not carry (the plan's inputs).
	Inputs map[string]string `json:"inputs,omitempty"`
	// Confirm is the typed confirmation for a destructive or irreversible fix.
	Confirm string `json:"confirm,omitempty"`
}

type decisionGuideResponse struct {
	Change     string `json:"change"`
	Reversible bool   `json:"reversible"`
	Rollback   string `json:"rollback"`
	CLI        string `json:"cli"`
}

type decisionRunResponse struct {
	Status      string            `json:"status"`
	Action      string            `json:"action"`
	ConnectorID string            `json:"connector_id"`
	Params      map[string]string `json:"params"`
	Plan        string            `json:"plan"`
	RequestedBy string            `json:"requested_by"`
	// RequestedByYou tells the panel whether this session is the first admin
	// (who waits) or a possible second one (who may confirm).
	RequestedByYou bool   `json:"requested_by_you"`
	ExecutedBy     string `json:"executed_by,omitempty"`
	Detail         string `json:"detail,omitempty"`
	Error          string `json:"error,omitempty"`
	// GrantExpiresAt and ConfirmText (what the second admin types) are set
	// while awaiting a second admin.
	GrantExpiresAt string `json:"grant_expires_at,omitempty"`
	ConfirmText    string `json:"confirm_text,omitempty"`
	UpdatedAt      string `json:"updated_at"`
}

type decisionAuditResponse struct {
	TS      string `json:"ts"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Details string `json:"details"`
}

type decisionPlanResponse struct {
	DecisionID          string                  `json:"decision_id"`
	State               string                  `json:"state"`
	Reason              string                  `json:"reason,omitempty"`
	Action              string                  `json:"action,omitempty"`
	ConnectorID         string                  `json:"connector_id,omitempty"`
	ConnectorName       string                  `json:"connector_name,omitempty"`
	Params              map[string]string       `json:"params"`
	Inputs              []string                `json:"inputs"`
	RequiresSecondAdmin bool                    `json:"requires_second_admin"`
	Guide               *decisionGuideResponse  `json:"guide,omitempty"`
	Run                 *decisionRunResponse    `json:"run,omitempty"`
	Audit               []decisionAuditResponse `json:"audit"`
	// AuditKnown is false when the run's audit rows could not be read.
	AuditKnown bool `json:"audit_known"`
}

type decisionDryRunResponse struct {
	Action      string            `json:"action"`
	ConnectorID string            `json:"connector_id"`
	Params      map[string]string `json:"params"`
	Detail      string            `json:"detail"`
	Destructive bool              `json:"destructive"`
	// ConfirmText is what to type to confirm; empty when a click is enough.
	ConfirmText string `json:"confirm_text"`
}

type decisionRunResultResponse struct {
	Run    decisionRunResponse `json:"run"`
	Result executionResponse   `json:"result"`
}

// PlanDecision handles GET /api/decisions/{id}/execution — what approve-and-run
// would do, or why it cannot, plus the run's state and audit rows.
func (h *Handler) PlanDecision(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.PlanDecision(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	resp := decisionPlanResponse{
		DecisionID: p.Target.DecisionID, State: string(p.State), Reason: p.Reason,
		Action: string(p.Action), ConnectorID: p.ConnectorID, ConnectorName: p.ConnectorName,
		Params: nonNil(p.Params), Inputs: p.Inputs, RequiresSecondAdmin: p.RequiresSecondAdmin,
		Audit: make([]decisionAuditResponse, len(p.Audit)), AuditKnown: p.AuditKnown,
	}
	if resp.Inputs == nil {
		resp.Inputs = []string{}
	}
	if g := p.Guidance; g != nil {
		resp.Guide = &decisionGuideResponse{Change: g.Change, Reversible: g.Reversible, Rollback: g.Rollback, CLI: g.CLI}
	}
	if p.Run != nil {
		run := toDecisionRunResponse(r.Context(), *p.Run)
		resp.Run = &run
	}
	for i, e := range p.Audit {
		resp.Audit[i] = decisionAuditResponse{TS: e.TS.UTC().Format(time.RFC3339), Actor: e.Actor, Action: e.Action, Details: e.Details}
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

// DryRunDecision handles POST /api/decisions/{id}/execution/dry-run — the exact
// change, resolved against the connector, with nothing changed.
func (h *Handler) DryRunDecision(w http.ResponseWriter, r *http.Request) {
	var req decisionRunRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	bp, res, err := h.svc.DryRunDecision(r.Context(), r.PathValue("id"), req.Inputs, decisionRequest)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, decisionDryRunResponse{
		Action: string(bp.Action), ConnectorID: bp.ConnectorID, Params: nonNil(bp.Params),
		Detail: res.Detail, Destructive: bp.Destructive, ConfirmText: bp.ConfirmText,
	})
}

// RequestDecisionApproval handles POST /api/decisions/{id}/execution/request —
// the first admin's yes on a fix that needs a second admin.
func (h *Handler) RequestDecisionApproval(w http.ResponseWriter, r *http.Request) {
	var req decisionRunRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	run, err := h.svc.RequestDecisionApproval(r.Context(), r.PathValue("id"), req.Inputs, req.Confirm, decisionRequest)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toDecisionRunResponse(r.Context(), run))
}

// RunDecision handles POST /api/decisions/{id}/execution/run — the click that
// runs the fix: this admin's yes, or a second admin's confirmation of a
// pending request.
func (h *Handler) RunDecision(w http.ResponseWriter, r *http.Request) {
	var req decisionRunRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	run, res, err := h.svc.RunDecision(r.Context(), r.PathValue("id"), req.Inputs, req.Confirm, decisionRequest)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, decisionRunResultResponse{
		Run: toDecisionRunResponse(r.Context(), run), Result: toExecutionResponse(res),
	})
}

// markFailedRequest is the body of the mark-failed route.
type markFailedRequest struct {
	// Verified is the admin's attestation that they checked the resource and
	// know whether the stalled run changed it.
	Verified bool   `json:"verified"`
	Note     string `json:"note,omitempty"`
}

// MarkStalledRunFailed handles POST /api/decisions/{id}/execution/mark-failed —
// an admin's release of a run stuck in running, so the fix can be retried.
// A stalled run is never taken over automatically: it may already have
// changed the cloud.
func (h *Handler) MarkStalledRunFailed(w http.ResponseWriter, r *http.Request) {
	var req markFailedRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	run, err := h.svc.MarkStalledRunFailed(r.Context(), r.PathValue("id"), req.Verified, req.Note)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toDecisionRunResponse(r.Context(), run))
}

func toDecisionRunResponse(ctx context.Context, run DecisionRun) decisionRunResponse {
	resp := decisionRunResponse{
		Status: string(run.Status), Action: string(run.Action), ConnectorID: run.ConnectorID,
		Params: nonNil(run.Params), Plan: run.Plan, RequestedBy: run.RequestedBy,
		RequestedByYou: run.RequestedByID != "" && run.RequestedByID == principalFromContext(ctx).ID,
		ExecutedBy:     run.ExecutedBy, Detail: run.Detail, Error: run.Error,
		UpdatedAt: run.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if run.Status == RunAwaitingSecondAdmin && !run.GrantExpiresAt.IsZero() {
		resp.GrantExpiresAt = run.GrantExpiresAt.UTC().Format(time.RFC3339)
		resp.ConfirmText = confirmText(run.Action, run.Params, true)
	}
	return resp
}

// nonNil keeps a required JSON object from encoding as null.
func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// decodeOptional reads a JSON body that may be empty.
func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return false
	}
	return true
}
