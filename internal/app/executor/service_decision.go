package executor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Approve-and-run: a person's yes on a decision runs its fix through the same
// Execute, Approve and audit path as the admin endpoints — there is no second
// execution path. What this file adds is the decision context: which action
// and connector carry the fix out, the typed confirmation, the two-person
// hand-off between two admins' clicks, and the decision's execution state.
//
// The two-person rule maps onto the grant like this: the first admin's
// approval mints the grant (Approve — their account must be old enough), and a
// DIFFERENT admin's confirmation executes with it (Verify refuses the same
// person, and flags a shared address). The age floor is applied to the
// confirming admin as well, so a fresh second account cannot be the second
// person.

// DecisionTargets reads what a decision proposes to change. Returns
// ErrDecisionNotFound for an unknown decision id.
type DecisionTargets interface {
	DecisionTarget(ctx context.Context, decisionID string) (DecisionTarget, error)
}

// ResourceOwners lists the connectors whose sync collects a resource.
// *connector.Service implements it.
type ResourceOwners interface {
	ConnectorsCollecting(ctx context.Context, assetID string) ([]string, error)
}

// DecisionRuns stores each decision's execution state. *PGDecisionRuns
// implements it. The Claim methods return false when another click holds the
// decision or it is running, so two clicks — or a click after a crash
// mid-call — never run one fix twice.
type DecisionRuns interface {
	Get(ctx context.Context, decisionID string) (DecisionRun, bool, error)
	Claim(ctx context.Context, run DecisionRun) (DecisionRun, bool, error)
	ClaimApproved(ctx context.Context, decisionID, executedBy, executedByID string) (DecisionRun, bool, error)
	// Finish records the result of the attempt claimed at claimedAt (the
	// claim's CreatedAt); a later attempt's state is never overwritten.
	Finish(ctx context.Context, decisionID string, claimedAt time.Time, status RunStatus, detail, errText string) error
	// FailStalled marks a run failed only while it is still running and has
	// not been updated for staleAfter (database clock); false when it
	// finished or moved.
	FailStalled(ctx context.Context, decisionID string, staleAfter time.Duration, errText string) (DecisionRun, bool, error)
}

// DecisionOutcomes records a fix the executor actually carried out — the only
// moment a decision's outcome is real.
type DecisionOutcomes interface {
	RecordExecuted(ctx context.Context, t DecisionTarget, actor string) error
}

// DecisionAuditReader reads back the executor audit rows a decision's run
// wrote. *CHAuditRepo implements it.
type DecisionAuditReader interface {
	// DecisionAudit is the panel's trail: every executor row, dry runs and
	// approvals included.
	DecisionAudit(ctx context.Context, decisionID string, since time.Time) ([]AuditEvent, error)
	// DecisionRunEvents is only the intent and result rows, oldest first, at
	// most DecisionRunEventsLimit of them — what the stalled-run check reads,
	// so a pile of dry runs cannot push the intent row out of the page.
	DecisionRunEvents(ctx context.Context, decisionID string, since time.Time) ([]AuditEvent, error)
}

// DecisionRunEventsLimit bounds DecisionRunEvents; a full page means the
// trail may continue past it and is read as unknown.
const DecisionRunEventsLimit = 100

// DecisionDeps wires approve-and-run. Every field is required.
type DecisionDeps struct {
	Targets  DecisionTargets
	Owners   ResourceOwners
	Runs     DecisionRuns
	Outcomes DecisionOutcomes
	Audit    DecisionAuditReader
}

// runStateWriteTimeout bounds the post-call state writes in finishRun, which
// run detached from the caller's context.
const runStateWriteTimeout = 5 * time.Second

// auditLookback is how far before a run's creation its trail is read from,
// so the dry runs that preceded it are included.
const auditLookback = time.Hour

// WithDecisions wires approve-and-run from the decision panel.
func (s *Service) WithDecisions(d DecisionDeps) *Service {
	s.decisions = &d
	return s
}

// PlanDecision reports what approve-and-run would do for a decision, or why it
// cannot run from Vulngraph. It changes nothing and contacts no cloud.
func (s *Service) PlanDecision(ctx context.Context, decisionID string) (DecisionPlan, error) {
	p, _, err := s.planDecision(ctx, decisionID)
	if err != nil {
		return DecisionPlan{}, err
	}
	if p.Run != nil {
		events, err := s.decisions.Audit.DecisionAudit(ctx, decisionID, p.Run.CreatedAt.Add(-auditLookback))
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("decision_id", decisionID).Msg("executor: decision audit trail unavailable")
		} else {
			p.Audit, p.AuditKnown = events, true
		}
	}
	return p, nil
}

// planDecision resolves the plan and, when one owns the resource, the
// decrypted connector.
func (s *Service) planDecision(ctx context.Context, decisionID string) (DecisionPlan, connector.Connector, error) {
	d := s.decisions
	if d == nil {
		return DecisionPlan{}, connector.Connector{}, ErrDecisionsUnwired
	}
	t, err := d.Targets.DecisionTarget(ctx, decisionID)
	if err != nil {
		return DecisionPlan{}, connector.Connector{}, fmt.Errorf("PlanDecision: %w", err)
	}
	p := DecisionPlan{Target: t, State: PlanGuidanceOnly}
	run, ok, err := d.Runs.Get(ctx, decisionID)
	if err != nil {
		return DecisionPlan{}, connector.Connector{}, fmt.Errorf("PlanDecision: %w", err)
	}
	if ok {
		p.Run = &run
	}

	switch {
	case !t.AwaitingHuman:
		p.Reason = "This decision is not waiting on a person, so there is no fix to approve and run."
		return p, connector.Connector{}, nil
	case t.ResourceID == "":
		p.Reason = "The decision's finding could not be loaded, so Vulngraph does not know which resource to change."
		return p, connector.Connector{}, nil
	}
	g, ok := GuideFor(t.ResourceType, t.ResourceID, t.Region, t.ActionClass)
	if !ok {
		p.Reason = fmt.Sprintf("No executor action carries out a %s plan on a %s, so apply it by hand or in IaC.",
			t.ActionClass, orPlaceholder(t.ResourceType, "resource of unknown type"))
		return p, connector.Connector{}, nil
	}
	p.Guidance, p.Action, p.RequiresSecondAdmin = &g, g.Action, g.Destructive

	owners, err := d.Owners.ConnectorsCollecting(ctx, t.ResourceID)
	if err != nil {
		return DecisionPlan{}, connector.Connector{}, fmt.Errorf("PlanDecision: %w", err)
	}
	switch len(owners) {
	case 0:
		p.Reason = "No connector currently collects this resource, so Vulngraph does not know which credentials can change it."
		return p, connector.Connector{}, nil
	case 1:
	default:
		p.Reason = fmt.Sprintf("%d connectors collect this resource (%s). Vulngraph will not guess which one should change it.",
			len(owners), strings.Join(owners, ", "))
		return p, connector.Connector{}, nil
	}
	c, err := s.connectors.Get(ctx, owners[0])
	if err != nil {
		return DecisionPlan{}, connector.Connector{}, fmt.Errorf("PlanDecision: %w", err)
	}
	p.ConnectorID, p.ConnectorName = c.ID, c.Name
	if want := specs[g.Action].connectorType; c.Type != want {
		p.Reason = fmt.Sprintf("Connector %q is a %s connector, and %s needs a %s one.", c.Name, c.Type, g.Action, want)
		return p, c, nil
	}
	if c.Mode != connector.ModeReadWrite {
		p.Reason = fmt.Sprintf("Connector %q is read-only. Switch it to read-write and give it an execution role to run fixes from Vulngraph.", c.Name)
		return p, c, nil
	}
	if key := missingExecutionPrincipal(c); key != "" {
		p.Reason = fmt.Sprintf("Connector %q has no execution role (%s), so Vulngraph cannot change anything through it.", c.Name, key)
		return p, c, nil
	}

	p.Params = map[string]string{}
	for k, v := range g.Params {
		if isPlaceholder(v) {
			p.Inputs = append(p.Inputs, k)
		} else {
			p.Params[k] = v
		}
	}
	slices.Sort(p.Inputs)
	// Ready when the connector's own defaults fill every gap — the same
	// resolution the execution runs, so the dry run shows what they filled.
	p.State = PlanReady
	if _, _, err := Plan(c, p.Action, p.Params); err != nil {
		p.State = PlanNeedsInput
	}
	return p, c, nil
}

// bindDecision settles a runnable plan's parameters: the finding's values,
// plus what a person typed for the Inputs keys (never for the others).
func (s *Service) bindDecision(ctx context.Context, decisionID string, inputs map[string]string) (BoundPlan, error) {
	p, c, err := s.planDecision(ctx, decisionID)
	if err != nil {
		return BoundPlan{}, err
	}
	if p.State == PlanGuidanceOnly {
		return BoundPlan{}, fmt.Errorf("%w: %s", ErrNotRunnable, p.Reason)
	}
	params := maps.Clone(p.Params)
	for k, v := range inputs {
		if !slices.Contains(p.Inputs, k) {
			return BoundPlan{}, fmt.Errorf("%w: %s is set by the decision's finding, not typed", ErrBadParams, k)
		}
		if v = strings.TrimSpace(v); v != "" {
			params[k] = v
		}
	}
	change, destructive, err := Plan(c, p.Action, params)
	if err != nil {
		return BoundPlan{}, fmt.Errorf("bindDecision: %w", err)
	}
	p.Params = params
	return BoundPlan{
		DecisionPlan: p, Change: change, Destructive: destructive,
		ConfirmText: confirmText(p.Action, params, destructive),
	}, nil
}

// DryRunDecision resolves and describes the decision's fix without changing
// anything — what the person confirms next is exactly this text.
func (s *Service) DryRunDecision(ctx context.Context, decisionID string, inputs map[string]string, build RequestBuilder) (BoundPlan, ExecutionResult, error) {
	bp, err := s.bindDecision(ctx, decisionID, inputs)
	if err != nil {
		return BoundPlan{}, ExecutionResult{}, err
	}
	res, err := s.Execute(ctx, build(bp, true))
	if err != nil {
		return BoundPlan{}, ExecutionResult{}, fmt.Errorf("DryRunDecision: %w", err)
	}
	return bp, res, nil
}

// RequestDecisionApproval is the first admin's yes on a fix that needs two
// people: it mints the grant (Approve, with its account-age floor) bound to
// the exact plan and parks the decision for a different admin to confirm.
func (s *Service) RequestDecisionApproval(ctx context.Context, decisionID string, inputs map[string]string, confirm string, build RequestBuilder) (DecisionRun, error) {
	// A key never mints a grant (Approve). Checked before anything about the
	// decision, so a key gets the same 403 whatever the fix, its confirmation
	// text or its run state.
	if viaAPIKey(ctx) {
		return DecisionRun{}, s.refuseDecision(ctx, "request_decision_approval", decisionID, "", "",
			fmt.Errorf("%w: an API key cannot approve; a signed-in admin must request this fix", ErrApprovalInvalid))
	}
	bp, err := s.bindDecision(ctx, decisionID, inputs)
	if err != nil {
		return DecisionRun{}, err
	}
	if !bp.Destructive {
		return DecisionRun{}, fmt.Errorf("%w: run %s directly", ErrApprovalNotRequired, bp.Action)
	}
	if err := checkConfirmation(bp.ConfirmText, confirm); err != nil {
		return DecisionRun{}, err
	}
	// Refused before minting, so a grant nobody can use is never issued; the
	// Claim below still settles a race.
	if r := bp.Run; r != nil && (r.Status == RunSucceeded || r.Status == RunRunning || r.Status == RunOutcomeUnknown ||
		(r.Status == RunAwaitingSecondAdmin && s.now().Before(r.GrantExpiresAt))) {
		return DecisionRun{}, ErrRunConflict
	}
	approval, err := s.Approve(ctx, build(bp, false))
	if err != nil {
		return DecisionRun{}, fmt.Errorf("RequestDecisionApproval: %w", err)
	}
	me := principalFromContext(ctx)
	run, ok, err := s.decisions.Runs.Claim(ctx, DecisionRun{
		DecisionID: decisionID, FindingID: bp.Target.FindingID, ConnectorID: bp.ConnectorID,
		Action: bp.Action, Params: bp.Params, Plan: approval.Plan, Status: RunAwaitingSecondAdmin,
		RequestedBy: me.Name, RequestedByID: me.ID,
		GrantToken: approval.Token, GrantExpiresAt: approval.ExpiresAt,
	})
	if err != nil {
		return DecisionRun{}, fmt.Errorf("RequestDecisionApproval: %w", err)
	}
	if !ok {
		return DecisionRun{}, ErrRunConflict
	}
	return run, nil
}

// RunDecision is the click that runs a decision's fix. A fix that needs no
// second admin runs on this admin's yes. One that does runs only as a
// DIFFERENT admin's confirmation of a live request — its params and grant
// come from the request, never from this call.
func (s *Service) RunDecision(ctx context.Context, decisionID string, inputs map[string]string, confirm string, build RequestBuilder) (DecisionRun, ExecutionResult, error) {
	me, err := requirePerson(ctx)
	if err != nil {
		return DecisionRun{}, ExecutionResult{}, fmt.Errorf("%w: decision %s", err, decisionID)
	}
	p, _, err := s.planDecision(ctx, decisionID)
	if err != nil {
		return DecisionRun{}, ExecutionResult{}, err
	}
	if r := p.Run; r != nil && r.Status == RunAwaitingSecondAdmin && s.now().Before(r.GrantExpiresAt) {
		return s.runApproved(ctx, p, me, confirm, build)
	}

	bp, err := s.bindDecision(ctx, decisionID, inputs)
	if err != nil {
		return DecisionRun{}, ExecutionResult{}, err
	}
	if bp.Destructive {
		return DecisionRun{}, ExecutionResult{}, s.refuseDecision(ctx, "run_decision", decisionID, bp.ConnectorID, bp.Action,
			fmt.Errorf("%w: request a second admin's confirmation first", ErrApprovalRequired))
	}
	// Execute would refuse an API key's ungranted run anyway; refusing here
	// keeps the decision from being claimed and marked failed on the way.
	if viaAPIKey(ctx) {
		return DecisionRun{}, ExecutionResult{}, s.refuseDecision(ctx, "run_decision", decisionID, bp.ConnectorID, bp.Action,
			fmt.Errorf("%w: an API key needs a different admin's grant, so a signed-in admin must run this fix", ErrApprovalRequired))
	}
	if err := checkConfirmation(bp.ConfirmText, confirm); err != nil {
		return DecisionRun{}, ExecutionResult{}, err
	}
	run, ok, err := s.decisions.Runs.Claim(ctx, DecisionRun{
		DecisionID: decisionID, FindingID: bp.Target.FindingID, ConnectorID: bp.ConnectorID,
		Action: bp.Action, Params: bp.Params, Plan: bp.Change, Status: RunRunning,
		RequestedBy: me.Name, RequestedByID: me.ID, ExecutedBy: me.Name, ExecutedByID: me.ID,
	})
	if err != nil {
		return DecisionRun{}, ExecutionResult{}, fmt.Errorf("RunDecision: %w", err)
	}
	if !ok {
		return DecisionRun{}, ExecutionResult{}, ErrRunConflict
	}
	res, execErr := s.Execute(ctx, build(bp, false))
	return s.finishRun(ctx, bp.Target, run, me, res, execErr)
}

// runApproved executes a live two-person request as the confirming admin.
//
// The request froze its params and grant when the first admin approved it, but
// the decision itself is re-planned on this click: if it no longer waits on a
// person (resolved, superseded, re-decided) or its fix can no longer run from
// Vulngraph (connector changed, resource gone), the request is not confirmable.
func (s *Service) runApproved(ctx context.Context, p DecisionPlan, me Principal, confirm string, build RequestBuilder) (DecisionRun, ExecutionResult, error) {
	r := *p.Run
	if !p.Target.AwaitingHuman || p.State == PlanGuidanceOnly {
		return DecisionRun{}, ExecutionResult{}, fmt.Errorf("%w: %s", ErrNotRunnable, p.Reason)
	}
	if p.ConnectorID != r.ConnectorID {
		return DecisionRun{}, ExecutionResult{}, fmt.Errorf(
			"%w: the request was approved for connector %s, which no longer owns this resource", ErrNotRunnable, r.ConnectorID)
	}
	if r.RequestedByID == me.ID {
		return DecisionRun{}, ExecutionResult{}, s.refuseDecision(ctx, "run_decision", r.DecisionID, r.ConnectorID, r.Action,
			fmt.Errorf("%w: you approved this change, so a different admin must confirm and run it", ErrApprovalInvalid))
	}
	if err := s.checkAccountAge(me, "executing"); err != nil {
		return DecisionRun{}, ExecutionResult{}, s.refuseDecision(ctx, "run_decision", r.DecisionID, r.ConnectorID, r.Action, err)
	}
	p.ConnectorID, p.Action, p.Params = r.ConnectorID, r.Action, r.Params
	bp := BoundPlan{
		DecisionPlan: p, Change: r.Plan, Destructive: true,
		ConfirmText: confirmText(r.Action, r.Params, true), GrantToken: r.GrantToken,
	}
	if err := checkConfirmation(bp.ConfirmText, confirm); err != nil {
		return DecisionRun{}, ExecutionResult{}, err
	}
	run, ok, err := s.decisions.Runs.ClaimApproved(ctx, r.DecisionID, me.Name, me.ID)
	if err != nil {
		return DecisionRun{}, ExecutionResult{}, fmt.Errorf("RunDecision: %w", err)
	}
	if !ok {
		return DecisionRun{}, ExecutionResult{}, ErrRunConflict
	}
	res, execErr := s.Execute(ctx, build(bp, false))
	return s.finishRun(ctx, p.Target, run, me, res, execErr)
}

// finishRun records the executor's actual result on the decision, and — only
// when the fix really ran — hands it to the outcome ledger. Neither write
// fails the response: the cloud change has already happened (or not), the
// audit rows already say so, and an error here would invite a retry of a
// mutation.
func (s *Service) finishRun(ctx context.Context, t DecisionTarget, run DecisionRun, me Principal, res ExecutionResult, execErr error) (DecisionRun, ExecutionResult, error) {
	run.Status, run.Detail, run.Error, run.GrantToken = RunSucceeded, res.Detail, "", ""
	switch {
	case errors.Is(execErr, ErrOutcomeUnknown):
		run.Status, run.Detail, run.Error = RunOutcomeUnknown, "",
			"result unknown — verify in the cloud console, then mark the run failed to retry: "+execErr.Error()
	case execErr != nil:
		run.Status, run.Detail, run.Error = RunFailed, "", execErr.Error()
	}
	// The run's state is written whatever happened to the caller's context:
	// the request deadline or a disconnect must not leave a finished (or
	// outcome-unknown) run marked running.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runStateWriteTimeout)
	defer cancel()
	if err := s.decisions.Runs.Finish(wctx, run.DecisionID, run.CreatedAt, run.Status, run.Detail, run.Error); err != nil {
		log.FromContext(ctx).Error().Err(err).Str("decision_id", run.DecisionID).Str("status", string(run.Status)).
			Msg("executor: decision run state not recorded; the audit trail has the result")
	}
	if execErr != nil {
		return run, ExecutionResult{}, fmt.Errorf("RunDecision: %w", execErr)
	}
	if err := s.decisions.Outcomes.RecordExecuted(wctx, t, me.Name); err != nil {
		log.FromContext(ctx).Error().Err(err).Str("decision_id", run.DecisionID).
			Msg("executor: executed fix not recorded as an outcome")
	}
	return run, res, nil
}

// refuseDecision audits a decision request or run refused for who asked, and
// returns refused.
func (s *Service) refuseDecision(ctx context.Context, stage, decisionID, connectorID string, action Action, refused error) error {
	details := map[string]any{"decision_id": decisionID}
	if action != "" {
		details["action"] = string(action)
	}
	s.recordRefusal(ctx, stage, connectorID, details, refused)
	return refused
}

// checkConfirmation requires the typed confirmation when one is due — checked
// here, not only in the UI, so no client can skip it.
func checkConfirmation(want, got string) error {
	if want != "" && strings.TrimSpace(got) != want {
		return fmt.Errorf("%w: type %q to confirm", ErrConfirmationMismatch, want)
	}
	return nil
}
