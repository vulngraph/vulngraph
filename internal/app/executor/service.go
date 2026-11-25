package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ConnectorGetter is the narrow interface the service needs from the connector
// domain — only Get is required; the full *connector.Service satisfies it.
type ConnectorGetter interface {
	Get(ctx context.Context, id string) (connector.Connector, error)
}

// Auditor appends to the insert-only audit trail. *CHAuditRepo implements it.
type Auditor interface {
	RecordAudit(ctx context.Context, e AuditEvent) error
}

// ExecutionTimeout bounds one cloud call (credentials plus the mutation),
// which runs detached from the caller's context. It is below the HTTP
// request deadline (45s), so the person who clicked still gets the answer,
// and far below RunStallAfter, so a run still `running` past that point is
// one whose process died, not one waiting on a slow API. A call that hits it
// is outcome_unknown, never retried without a person's check.
const ExecutionTimeout = 30 * time.Second

// DefaultMinApproverAccountAge is how old an account must be before it may
// approve a destructive action, unless configured otherwise.
const DefaultMinApproverAccountAge = 24 * time.Hour

// Service executes cloud remediation actions using the credentials of the
// connector identified by the request's ConnectorID.
type Service struct {
	connectors ConnectorGetter
	audit      Auditor // nil = auditing disabled (tests, CLI paths with no ClickHouse)
	// approver mints and verifies two-person grants. nil means destructive
	// actions are REFUSED outright rather than allowed — an unwired approval
	// seam must not read as "no approval needed".
	approver *Approver
	// minApproverAge is how old the approving account must be; an account of
	// unknown age (zero User.CreatedAt) never qualifies, and the clock restarts
	// when the account is promoted to admin (User.AdminSince).
	minApproverAge time.Duration
	now            func() time.Time
	// decisions wires approve-and-run from the decision panel; nil leaves
	// those methods refusing with ErrDecisionsUnwired.
	decisions *DecisionDeps
	// call carries out a resolved action (run); tests replace it to observe
	// the context the cloud call gets.
	call func(ctx context.Context, c connector.Connector, action Action, p map[string]string) (ExecutionResult, error)
	// execTimeout is ExecutionTimeout; tests shorten it.
	execTimeout time.Duration
}

// NewService constructs an executor Service.
func NewService(connectors ConnectorGetter) *Service {
	s := &Service{connectors: connectors, minApproverAge: DefaultMinApproverAccountAge, now: time.Now, execTimeout: ExecutionTimeout}
	s.call = s.run
	return s
}

// WithAudit attaches the audit sink. It is an option rather than a constructor
// argument so the many non-HTTP construction sites keep compiling, but every
// wiring that can reach a cloud mutation MUST set it — TestExecutorIsWiredWithAudit
// in cmd/graph pins that.
func (s *Service) WithAudit(a Auditor) *Service {
	s.audit = a
	return s
}

// WithApprovals attaches the two-person approval seam. Without it every
// execution that needs a grant is refused (ErrApprovalRequired): the
// destructive subset, and every API-key or MCP execution. That is the
// fail-closed direction, so a wiring omission costs availability rather than
// silently removing the control.
func (s *Service) WithApprovals(a *Approver) *Service {
	s.approver = a
	return s
}

// WithMinApproverAge sets the minimum age an approving account must have
// (default DefaultMinApproverAccountAge). A second admin account created
// minutes ago by the executor is the cheapest way for one person to satisfy
// the two-person rule alone; the age floor makes that take a day instead of a
// minute.
func (s *Service) WithMinApproverAge(minAge time.Duration) *Service {
	s.minApproverAge = minAge
	return s
}

// Execute carries out the remediation described by req, in this order: load the
// connector, refuse read_only, resolve+validate the action against the registry,
// and — unless req.DryRun — verify any required approval, write an intent audit
// row, and call the cloud API as the connector's EXECUTION principal.
//
// Returns ErrNoPrincipal, ErrBypassAuth, ErrCapabilityMissing, ErrBadParams, ErrNoExecutionRole,
// ErrApprovalRequired/ErrApprovalInvalid, ErrAuditUnavailable, or
// ErrExecutionFailed (wrapping the underlying error) on failure.
//
// Every attempt — successful or not — is written to the audit trail. The
// actor is the authenticated principal on the context, which both transports
// (HTTP RequireAuth and the MCP seam) attach, so auditing does not depend on
// each caller remembering to thread an actor through.
func (s *Service) Execute(ctx context.Context, req ExecutionRequest) (ExecutionResult, error) {
	extra := map[string]any{}
	result, err := s.execute(ctx, req, extra)
	s.recordAudit(ctx, req, result, err, extra)
	return result, err
}

func (s *Service) execute(ctx context.Context, req ExecutionRequest, extra map[string]any) (ExecutionResult, error) {
	c, err := s.connectors.Get(ctx, req.ConnectorID)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("Execute: load connector: %w", err)
	}

	// Reject read-only connectors before touching any cloud API.
	if c.Mode != connector.ModeReadWrite {
		return ExecutionResult{}, fmt.Errorf("%w: connector %s is %s", ErrCapabilityMissing, c.ID, c.Mode)
	}

	spec, ok := specs[req.Action]
	if !ok {
		return ExecutionResult{}, fmt.Errorf("%w: unknown action %q", ErrCapabilityMissing, req.Action)
	}
	if c.Type != spec.connectorType {
		return ExecutionResult{}, fmt.Errorf("%w: %s requires a %s connector, got %s",
			ErrCapabilityMissing, req.Action, spec.connectorType, c.Type)
	}
	params, err := spec.resolve(c, req.Params)
	if err != nil {
		return ExecutionResult{}, err
	}
	planned := spec.describe(c, params)
	destructive := spec.destructive(params)
	// An API key may be held by an agent, so a change asked for on one needs a
	// DIFFERENT admin's grant whatever the action — the rule the MCP seam sets
	// with RequireGrant, applied here so no HTTP route can skip it.
	needsGrant := destructive || req.RequireGrant || viaAPIKey(ctx)

	if req.DryRun {
		return ExecutionResult{
			ConnectorID: c.ID,
			Action:      req.Action,
			DryRun:      true,
			Destructive: destructive,
			Detail:      dryRunDetail(planned, needsGrant),
		}, nil
	}

	// A change runs only on a person's explicit request (ADR 087): an
	// authenticated principal on the context is the transport's proof that a
	// human asked — HTTP RequireAuth and the MCP seam both attach one. A
	// background caller (a job, a sweep, the decision pipeline) carries none,
	// so it is refused here rather than trusted to never call.
	if _, err := requirePerson(ctx); err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: %s", err, planned)
	}

	if needsGrant {
		grant, err := s.checkApproval(ctx, c.ID, req, planned)
		if err != nil {
			return ExecutionResult{}, err
		}
		extra["approved_by"] = grant.Approver
		extra["approver_user_id"] = grant.ApproverID
		if grant.SameIP {
			extra["approver_same_ip"] = true
		}
	}

	if err := s.recordIntent(ctx, req, planned, extra); err != nil {
		return ExecutionResult{}, err
	}

	// Detached from the caller: a client that disconnects, or the HTTP
	// request deadline, must not cut a mutation off mid-flight. The call is
	// bounded by ExecutionTimeout alone.
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.execTimeout)
	defer cancel()
	result, err := s.call(runCtx, c, req.Action, params)
	if err != nil {
		// The intent row is written and the call was cut off: the request may
		// have reached the provider and the change may have landed. That is
		// not a failure a plain retry may repeat — it must be verified.
		if runCtx.Err() != nil {
			return ExecutionResult{}, fmt.Errorf("%w: %s: %w", ErrOutcomeUnknown, planned, err)
		}
		return ExecutionResult{}, err
	}
	result.Destructive = destructive
	return result, nil
}

// dryRunDetail states, unambiguously and first, that nothing changed. The plan
// text is identical to what an approval grant binds to.
func dryRunDetail(planned string, needsGrant bool) string {
	detail := "DRY RUN — nothing was changed. Would " + planned
	if needsGrant {
		detail += ". This action requires an approval grant from a second admin."
	}
	return detail
}

// run dispatches a resolved action to its provider implementation. Params are
// already validated and defaulted by the registry, so the implementations read
// them directly.
func (s *Service) run(ctx context.Context, c connector.Connector, action Action, p map[string]string) (ExecutionResult, error) {
	switch action {
	case ActionSGRuleRemove:
		return s.revokeSGRule(ctx, c, p)
	case ActionIAMKeyDisable:
		return s.disableIAMKey(ctx, c, p)
	case ActionEC2Stop:
		return s.stopEC2Instance(ctx, c, p)
	case ActionEC2Start:
		return s.startEC2Instance(ctx, c, p)
	case ActionS3BlockPublic:
		return s.s3BlockPublicAccess(ctx, c, p)
	case ActionGCPSAKeyDisable, ActionGCPFirewallRemove:
		return s.executeGCP(ctx, c, action, p)
	case ActionAzureNSGRuleRemove:
		return s.executeAzure(ctx, c, action, p)
	default:
		// Unreachable: execute() looked the action up in the same registry.
		return ExecutionResult{}, fmt.Errorf("%w: unhandled action %q", ErrCapabilityMissing, action)
	}
}

// checkApproval enforces two-person control on the destructive subset, and on
// every action when the request requires a grant.
func (s *Service) checkApproval(ctx context.Context, connectorID string, req ExecutionRequest, planned string) (Grant, error) {
	if s.approver == nil {
		return Grant{}, fmt.Errorf("%w: no approval seam is configured, so %s cannot run", ErrApprovalRequired, req.Action)
	}
	if req.ApprovalToken == "" {
		return Grant{}, fmt.Errorf("%w: %s needs an approval grant for: %s", ErrApprovalRequired, req.Action, planned)
	}
	executor := principalFromContext(ctx)
	// The floor binds the executor as well as the approver: otherwise one admin
	// with an old account approves and a second admin account they created a
	// minute ago executes, and one person has satisfied the two-person rule.
	if err := s.checkAccountAge(executor, "executing"); err != nil {
		return Grant{}, err
	}
	return s.approver.Redeem(ctx, req.ApprovalToken, connectorID, req.Action, planned, executor)
}

// Approve mints an approval grant for a destructive action (or any action,
// when req.RequireGrant — the grant an agent's execution needs), from the same
// resolution the execution will perform — so the plan the approver reads is
// the plan the grant is bound to, byte for byte. The approving admin is taken
// from the context, never from the request, and their account must be at
// least minApproverAge old. A refusal of who asked (an API key, a too-young
// account) is audited.
func (s *Service) Approve(ctx context.Context, req ExecutionRequest) (Approval, error) {
	approval, err := s.approve(ctx, req)
	if errors.Is(err, ErrApprovalInvalid) {
		s.recordRefusal(ctx, "approve", req.ConnectorID,
			withDecision(req, map[string]any{"action": string(req.Action), "params": req.Params}), err)
	}
	return approval, err
}

func (s *Service) approve(ctx context.Context, req ExecutionRequest) (Approval, error) {
	if s.approver == nil {
		return Approval{}, fmt.Errorf("%w: no approval seam is configured", ErrApprovalRequired)
	}
	// The grant is the person's half of the two-person rule. A key may be an
	// agent's, and an agent that could mint grants could feed them to another
	// admin's key and run anything with no person involved. Checked first, so
	// a key gets the same 403 whatever the action.
	if viaAPIKey(ctx) {
		return Approval{}, fmt.Errorf("%w: an API key cannot approve; a signed-in admin must mint the grant", ErrApprovalInvalid)
	}
	c, err := s.connectors.Get(ctx, req.ConnectorID)
	if err != nil {
		return Approval{}, fmt.Errorf("Approve: load connector: %w", err)
	}
	planned, destructive, err := Plan(c, req.Action, req.Params)
	if err != nil {
		return Approval{}, fmt.Errorf("Approve: %w", err)
	}
	if !destructive && !req.RequireGrant {
		return Approval{}, fmt.Errorf("%w: %s", ErrApprovalNotRequired, req.Action)
	}
	approver := principalFromContext(ctx)
	if err := s.checkAccountAge(approver, "approving"); err != nil {
		return Approval{}, err
	}
	approval, err := s.approver.Mint(c.ID, req.Action, planned, approver)
	if err != nil {
		return Approval{}, fmt.Errorf("Approve: %w", err)
	}
	s.recordApproval(ctx, req, approval)
	return approval, nil
}

// checkAccountAge refuses either half of a two-person grant (role is
// "approving" or "executing") from an account that has not been an admin for
// minApproverAge. The clock starts at the later of the account's created_at and
// the time its role last became admin, so promoting an old account does not
// skip the floor. An admin from before admin_since was recorded has no such
// time and counts from created_at. The times come from the authenticated
// principal (RequireAuth attaches the user row's for sessions and the owner's
// for API keys); an unknown account age fails closed — a zero time would
// otherwise read as an account two thousand years old.
func (s *Service) checkAccountAge(p Principal, role string) error {
	if p.ID == "" {
		return fmt.Errorf("%w: a two-person action must name the %s admin", ErrApprovalInvalid, role)
	}
	start := p.adminTenureStart()
	if start.IsZero() {
		return fmt.Errorf("%w: the %s account's age is unknown, so it cannot take part in a two-person action", ErrApprovalInvalid, role)
	}
	if age := s.now().Sub(start); age < s.minApproverAge {
		return fmt.Errorf("%w: the %s account has been an admin for %s; two-person actions need accounts that have been admin for at least %s",
			ErrApprovalInvalid, role, age.Truncate(time.Minute), s.minApproverAge)
	}
	return nil
}

// recordApproval puts the grant in the same insert-only trail as the execution
// it authorises, so "who approved what" and "who ran what" are one query.
func (s *Service) recordApproval(ctx context.Context, req ExecutionRequest, a Approval) {
	if s.audit == nil {
		return
	}
	event := s.auditEvent(ctx, AuditActionApprove, req.ConnectorID, withDecision(req, map[string]any{
		"action":     string(req.Action),
		"params":     req.Params,
		"plan":       a.Plan,
		"expires_at": a.ExpiresAt.Format(time.RFC3339),
	}))
	event.Actor = a.Approver
	if err := s.audit.RecordAudit(ctx, event); err != nil {
		log.FromContext(ctx).Error().Err(err).
			Str("actor", event.Actor).Str("connector_id", event.TargetID).
			Msg("executor: AUDIT WRITE FAILED — an approval was granted with no audit row")
	}
}

// recordRefusal writes the row for an attempt refused before Execute, which
// audits its own refusals. Like the result row it never fails the call: the
// caller is already being refused.
func (s *Service) recordRefusal(ctx context.Context, stage, connectorID string, details map[string]any, refused error) {
	if s.audit == nil {
		return
	}
	details["stage"] = stage
	details["error"] = refused.Error()
	event := s.auditEvent(ctx, AuditActionRefused, connectorID, details)
	if err := s.audit.RecordAudit(ctx, event); err != nil {
		log.FromContext(ctx).Error().Err(err).
			Str("actor", event.Actor).Str("stage", stage).Str("connector_id", connectorID).
			Msg("executor: AUDIT WRITE FAILED — a refused attempt has no audit row")
	}
}

// recordIntent writes the pre-execution row. Unlike the result row it is a
// precondition: if it cannot be written the cloud call does not happen, so a
// mutation can never exist with no trace at all.
func (s *Service) recordIntent(ctx context.Context, req ExecutionRequest, planned string, extra map[string]any) error {
	if s.audit == nil {
		return nil
	}
	details := withDecision(req, map[string]any{"action": string(req.Action), "params": req.Params, "plan": planned})
	if req.Reason != "" {
		details["reason"] = req.Reason
	}
	for k, v := range extra {
		details[k] = v
	}
	if err := s.audit.RecordAudit(ctx, s.auditEvent(ctx, AuditActionExecuteIntent, req.ConnectorID, details)); err != nil {
		log.FromContext(ctx).Error().Err(err).Str("connector_id", req.ConnectorID).
			Msg("executor: intent audit write failed — execution refused")
		return fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return nil
}

// recordAudit writes the result row for every attempt. A failed write here
// never fails the execution — the cloud mutation has already happened, and
// the intent row already records that it was about to — but it is logged at
// Error so a silently dark audit trail is visible in the logs.
func (s *Service) recordAudit(ctx context.Context, req ExecutionRequest, result ExecutionResult, execErr error, extra map[string]any) {
	if s.audit == nil {
		return
	}
	action := AuditActionExecute
	if result.DryRun {
		action = AuditActionDryRun
	}
	details := withDecision(req, map[string]any{
		"action": string(req.Action),
		"params": req.Params,
		"detail": result.Detail,
	})
	if req.Reason != "" {
		details["reason"] = req.Reason
	}
	for k, v := range extra {
		details[k] = v
	}
	switch {
	case errors.Is(execErr, ErrOutcomeUnknown):
		action = AuditActionExecuteOutcomeUnknown
		details["error"] = execErr.Error()
		delete(details, "detail")
	case execErr != nil:
		action = AuditActionExecuteFailed
		details["error"] = execErr.Error()
		delete(details, "detail")
	}
	event := s.auditEvent(ctx, action, req.ConnectorID, details)
	if err := s.audit.RecordAudit(ctx, event); err != nil {
		log.FromContext(ctx).Error().Err(err).
			Str("actor", event.Actor).Str("audit_action", event.Action).Str("connector_id", event.TargetID).
			Msg("executor: AUDIT WRITE FAILED — a cloud mutation was attempted with no audit row")
	}
}

// withDecision tags an audit row with the decision a request carries out, so
// the decision panel can read its own trail back (CHAuditRepo.DecisionAudit).
func withDecision(req ExecutionRequest, details map[string]any) map[string]any {
	if req.DecisionID != "" {
		details["decision_id"] = req.DecisionID
	}
	return details
}

// auditEvent builds a connector-targeted row attributed to the context's
// principal: the display name as Actor and the stable user id in the details.
func (s *Service) auditEvent(ctx context.Context, action, connectorID string, details map[string]any) AuditEvent {
	p := principalFromContext(ctx)
	details["actor_user_id"] = p.ID
	encoded, err := json.Marshal(details)
	if err != nil {
		encoded = []byte(`{"error":"audit details could not be encoded"}`)
	}
	return AuditEvent{
		TS:         s.now().UTC(),
		Actor:      p.Name,
		Action:     action,
		TargetType: AuditTargetConnector,
		TargetID:   connectorID,
		Details:    string(encoded),
	}
}

// actorFromContext resolves the authenticated principal both transports attach
// to the request context (HTTP RequireAuth, and the MCP seam's own auth check).
func actorFromContext(ctx context.Context) string {
	if u, ok := auth.UserFromContext(ctx); ok && u.Email != "" {
		return u.Email
	}
	return AuditActorUnknown
}

// viaAPIKey reports whether the request authenticated with an API key rather
// than a person's session (RequireAuth's Bearer gph_* path).
func viaAPIKey(ctx context.Context) bool {
	_, ok := auth.APIKeyFromContext(ctx)
	return ok
}

// requirePerson is the "a person asked" check every state change passes
// (ADR 087): the principal must be an identified user, not absent (a
// background caller) and not the synthetic admin BYPASS_AUTH serves every
// request as.
func requirePerson(ctx context.Context) (Principal, error) {
	if auth.BypassFromContext(ctx) {
		return Principal{}, ErrBypassAuth
	}
	p := principalFromContext(ctx)
	if p.ID == "" {
		return Principal{}, ErrNoPrincipal
	}
	return p, nil
}

// principalFromContext is the identity the two-person check compares. Both auth
// paths attach the owning user's id: a session carries the user row's id and an
// API key carries the id of the user who created it (see auth.RequireAuth), so
// the same human resolves to the same ID whichever credential they present.
// The client address is the one RequireAuth resolved through the trusted
// CLIENT_IP_HEADER, so the same-address flag sees clients, not the proxy.
func principalFromContext(ctx context.Context) Principal {
	p := Principal{Name: actorFromContext(ctx), IP: auth.ClientIPFromContext(ctx)}
	if u, ok := auth.UserFromContext(ctx); ok {
		p.ID = u.ID
		p.CreatedAt = u.CreatedAt
		p.AdminSince = u.AdminSince
	}
	return p
}

// revokeSGRule calls ec2:RevokeSecurityGroupIngress to remove a single ingress
// rule identified by protocol/port/CIDR from the given security group.
func (s *Service) revokeSGRule(ctx context.Context, c connector.Connector, params map[string]string) (ExecutionResult, error) {
	groupID := params[ParamGroupID]
	region := params[ParamRegion]
	protocol := params[ParamProtocol]
	cidr := params[ParamCIDR]

	fromPort, err := parsePort(params[ParamFromPort])
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: from_port: %v", ErrBadParams, err)
	}
	toPort, err := parsePort(params[ParamToPort])
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: to_port: %v", ErrBadParams, err)
	}

	awsCfg, err := executionAWSConfig(ctx, c, region)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("Execute sg_rule_remove: %w", err)
	}

	client := ec2.NewFromConfig(awsCfg)

	perm := ec2types.IpPermission{
		IpProtocol: awssdk.String(protocol),
	}
	// Port fields only make sense for TCP/UDP; -1 (all traffic) has no ports.
	if protocol != "-1" {
		perm.FromPort = awssdk.Int32(fromPort)
		perm.ToPort = awssdk.Int32(toPort)
	}
	// Detect IPv6 vs IPv4 CIDR.
	if isIPv6(cidr) {
		perm.Ipv6Ranges = []ec2types.Ipv6Range{{CidrIpv6: awssdk.String(cidr)}}
	} else {
		perm.IpRanges = []ec2types.IpRange{{CidrIp: awssdk.String(cidr)}}
	}

	_, apiErr := client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId:       awssdk.String(groupID),
		IpPermissions: []ec2types.IpPermission{perm},
	})
	if apiErr != nil {
		log.FromContext(ctx).Error().Err(apiErr).
			Str("group_id", groupID).Str("cidr", cidr).
			Msg("executor: RevokeSecurityGroupIngress failed")
		return ExecutionResult{}, fmt.Errorf("%w: RevokeSecurityGroupIngress %s: %v", ErrExecutionFailed, groupID, apiErr)
	}

	detail := fmt.Sprintf("revoked %s ingress rule proto=%s from_port=%d to_port=%d cidr=%s from %s",
		groupID, protocol, fromPort, toPort, cidr, region)
	log.FromContext(ctx).Info().Str("group_id", groupID).Str("cidr", cidr).Str("region", region).
		Msg("executor: sg rule removed")
	return ExecutionResult{ConnectorID: c.ID, Action: ActionSGRuleRemove, Detail: detail}, nil
}

// disableIAMKey calls iam:UpdateAccessKey with Status=Inactive, and optionally
// iam:DeleteAccessKey when delete_key=true. The key is identified by username +
// key_id.
func (s *Service) disableIAMKey(ctx context.Context, c connector.Connector, params map[string]string) (ExecutionResult, error) {
	keyID := params[ParamKeyID]
	username := params[ParamUsername]
	deleteKey := params[ParamDeleteKey] == "true"

	// IAM is a global service; the region only picks the STS/credential endpoint.
	awsCfg, err := executionAWSConfig(ctx, c, params[ParamRegion])
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("Execute iam_key_disable: %w", err)
	}

	iamClient := iam.NewFromConfig(awsCfg)

	_, apiErr := iamClient.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
		AccessKeyId: awssdk.String(keyID),
		UserName:    awssdk.String(username),
		Status:      iamtypes.StatusTypeInactive,
	})
	if apiErr != nil {
		log.FromContext(ctx).Error().Err(apiErr).
			Str("key_id", keyID).Str("username", username).
			Msg("executor: UpdateAccessKey failed")
		return ExecutionResult{}, fmt.Errorf("%w: UpdateAccessKey %s/%s: %v", ErrExecutionFailed, username, keyID, apiErr)
	}

	detail := fmt.Sprintf("disabled IAM access key %s for user %s", keyID, username)

	if deleteKey {
		_, delErr := iamClient.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			AccessKeyId: awssdk.String(keyID),
			UserName:    awssdk.String(username),
		})
		if delErr != nil {
			// Disable succeeded — log the delete failure but don't fail the request.
			// The key is already inactive; deletion can be retried manually.
			log.FromContext(ctx).Warn().Err(delErr).
				Str("key_id", keyID).Str("username", username).
				Msg("executor: DeleteAccessKey failed after successful disable")
		} else {
			detail = fmt.Sprintf("disabled and deleted IAM access key %s for user %s", keyID, username)
		}
	}

	log.FromContext(ctx).Info().Str("key_id", keyID).Str("username", username).Bool("deleted", deleteKey).
		Msg("executor: IAM key disabled")
	return ExecutionResult{ConnectorID: c.ID, Action: ActionIAMKeyDisable, Detail: detail}, nil
}

// stopEC2Instance calls ec2:StopInstances to stop the instance identified by
// instance_id in the given region.
func (s *Service) stopEC2Instance(ctx context.Context, c connector.Connector, params map[string]string) (ExecutionResult, error) {
	instanceID := params[ParamInstanceID]
	region := params[ParamRegion]

	awsCfg, err := executionAWSConfig(ctx, c, region)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("Execute ec2_stop: %w", err)
	}

	_, apiErr := ec2.NewFromConfig(awsCfg).StopInstances(ctx, &ec2.StopInstancesInput{
		InstanceIds: []string{instanceID},
		Force:       awssdk.Bool(false),
	})
	if apiErr != nil {
		log.FromContext(ctx).Error().Err(apiErr).
			Str("instance_id", instanceID).Str("region", region).
			Msg("executor: StopInstances failed")
		return ExecutionResult{}, fmt.Errorf("%w: StopInstances %s: %v", ErrExecutionFailed, instanceID, apiErr)
	}

	detail := fmt.Sprintf("stopped EC2 instance %s in %s", instanceID, region)
	log.FromContext(ctx).Info().Str("instance_id", instanceID).Str("region", region).
		Msg("executor: EC2 instance stopped")
	return ExecutionResult{ConnectorID: c.ID, Action: ActionEC2Stop, Detail: detail}, nil
}

// startEC2Instance calls ec2:StartInstances to start the instance identified by
// instance_id in the given region.
func (s *Service) startEC2Instance(ctx context.Context, c connector.Connector, params map[string]string) (ExecutionResult, error) {
	instanceID := params[ParamInstanceID]
	region := params[ParamRegion]

	awsCfg, err := executionAWSConfig(ctx, c, region)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("Execute ec2_start: %w", err)
	}

	_, apiErr := ec2.NewFromConfig(awsCfg).StartInstances(ctx, &ec2.StartInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if apiErr != nil {
		log.FromContext(ctx).Error().Err(apiErr).
			Str("instance_id", instanceID).Str("region", region).
			Msg("executor: StartInstances failed")
		return ExecutionResult{}, fmt.Errorf("%w: StartInstances %s: %v", ErrExecutionFailed, instanceID, apiErr)
	}

	detail := fmt.Sprintf("started EC2 instance %s in %s", instanceID, region)
	log.FromContext(ctx).Info().Str("instance_id", instanceID).Str("region", region).
		Msg("executor: EC2 instance started")
	return ExecutionResult{ConnectorID: c.ID, Action: ActionEC2Start, Detail: detail}, nil
}

// s3BlockPublicAccess calls s3:PutPublicAccessBlock to block all forms of
// public access on the bucket identified by bucket_name. It first reads the
// bucket's own block, so the result row (or, on a failed or cut-off call, the
// error) records the exact settings an undo puts back; if that read fails
// nothing is changed, because the undo could not be recorded.
func (s *Service) s3BlockPublicAccess(ctx context.Context, c connector.Connector, params map[string]string) (ExecutionResult, error) {
	bucketName := params[ParamBucketName]
	region := params[ParamRegion]

	awsCfg, err := executionAWSConfig(ctx, c, region)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("Execute s3_block_public: %w", err)
	}
	client := s3.NewFromConfig(awsCfg)

	before, err := publicAccessBlockBefore(client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: awssdk.String(bucketName),
	}))
	if err != nil {
		log.FromContext(ctx).Error().Err(err).
			Str("bucket_name", bucketName).Str("region", region).
			Msg("executor: GetPublicAccessBlock failed, bucket left unchanged")
		return ExecutionResult{}, fmt.Errorf("%w: GetPublicAccessBlock %s (nothing changed): %v", ErrExecutionFailed, bucketName, err)
	}

	_, apiErr := client.PutPublicAccessBlock(ctx, &s3.PutPublicAccessBlockInput{
		Bucket: awssdk.String(bucketName),
		PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
			BlockPublicAcls:       awssdk.Bool(true),
			IgnorePublicAcls:      awssdk.Bool(true),
			BlockPublicPolicy:     awssdk.Bool(true),
			RestrictPublicBuckets: awssdk.Bool(true),
		},
	})
	if apiErr != nil {
		log.FromContext(ctx).Error().Err(apiErr).
			Str("bucket_name", bucketName).Str("region", region).
			Msg("executor: PutPublicAccessBlock failed")
		return ExecutionResult{}, fmt.Errorf("%w: PutPublicAccessBlock %s (bucket-level block before: %s): %v",
			ErrExecutionFailed, bucketName, before, apiErr)
	}

	detail := fmt.Sprintf("blocked all public access on S3 bucket %s (bucket-level block before: %s)", bucketName, before)
	log.FromContext(ctx).Info().Str("bucket_name", bucketName).Str("region", region).Str("before", before).
		Msg("executor: S3 public access blocked")
	return ExecutionResult{ConnectorID: c.ID, Action: ActionS3BlockPublic, Detail: detail}, nil
}

// publicAccessBlockBefore renders a bucket's own public access block as the
// undo needs it: "none" when the bucket has none (delete the block to undo),
// otherwise the four flags in put-public-access-block syntax (re-apply them).
// An unset flag is false, as S3 treats it.
func publicAccessBlockBefore(out *s3.GetPublicAccessBlockOutput, err error) (string, error) {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchPublicAccessBlockConfiguration" {
		return "none", nil
	}
	if err != nil {
		return "", fmt.Errorf("publicAccessBlockBefore: %w", err)
	}
	if out == nil || out.PublicAccessBlockConfiguration == nil {
		return "", fmt.Errorf("publicAccessBlockBefore: %w: empty response", ErrExecutionFailed)
	}
	b := out.PublicAccessBlockConfiguration
	return fmt.Sprintf("BlockPublicAcls=%t,IgnorePublicAcls=%t,BlockPublicPolicy=%t,RestrictPublicBuckets=%t",
		awssdk.ToBool(b.BlockPublicAcls), awssdk.ToBool(b.IgnorePublicAcls),
		awssdk.ToBool(b.BlockPublicPolicy), awssdk.ToBool(b.RestrictPublicBuckets)), nil
}

// parsePort converts a string port param to int32. Empty string returns 0.
func parsePort(s string) (int32, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parsePort: %w", err)
	}
	return int32(n), nil
}

// isIPv6 reports whether a CIDR string is IPv6 (contains a colon).
func isIPv6(cidr string) bool {
	for _, ch := range cidr {
		if ch == ':' {
			return true
		}
	}
	return false
}
