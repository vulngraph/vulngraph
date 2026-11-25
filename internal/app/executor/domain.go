// Package executor owns cloud remediation actions: it runs the cloud API call
// a person requests, from a signed-in admin session or with a grant another
// admin minted (a second admin's grant is required where the action or the
// caller needs one), then records the outcome. It reads no queue
// verdict: approving a decision in the queue or by email link runs nothing.
// Execution events are audit_events rows the service inserts and never
// updates (the table is not tamper-proof: docs/security-hardening.md#audit-trail).
// It stores each decision's approve-and-run status (decision_executions), so
// two clicks never run one fix twice, and approval-grant redemptions
// (executor_grant_redemptions), so a grant runs at most once.
//
// AWS actions:
//
//	sg_rule_remove    — revoke a 0.0.0.0/0 or ::/0 ingress rule from a security group
//	iam_key_disable   — disable (or delete) an IAM access key
//	ec2_stop          — stop a running EC2 instance
//	ec2_start         — start a stopped EC2 instance
//	s3_block_public   — block all public access on an S3 bucket
//
// GCP actions:
//
//	gcp_sa_key_disable  — disable a GCP service account key
//	gcp_firewall_remove — remove a GCP firewall rule
//
// Azure actions:
//
//	azure_nsg_rule_remove — remove a rule from an Azure NSG
//
// Every action requires: an authenticated person who asked for it (Vulngraph never
// executes on its own — ADR 087), admin role (enforced at the HTTP layer via
// auth.RequireRole), a connector in read_write mode, and an EXECUTION principal
// distinct from the connector's collection credential (creds.go). The
// destructive subset additionally requires a grant minted by a second admin
// (approval.go). Any action can be run as a dry-run first, which resolves and
// describes the change without contacting the cloud (plan.go).
//
// The only callers are the two transports a person drives — executor.Handler
// (including the decision panel's approve-and-run, service_decision.go) and
// the MCP execute_action tool — and both run synchronously; there is no
// background execution path (TestOnlyHumanTransportsBuildExecutionRequests).
package executor

import (
	"errors"
	"time"
)

// AuditEvent is one row of the insert-only audit trail (the shared
// `audit_events` ClickHouse table, 7-year TTL). Executor writes one per
// attempted execution — successes and failures alike, because "who tried to
// disable which key and was refused" is exactly as auditable as "who did".
// A refusal of who asked that comes before Execute — an API key or a
// too-young account minting a grant, a key running a decision fix, a
// destructive decision fix run with no second admin's request, an admin
// confirming their own request — writes an AuditActionRefused row. Input
// errors that never reach Execute (an unknown decision, a wrong confirmation
// text, a grant asked for an action that needs none) write no row.
type AuditEvent struct {
	TS         time.Time
	Actor      string // authenticated principal's email; "unknown" when unresolved
	Action     string // one of the AuditAction* constants
	TargetType string // always AuditTargetConnector — the credential used
	TargetID   string // connector id
	// Details is JSON: action, params, outcome or error, plus actor_user_id —
	// the stable user id behind Actor. Actor is the authenticated user's email
	// for sessions and API keys alike; actor_user_id is the stable id that
	// attributes the row.
	Details string
}

// Audit action + target values written to audit_events. Kept as constants so
// the trail can be queried without guessing at string spellings.
const (
	AuditActionExecute       = "executor.execute"
	AuditActionExecuteFailed = "executor.execute_failed"
	AuditActionDryRun        = "executor.dry_run"
	AuditActionApprove       = "executor.approve"
	// AuditActionExecuteIntent is written BEFORE a cloud call. If it cannot be
	// written the call is refused, so no mutation happens without a row.
	AuditActionExecuteIntent = "executor.execute_intent"
	// AuditActionExecuteOutcomeUnknown is the result row of a call cut off
	// after its intent row: the change may or may not have landed.
	AuditActionExecuteOutcomeUnknown = "executor.execute_outcome_unknown"
	// AuditActionRunMarkedFailed records an admin releasing a stalled
	// decision run (MarkStalledRunFailed), with what they attested.
	AuditActionRunMarkedFailed = "executor.run_marked_failed"
	// AuditActionRefused records a grant or a decision run refused for who
	// asked, before Execute; details carry the stage and the reason.
	AuditActionRefused   = "executor.refused"
	AuditTargetConnector = "connector"
	// AuditActorUnknown is recorded when no authenticated principal is on the
	// context. It must never be silently dropped: an un-attributed execution is
	// itself the thing an auditor needs to see.
	AuditActorUnknown = "unknown"
)

// Action identifies what remediation to perform.
type Action string

const (
	// ActionSGRuleRemove revokes a specific ingress rule from an EC2 security group.
	ActionSGRuleRemove Action = "sg_rule_remove"
	// ActionIAMKeyDisable disables (and optionally deletes) an IAM access key.
	ActionIAMKeyDisable Action = "iam_key_disable"
	// ActionEC2Stop stops a running EC2 instance.
	ActionEC2Stop Action = "ec2_stop"
	// ActionEC2Start starts a stopped EC2 instance.
	ActionEC2Start Action = "ec2_start"
	// ActionS3BlockPublic blocks all public access on an S3 bucket.
	ActionS3BlockPublic Action = "s3_block_public"
	// ActionGCPSAKeyDisable disables a GCP service account key.
	ActionGCPSAKeyDisable Action = "gcp_sa_key_disable"
	// ActionGCPFirewallRemove removes a GCP firewall rule.
	ActionGCPFirewallRemove Action = "gcp_firewall_remove"
	// ActionAzureNSGRuleRemove removes a rule from an Azure network security group.
	ActionAzureNSGRuleRemove Action = "azure_nsg_rule_remove"
)

// ExecutionRequest describes a single remediation to carry out against a cloud
// connector. Params is action-specific — see the Param constants below.
type ExecutionRequest struct {
	ConnectorID string
	Action      Action
	Params      map[string]string

	// DryRun resolves and describes the change without performing it. Nothing
	// is contacted in the cloud; the result carries the plan the real call
	// would carry out.
	DryRun bool

	// ApprovalToken is a grant minted by a DIFFERENT admin for exactly this
	// connector, action and resolved plan. Required for the destructive subset
	// (see actionSpec.destructive), and for every action when RequireGrant.
	ApprovalToken string

	// RequireGrant makes the approval grant mandatory whatever the action.
	// Set by transports that act for an agent (the MCP seam): an LLM client
	// holding an admin key reads attacker-influenced data, so no mutation it
	// asks for runs without a human's grant. On Approve it permits minting a
	// grant for a non-destructive action.
	RequireGrant bool

	// Reason is the caller's stated justification, written to the audit row.
	Reason string

	// DecisionID names the decision this request carries out when it comes
	// from the decision panel's approve-and-run. Every audit row it produces
	// carries it, so the decision can show its own trail.
	DecisionID string
}

// ExecutionResult is the outcome of a successful execution. The Detail field
// carries a human-readable summary of exactly what was done — or, when DryRun,
// of what would have been done.
type ExecutionResult struct {
	ConnectorID string
	Action      Action
	Detail      string

	// DryRun is true when nothing was changed.
	DryRun bool
	// Destructive is true when this call needs (or needed) a second admin's
	// approval. Surfaced on the dry-run response so an operator learns the
	// approval is coming before they hit the refusal.
	Destructive bool
}

// Param constants are the keys used in ExecutionRequest.Params.
//
// AWS shared:
//
//	region      — AWS region (e.g. eu-west-1); required, overrides connector default
//
// sg_rule_remove:
//
//	group_id    — the security group ID (e.g. sg-0123456789abcdef0)
//	protocol    — IP protocol: "tcp", "udp", "icmp", or "-1" (all)
//	from_port   — start of port range (string int)
//	to_port     — end of port range (string int)
//	cidr        — the CIDR block to remove: "0.0.0.0/0" or "::/0" only
//
// iam_key_disable:
//
//	key_id      — IAM access key ID
//	username    — IAM user name
//	delete_key  — "true" to also delete the key after disabling
//
// ec2_stop / ec2_start:
//
//	instance_id — EC2 instance ID (e.g. i-0123456789abcdef0)
//
// s3_block_public:
//
//	bucket_name — S3 bucket name
const (
	ParamGroupID        = "group_id"
	ParamRegion         = "region"
	ParamProtocol       = "protocol"
	ParamFromPort       = "from_port"
	ParamToPort         = "to_port"
	ParamCIDR           = "cidr"
	ParamKeyID          = "key_id"
	ParamUsername       = "username"
	ParamDeleteKey      = "delete_key"
	ParamInstanceID     = "instance_id"
	ParamBucketName     = "bucket_name"
	ParamServiceAccount = "service_account"
	ParamKeyName        = "key_name"
	ParamFirewallRule   = "firewall_rule"
	ParamProject        = "project"
	ParamSubscriptionID = "subscription_id"
	ParamResourceGroup  = "resource_group"
	ParamNSGName        = "nsg_name"
	ParamRuleName       = "rule_name"
)

var (
	// ErrCapabilityMissing is returned when the connector type does not support
	// the requested action (e.g. asking for sg_rule_remove on a GCP connector).
	ErrCapabilityMissing = errors.New("executor: capability not supported for connector type")

	// ErrExecutionFailed wraps the underlying AWS API error when the action was
	// attempted but the cloud rejected it (e.g. insufficient permissions, resource
	// not found). Callers should not retry on this error.
	ErrExecutionFailed = errors.New("executor: execution failed")

	// ErrOutcomeUnknown is returned when the cloud call was cut off (timeout
	// or cancellation) after its intent row was written: the change may or
	// may not have landed, and only the cloud console can say which.
	ErrOutcomeUnknown = errors.New("executor: result unknown — verify in the cloud console")

	// ErrBadParams is returned when required Params keys are absent or malformed.
	ErrBadParams = errors.New("executor: invalid or missing params")

	// ErrNoExecutionRole is returned when the connector has no execution
	// principal distinct from its collection credential. The executor fails
	// closed on this: no separate write role means no mutation (see creds.go).
	ErrNoExecutionRole = errors.New("executor: connector has no distinct execution role")

	// ErrApprovalRequired is returned when a destructive action was requested
	// with no approval grant, or when no approver is wired at all.
	ErrApprovalRequired = errors.New("executor: action requires a second admin's approval")

	// ErrApprovalInvalid is returned when a grant does not verify, has expired,
	// covers a different change, or was minted by the same admin now executing.
	ErrApprovalInvalid = errors.New("executor: approval grant is not valid for this execution")

	// ErrAuditUnavailable is returned when the pre-execution audit row cannot
	// be written; the cloud call is refused rather than run unaudited.
	ErrAuditUnavailable = errors.New("executor: audit trail unavailable, execution refused")

	// ErrNoPrincipal is returned when a real (non-dry-run) execution arrives
	// with no authenticated principal on the context — no person asked for it,
	// so it does not run (ADR 087).
	ErrNoPrincipal = errors.New("executor: no authenticated person requested this change")

	// ErrBypassAuth is returned when a real execution arrives as the synthetic
	// admin BYPASS_AUTH injects: every request carries that one identity, so
	// the change could be attributed to no person and two-person rules could
	// not tell admins apart.
	ErrBypassAuth = errors.New("executor: BYPASS_AUTH identifies no person, so changes are refused; " +
		"sign in through OIDC, oauth2-proxy or IAP to run them")

	// ErrApprovalNotRequired is returned when an approval is requested for an
	// action that does not need one — a grant nobody will check reads like a
	// control and is not one.
	ErrApprovalNotRequired = errors.New("executor: action does not require approval")

	// ErrDecisionNotFound is returned when a decision id names no decision.
	ErrDecisionNotFound = errors.New("executor: decision not found")

	// ErrNotRunnable is returned when a decision's fix cannot run from Vulngraph
	// (DecisionPlan.Reason says why); the panel shows it as guidance only.
	ErrNotRunnable = errors.New("executor: this decision's fix cannot run from Vulngraph")

	// ErrConfirmationMismatch is returned when a destructive or irreversible
	// fix is confirmed with text other than DecisionPlan's ConfirmText.
	ErrConfirmationMismatch = errors.New("executor: the typed confirmation does not match")

	// ErrRunConflict is returned when a decision's fix is already running,
	// already waiting on a second admin, or already done.
	ErrRunConflict = errors.New("executor: this decision's fix is already running, awaiting a second admin, or done")

	// ErrRunNotStalled is returned when a decision run is released by hand
	// but it is not running, or has not been running long enough to be
	// presumed dead rather than in flight.
	ErrRunNotStalled = errors.New("executor: this decision's run is not stalled")

	// ErrCloudStateUnverified is returned when a stalled run may have changed
	// the cloud (its intent row exists with no result, or its audit trail
	// cannot be read) and the admin releasing it has not attested that they
	// checked the resource.
	ErrCloudStateUnverified = errors.New("executor: the stalled run may have changed the cloud; verify the resource first")

	// ErrDecisionsUnwired is returned by the decision methods when the service
	// was built without WithDecisions.
	ErrDecisionsUnwired = errors.New("executor: approve-and-run is not configured")
)

// DecisionTarget is what a decision proposes to change: its plan's action
// class and the resource of the finding it was made for.
type DecisionTarget struct {
	DecisionID  string
	FindingID   string
	ActionClass string
	// AwaitingHuman is true while the decision's outcome asks a person
	// (parked for approval or escalated). Nothing else has a fix to approve.
	AwaitingHuman bool
	// ResourceType/ResourceID/Region are empty when the finding no longer loads.
	ResourceType string
	ResourceID   string
	Region       string
}

// RunStatus is where a decision's approve-and-run stands.
type RunStatus string

const (
	// RunAwaitingSecondAdmin: the first admin approved a destructive fix and
	// minted the grant; a different admin's confirmation runs it.
	RunAwaitingSecondAdmin RunStatus = "awaiting_second_admin"
	RunRunning             RunStatus = "running"
	// RunOutcomeUnknown: the cloud call was cut off after its intent row, so
	// the change may have landed. Never re-claimed by a click; an admin
	// releases it through MarkStalledRunFailed, attesting they checked.
	RunOutcomeUnknown RunStatus = "outcome_unknown"
	RunSucceeded      RunStatus = "succeeded"
	RunFailed         RunStatus = "failed"
)

// DecisionRun is a decision's execution state — one per decision. The audit
// trail is the history; this is where it stands now.
type DecisionRun struct {
	DecisionID    string
	FindingID     string
	ConnectorID   string
	Action        Action
	Params        map[string]string
	Plan          string
	Status        RunStatus
	RequestedBy   string
	RequestedByID string
	// GrantToken is the first admin's grant while awaiting a second admin. It
	// never leaves the server.
	GrantToken string
	// GrantExpiresAt is zero when the run carries no grant.
	GrantExpiresAt time.Time
	ExecutedBy     string
	ExecutedByID   string
	// Detail is the executor's account of what changed; Error why it did not.
	Detail    string
	Error     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// PlanState is whether a decision's fix can run from Vulngraph.
type PlanState string

const (
	// PlanGuidanceOnly: it cannot (DecisionPlan.Reason says why) — the panel
	// shows the guidance and the CLI to run by hand.
	PlanGuidanceOnly PlanState = "guidance_only"
	// PlanNeedsInput: the finding does not carry every parameter; a person
	// types the rest before the dry run.
	PlanNeedsInput PlanState = "needs_input"
	// PlanReady: every parameter is known; the dry run can go.
	PlanReady PlanState = "ready"
)

// DecisionPlan is what approve-and-run would do for one decision.
type DecisionPlan struct {
	Target DecisionTarget
	State  PlanState
	// Reason explains a guidance_only state to the person reading it.
	Reason string
	// Guidance is nil when no executor action fits the plan.
	Guidance      *Guidance
	ConnectorID   string
	ConnectorName string
	Action        Action
	// Params are the values the decision's finding fixes; Inputs the keys a
	// person may type (they never override Params).
	Params map[string]string
	Inputs []string
	// RequiresSecondAdmin: the fix needs a grant from a second admin.
	RequiresSecondAdmin bool
	// Run is nil until someone first runs or requests the fix.
	Run *DecisionRun
	// Audit is the run's executor audit rows, oldest first. AuditKnown is
	// false when they could not be read — an empty list is then not "no rows".
	Audit      []AuditEvent
	AuditKnown bool
}

// BoundPlan is a DecisionPlan with every parameter settled and resolved
// against the connector: Change is the text the dry run, the grant and the
// execution all bind to.
type BoundPlan struct {
	DecisionPlan
	Change      string
	Destructive bool
	// ConfirmText is what a person must type to confirm a destructive or
	// irreversible fix; empty when a click is enough.
	ConfirmText string
	// GrantToken is set only when running a second admin's confirmation.
	GrantToken string
}

// RequestBuilder turns a bound plan into the executor request that carries it
// out. The decision handler supplies it, so every ExecutionRequest is still
// built in a transport a person drives (TestOnlyHumanTransportsBuildExecutionRequests).
type RequestBuilder func(p BoundPlan, dryRun bool) ExecutionRequest
