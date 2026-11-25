package connector

import (
	"errors"
	"time"
)

// aws_org connector config keys (ADR 091). The org connector holds the hub
// credential choice and the ExternalId; its children hold only references.
const (
	// OrgKeyHubAuth picks the hub identity: HubAuthAmbient (Vulngraph's own
	// IRSA / Pod Identity / instance role, the default) or HubAuthAccessKey
	// (aws_access_key_id + aws_secret_access_key stored on the org connector).
	OrgKeyHubAuth = "hub_auth"
	// OrgKeyHubRoleARN is the hub role (deploy/aws/graph-hub-role.yaml) the
	// hub credential assumes first, for a hub role that trusts a principal
	// (TrustType=principal: an instance role, or the IAM user whose key
	// hub_auth=access_key stores) rather than graph's session directly. Every
	// role in the chain trusts only the hub role, so it is required with
	// HubAuthAccessKey. Children get it in memory only, like the credential.
	OrgKeyHubRoleARN = "hub_role_arn"
	// OrgKeyManagementRoleARN is the discovery role in the management or
	// delegated-admin account (organizations:List*).
	OrgKeyManagementRoleARN = "management_role_arn"
	// OrgKeyMemberRoleName is the read-only role in every member account
	// (default GraphReadOnly).
	OrgKeyMemberRoleName = "member_role_name"
	// OrgKeyExternalID is the sts:ExternalId every role in the chain requires.
	OrgKeyExternalID = "external_id"
	// OrgKeyRegion is the home region (API calls, children's region).
	OrgKeyRegion = "region"
	// OrgKeyRegions optionally restricts the children's regional sweep (csv).
	OrgKeyRegions = "regions"
	// Account filters, csv. Excludes win; with any include set, an account
	// must match an include. OU filters match any OU on the account's path.
	OrgKeyIncludeAccounts = "include_accounts"
	OrgKeyExcludeAccounts = "exclude_accounts"
	OrgKeyIncludeOUs      = "include_ous"
	OrgKeyExcludeOUs      = "exclude_ous"
	// OrgKeyExecuteRoleName optionally names the Approve & run execution role
	// (deploy/aws/graph-execution-role.yaml) in every member account. Absent,
	// children get no execute_role_arn and the executor fails closed.
	OrgKeyExecuteRoleName = "execute_role_name"

	HubAuthAmbient   = "ambient"
	HubAuthAccessKey = "access_key"

	// ChildKeyOrgConnectorID marks an aws connector as an org child: its hub
	// credential and ExternalId are resolved from that org connector on read.
	ChildKeyOrgConnectorID = "org_connector_id"

	// DefaultMemberRoleName matches deploy/aws/graph-readonly-role.yaml.
	DefaultMemberRoleName = "GraphReadOnly"
	defaultOrgRegion      = "us-east-1"
)

// childSecretKeys are the config keys a child must never store: they are the
// org connector's to hold, and resolveChild supplies them in memory only.
var childSecretKeys = []string{
	"aws_access_key_id", "aws_secret_access_key", "aws_session_token",
	OrgKeyExternalID, "execute_external_id", "readonly_external_id",
}

// OrgAccountStatus is what Vulngraph did with a discovered account.
type OrgAccountStatus string

const (
	// OrgAccountActive: ACTIVE and in scope — the child is enabled.
	OrgAccountActive OrgAccountStatus = "active"
	// OrgAccountPending: PENDING_ACTIVATION — no child until it activates.
	OrgAccountPending OrgAccountStatus = "pending"
	// OrgAccountSuspended / OrgAccountClosed: the child is disabled, its data kept.
	OrgAccountSuspended OrgAccountStatus = "suspended"
	OrgAccountClosed    OrgAccountStatus = "closed"
	// OrgAccountExcluded: a filter puts it out of scope — the child is disabled.
	OrgAccountExcluded OrgAccountStatus = "excluded"
	// OrgAccountRemoved: a complete listing no longer has it — child disabled.
	OrgAccountRemoved OrgAccountStatus = "removed"
	// OrgAccountConflict: another aws connector already collects the account,
	// so no child is created (two connectors would sweep it twice).
	OrgAccountConflict OrgAccountStatus = "conflict"
	// OrgAccountUnknown: AWS returned a state Vulngraph does not know, or an OU
	// filter applies and the account's OU could not be placed. Nothing about
	// its child changes: unknown is not evidence either way.
	OrgAccountUnknown OrgAccountStatus = "unknown"
	// OrgAccountError: graph failed to create or update the child.
	OrgAccountError OrgAccountStatus = "error"
)

// DiscoveredAccount is one account as an organization listing returned it.
type DiscoveredAccount struct {
	ID    string
	Name  string
	Email string
	State string // Organizations State: ACTIVE, SUSPENDED, PENDING_CLOSURE, CLOSED, PENDING_ACTIVATION
	// OUPath is root-to-parent; OUPathKnown is false when the listing did not
	// place the account. An unknown path never satisfies or fails an OU filter.
	OUPath      []string
	OUPathKnown bool
}

// OrgAccount is a stored discovered account, with its child's health.
type OrgAccount struct {
	OrgConnectorID   string
	AccountID        string
	Name             string
	Email            string
	AWSState         string
	OUPath           string
	Status           OrgAccountStatus
	StatusDetail     string
	ChildConnectorID string
	FirstSeenAt      time.Time
	LastSeenAt       time.Time
	StatusChangedAt  time.Time
	// Child is the child connector's health; nil when there is none.
	Child *ChildHealth
}

// ChildHealth is the subset of a child connector the accounts view shows.
type ChildHealth struct {
	Enabled       bool
	SyncStatus    SyncStatus
	SyncError     string
	LastSuccessAt *time.Time
	CreatedAt     time.Time
}

// OrgTestReport is an aws_org connection test, step by step.
type OrgTestReport struct {
	HubOK        bool
	HubIdentity  string
	HubError     string
	ListRan      bool
	ListOK       bool
	AccountCount int
	ListError    string
	Members      []MemberCheck
}

// MemberCheck is the hub → member role chain tested in one account. Cause is
// one of ok, role_missing_or_untrusted, hub_not_permitted, scp_deny,
// reads_denied, hub_credentials_invalid, throttled, error.
type MemberCheck struct {
	AccountID string
	OK        bool
	Cause     string
	Detail    string
}

// ReconcileResult summarises one discovery pass.
type ReconcileResult struct {
	Discovered int
	// Created lists the child connector ids created this pass, so the caller
	// can sync them now instead of at the next periodic sweep.
	Created []string
	// Adopted counts orphaned children (their org connector was deleted)
	// taken over instead of duplicated.
	Adopted  int
	Enabled  int
	Disabled int
	Errors   int
}

var (
	ErrNotOrgConnector = errors.New("connector: not an aws_org connector")
	// ErrOrgParentMissing: a child's org connector is gone or is not an
	// aws_org — its credential cannot be resolved.
	ErrOrgParentMissing = errors.New("connector: org child's aws_org connector is missing")
	// ErrChildStoresSecret guards the no-copied-keys rule at the write.
	ErrChildStoresSecret = errors.New("connector: an org child must not store credentials or the ExternalId")
	// ErrManagedChild: org children are created by discovery, not by hand.
	ErrManagedChild = errors.New("connector: org_connector_id is set by discovery; create an aws_org connector instead")
	// ErrEmptyDiscovery: a listing that succeeded with zero accounts. Every
	// organization lists at least its management account, so this is degraded
	// input and must not read as "every account left".
	ErrEmptyDiscovery = errors.New("connector: organization listing returned no accounts")
	// ErrNoOrgDiscoverer: the pod was built without AWS org access.
	ErrNoOrgDiscoverer = errors.New("connector: aws_org discovery is not wired in this process")
	ErrInvalidConfig   = errors.New("connector: invalid config value")
)
