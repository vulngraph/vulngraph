// Package connector owns the configured cloud, source and identity connections
// (aws, aws_org, gcp, github, kubernetes, azure, okta, google_workspace, demo) that
// collectors sync from. Config is encrypted at rest. Get returns it decrypted
// to in-process callers (collectors, executor, webhook, live tools); List
// never returns it.
package connector

import (
	"errors"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

type Type string

const (
	TypeAWS             Type = "aws"
	TypeAWSOrg          Type = "aws_org" // an AWS Organization: discovers accounts, manages one aws child each (ADR 091)
	TypeGCP             Type = "gcp"
	TypeGitHub          Type = "github"
	TypeKubernetes      Type = "kubernetes"
	TypeAzure           Type = "azure"
	TypeOkta            Type = "okta"             // Okta identity provider — human identities
	TypeGoogleWorkspace Type = "google_workspace" // Google Workspace Admin SDK — human identities
	TypeDemo            Type = "demo"             // Acme, a fictional AWS account: no credentials, no cloud calls
)

func (t Type) Valid() bool {
	return t == TypeAWS || t == TypeAWSOrg || t == TypeGCP || t == TypeGitHub || t == TypeKubernetes ||
		t == TypeAzure || t == TypeOkta || t == TypeGoogleWorkspace || t == TypeDemo
}

// requiredKeys lists the Config keys each provider must supply. Validation is
// presence-only here; collectors interpret the values.
//
// AWS and GCP connectors prefer a role/project *reference* that the workload
// identity authenticates. Connectors may still hold secrets: the GitHub App key,
// AWS static access keys (a migration path), the Okta API token, the Workspace
// SA JSON, and Azure SP client secrets.
var requiredKeys = map[Type][]string{
	// AWS accepts either OIDC role assumption (role_arn) or static credentials
	// (aws_access_key_id) as a migration path from an existing asset-inventory
	// tool. region is always needed.
	TypeAWS:        {"region"},
	TypeAWSOrg:     {OrgKeyManagementRoleARN, OrgKeyExternalID},
	TypeGCP:        {"project_id"},
	TypeGitHub:     {"app_id", "installation_id", "private_key_pem"},
	TypeKubernetes: {}, // in-cluster auth — no config keys required
	// Azure: subscription_id scopes the sync; tenant_id is required when using
	// Service Principal auth (client_id + client_secret). For Workload Identity
	// (production target) only subscription_id is needed — ADC resolves the tenant.
	TypeAzure: {"subscription_id"},
	// Identity providers — human identity graph
	TypeOkta:            {"domain", "api_token"},                 // domain = org.okta.com, api_token = SSWS token
	TypeGoogleWorkspace: {"service_account_json", "admin_email"}, // SA with domain-wide delegation
	TypeDemo:            {},                                      // bundled sample data — no config keys required
}

// oneOfKeys lists groups where at least one key in each group must be present
// (in addition to requiredKeys). AWS must carry a credential reference — either
// a role to assume or a static access key — otherwise every sync fails in the
// collector's baseConfig despite passing presence-only validation.
var oneOfKeys = map[Type][][]string{
	TypeAWS: {{"role_arn", "aws_access_key_id"}},
}

// Optional AWS keys (presence-only, not validated here):
//   - readonly_role_arn / readonly_external_id: a ViewOnlyAccess/SecurityAudit
//     role the live chat/verify path assumes instead of role_arn, so that path's
//     IAM ceiling is read-only. The collector always uses role_arn.

type SyncStatus string

const (
	SyncPending SyncStatus = "pending"
	SyncOK      SyncStatus = "ok"
	SyncError   SyncStatus = "error"
)

// Mode describes what the connector's cloud credentials permit.
// Connectors start read_only (safe default); an admin explicitly upgrades
// to read_write once the IAM role/credentials have been granted write permissions.
type Mode string

const (
	ModeReadOnly  Mode = "read_only"
	ModeReadWrite Mode = "read_write"
)

func (m Mode) Valid() bool { return m == ModeReadOnly || m == ModeReadWrite }

// Connector is one configured source. Config holds provider-specific
// credentials/settings and is never serialized to API responses.
type Connector struct {
	ID           string
	Type         Type
	Name         string
	Config       map[string]string
	Enabled      bool
	EventSource  string // "" = schedule-only
	SyncStatus   SyncStatus
	SyncError    string
	LastSyncedAt *time.Time // last sync ATTEMPT (success or failure)
	// LastSuccessAt is the last sync that completed without error. Distinct from
	// LastSyncedAt so a connector that runs on schedule but errors every time is
	// still detected as stale. Nil until the first success.
	LastSuccessAt *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time

	// Mode controls whether this connector can execute cloud mutations.
	// read_only (default) — collector-only, no write API calls permitted.
	// read_write — executor actions (SG rule removal, IAM key rotation, etc.) are allowed.
	// An admin explicitly sets this once the IAM role/credentials have write permissions.
	Mode Mode

	// SyncFingerprint is the combined content hash of all assets the connector
	// returned on its last successful sweep. If it matches the freshly
	// collected assets' fingerprint, the entire write+enrich pipeline is skipped.
	SyncFingerprint string

	// SyncStreak counts consecutive clean, complete, non-backfill syncs — the
	// existing SyncFingerprint matched, the collection wasn't Partial, and no
	// check-registry backfill was pending. EnqueueWorker uses it to back off
	// how often a genuinely quiet connector is re-swept (see
	// internal/jobs/enqueue.go's backoffInterval); a real change, a partial
	// collection, or an outright failure resets it to 0. This exact gap
	// ("Level 3 — skip collection itself for quiet connectors") was
	// deferred as a bigger lift requiring provider change feeds; this is
	// the smaller middle path using only the fingerprint signal already
	// computed, no new AWS integration.
	SyncStreak int32

	// DiskScanMode is the connector's opt-in to agentless VM disk scanning;
	// the zero value is off.
	DiskScanMode diskscan.DiskScanMode
	// DiskScanEnabledBy and DiskScanEnabledAt say who last enabled it and when;
	// empty and nil while off.
	DiskScanEnabledBy string
	DiskScanEnabledAt *time.Time

	// PartialStreak counts consecutive syncs whose collection was Partial
	// (some best-effort collector — e.g. one AWS global service — skipped a
	// permission gap, throttle, or deadline). Reset to 0 the moment one sync
	// completes non-Partial. Deliberately independent of LastSuccessAt, which
	// advances on any sync with runErr == nil regardless of Partial — that gap
	// let a connector go weeks without once completing its global-services
	// phase while Stale() kept reading it as healthy. See PartiallyStale.
	PartialStreak int32
}

// DefaultStaleAfter is how long an enabled connector may go without any sync
// before it is considered stale. Generous enough (24h) never to false-flag the
// 2h reconciliation cadence, tight enough to surface a collector that has
// silently stopped syncing long before its assets age toward the 180d TTL.
const DefaultStaleAfter = 24 * time.Hour

// Stale reports whether an enabled connector has gone too long without a
// SUCCESSFUL sync (or has never succeeded) — the signal that a collector has
// silently stopped working. Measuring against last success (not last attempt)
// means a connector that keeps running but erroring every time is still flagged;
// last-attempt tracking would mask it because the attempt timestamp keeps moving.
// Disabled connectors are never stale. Falls back to created_at until the first
// successful sync stamps last_success_at.
func (c Connector) Stale(now time.Time, after time.Duration) bool {
	if !c.Enabled {
		return false
	}
	if c.LastSuccessAt == nil {
		return now.Sub(c.CreatedAt) > after
	}
	return now.Sub(*c.LastSuccessAt) > after
}

// DefaultPartialStreakThreshold is how many consecutive Partial syncs an
// enabled connector may have before PartiallyStale flags it. 3 tolerates an
// occasional transient skip (a throttle, one bad zone) while still catching
// the sustained case — a permission gap or a phase that structurally never
// finishes in budget — well before Stale()'s 24h would, since Stale() cannot
// see a Partial sync at all: it reads a run with runErr == nil as healthy
// regardless of what it skipped.
const DefaultPartialStreakThreshold = 3

// PartiallyStale reports whether an enabled connector has racked up enough
// consecutive Partial syncs to be considered unhealthy, independent of
// LastSuccessAt — which keeps advancing on every Partial-but-runErr-nil sync
// and so cannot see this failure mode at all. Disabled connectors are never
// flagged, matching Stale.
func (c Connector) PartiallyStale(threshold int32) bool {
	return c.Enabled && c.PartialStreak >= threshold
}

var (
	ErrNotFound      = errors.New("connector: not found")
	ErrNameTaken     = errors.New("connector: name already used for this type")
	ErrInvalidType   = errors.New("connector: invalid type")
	ErrMissingName   = errors.New("connector: name is required")
	ErrMissingConfig = errors.New("connector: missing required config key")
	ErrReadOnly      = errors.New("connector: connector is read_only — upgrade to read_write to enable executor actions")
)

// AssetHashEntry carries the full context for a richer hash upsert that tracks
// per-asset change history in connector_asset_hashes.
type AssetHashEntry struct {
	AssetID string
	Hash    string
	PubIP   string // current public IP (stored as curr_public_ip; rotated to prev on change)
	// PubIPUnread is true when the collector could not read the public IP
	// this sweep (asset.PublicIPUnread): the stored address is kept, so an
	// unread IP is never recorded as a lost exposure.
	PubIPUnread bool
	AssetName   string // current name (stored as curr_name; rotated to prev on change)
	// AssetType is asset.Asset.Type at write time. It is the
	// granularity the scope-aware deletion decision in internal/jobs/sync_deletion_scope.go
	// needs: an absence is only evidence of deletion for a type a completed
	// collector scope this sweep proved it fully enumerated
	// (collect.Result.CompletedEnumerations). Leaving it empty is safe (see
	// StoredAssetHash) but means the row can never become a deletion
	// candidate.
	AssetType string
	// Region is asset.Asset.Region at write time. A
	// region-scoped collector family's completed-scope claim only covers ONE
	// region ("eu-west-1/ec2:instances" proves nothing about eu-west-2) —
	// see internal/app/forget.Family.RegionScoped, the already-audited grammar
	// this same field is matched against in internal/jobs/sync.go's
	// coveredScopes/isCovered. Leaving it empty is safe (see StoredAssetHash)
	// but means the row can never match a region-scoped completed scope.
	Region string
}

// StoredAssetHash is a stored connector_asset_hashes row's read side —
// GetAssetHashes' result. Hash detects content change; AssetType is what lets
// internal/jobs/sync_deletion_scope.go's findDeletedAssets decide whether this row's absence
// from a sweep is evidence of deletion at all.
//
// AssetType is empty for any row a collector wrote without populating
// AssetHashEntry.AssetType. An empty (or otherwise unrecognised) AssetType
// MUST be treated as "not attributable to any completed scope" — i.e. NEVER a
// deletion candidate. A zero value must not read as a safe default: an
// "unknown" type satisfies no exclusion, so treating it as attributable could
// mass-resolve findings the moment any scope completes.
type StoredAssetHash struct {
	Hash      string
	AssetType string
	// Region is the row's stored region. Empty/unrecognised
	// Region MUST be treated exactly like empty/unrecognised AssetType above:
	// "not attributable to any completed scope", never a deletion candidate —
	// a region-scoped family's completed scope proves only ITS region, and a
	// row with no recorded region can never be shown to match it.
	Region string
}

// Audit actions the connector service writes to audit_events, target_type
// AuditTargetConnector and target_id the connector id. Details name the
// config keys a connector was created with, never their values.
const (
	AuditActionCreate      = "connector.create"
	AuditActionModeChange  = "connector.mode_change" // details: before, after
	AuditActionDelete      = "connector.delete"
	AuditActionPurge       = "connector.purge"
	AuditActionPurgeFailed = "connector.purge_failed" // a purge that stopped part way: what it had already removed
	AuditTargetConnector   = "connector"
)

// PurgeResult reports what PurgeAndDelete actually did, so the caller (and the
// admin who triggered it) can see the blast radius rather than a bare "ok".
type PurgeResult struct {
	AssetsDeleted    int
	FindingsResolved int
	EdgesDeleted     int
}

// ErrNoAccountIdentity is returned when a connector's type has no known way to
// resolve the account/project/org it targets — PurgeAndDelete refuses rather
// than guessing which assets belong to it.
var ErrNoAccountIdentity = errors.New("connector: cannot resolve an account identity to purge for this connector type")

// ProvenCapability names a cross-sweep-persisted proof that a connector's
// credentials CAN do something a collector cannot always safely assume from
// ownership/config metadata alone — e.g. "sso_admin" for the AWS Identity
// Center delegated-admin gap (internal/collect/aws/identitycenter.go): AWS
// keeps InstanceMetadata.OwnerAccountId pinned to the management account
// even when SSO administration is delegated elsewhere, so ownership alone
// cannot tell a delegated admin apart from a genuine member account. A
// successful privileged call is the ONE signal that can, and this type is
// how that proof survives past the sweep that produced it.
//
// PROOF IS MONOTONIC: once proven, a capability is
// never unproven by this package. There is deliberately no unprove path — a
// transient failure must not cost a connector its proof, or the very next
// denial after a real regression starts would misread as the pre-proof
// no-op case again.
type ProvenCapability string

// CapabilitySSOAdmin is proven the moment an AWS connector's ListPermissionSets
// call succeeds even once — see internal/collect/aws/identitycenter.go.
const CapabilitySSOAdmin ProvenCapability = "sso_admin"
