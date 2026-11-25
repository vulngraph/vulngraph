// Package notify delivers outbound alerts (Slack, …) to configured channels.
// Channels carry per-event routing rules (event types, severities, min score,
// owner teams, environments, the unowned default);
// the service matches a Notification against each enabled channel and posts to
// the ones whose rules accept it. Distinct from internal/app/connector, which
// pulls cloud assets inbound — this pushes notifications outbound.
package notify

import (
	"errors"
	"slices"
	"strings"
	"time"
)

var (
	ErrNotFound      = errors.New("notify: channel not found")
	ErrUnsupported   = errors.New("notify: unsupported channel type")
	ErrMissingConfig = errors.New("notify: missing required config")
	ErrInvalidScope  = errors.New("notify: invalid routing scope")
	ErrInvalidURL    = errors.New("notify: invalid webhook URL")
)

// SealedSecret is one channel's stored secret ciphertext, as the key-rotation
// re-seal pass reads it. It never carries plaintext.
type SealedSecret struct {
	ChannelID  string
	Ciphertext []byte
}

// ChannelType identifies a delivery backend: Slack or a generic webhook.
type ChannelType string

const (
	TypeSlack   ChannelType = "slack"
	TypeWebhook ChannelType = "webhook" // generic JSON POST to a user-supplied URL
)

// EventType categorizes what produced a notification, for per-channel routing.
type EventType string

const (
	EventPhishing   EventType = "phishing"    // confirmed phishing domain (domain monitor)
	EventFinding    EventType = "finding"     // new high/critical finding
	EventDrift      EventType = "drift"       // inventory drift (new exposure, new asset)
	EventDecision   EventType = "decision"    // remediation decision executed / parked
	EventApproval   EventType = "approval"    // a decision cluster was approved
	EventConnector  EventType = "connector"   // connector sync failure
	EventQueryMatch EventType = "query_match" // saved Cypher query result changed
	// EventSuppressionExpiry: finding suppressions are about to expire.
	EventSuppressionExpiry EventType = "suppression_expiry"
	EventTest              EventType = "test" // "send test" button
)

// AllEventTypes is the set offered in the UI for per-channel routing.
var AllEventTypes = []EventType{
	EventPhishing, EventFinding, EventDrift, EventDecision, EventApproval, EventConnector, EventQueryMatch,
	EventSuppressionExpiry,
}

// unwiredEventTypes are advertised in AllEventTypes (so operators can pre-route
// a channel for a feature that is coming) but have NO producer anywhere in the
// codebase at the time of writing — verified by grepping every notify.Dispatch call
// site repo-wide. A channel routed to one of these will never receive a
// notification; that state is surfaced over the API rather than failing
// silently: per channel as channelResponse.UnwiredEventTypes and for the whole
// set as the list response's unwired_event_types (both in handler.go), which
// the Alert Channels UI labels "not emitted yet".
//
//   - EventDrift: asset.DriftEvents (internal/app/asset/drift.go) computes this
//     today only as an on-demand read for the /investigate/drift dashboard —
//     nothing turns a new drift event into a push. Wiring it needs a periodic
//     job that diffs drift events since its last tick and Dispatches one.
//   - EventConnector: connector.Service.RecordSync (internal/app/connector/service.go)
//     already carries the exact signal (SyncError + the error message) — the
//     missing piece is a Dispatch call where SyncWorker.Work
//     (internal/jobs/sync.go) calls recordSync with a non-nil runErr.
//
// EventPhishing, EventFinding, EventDecision, EventApproval, EventQueryMatch and
// EventSuppressionExpiry are all live-dispatched (internal/app/intel/service.go,
// newFindingNotification in internal/jobs/alerts.go, cmd/graph/alert_adapters.go ×2,
// cmd/graph/savedquery_wire.go, internal/jobs/suppression_expiry.go).
var unwiredEventTypes = map[EventType]bool{
	EventDrift:     true,
	EventConnector: true,
}

// Wired reports whether e has at least one known Dispatch call site in the
// codebase. See unwiredEventTypes.
func (e EventType) Wired() bool { return !unwiredEventTypes[e] }

// UnwiredIn returns the event types in routed that have no producer, in
// routed's order. An empty routed list means "all event types", so it is
// checked against AllEventTypes: a channel routed to everything also expects
// the unwired ones.
func UnwiredIn(routed []EventType) []EventType {
	if len(routed) == 0 {
		routed = AllEventTypes
	}
	var out []EventType
	for _, et := range routed {
		if !et.Wired() {
			out = append(out, et)
		}
	}
	return out
}

// Severity buckets a notification for routing + colour. Empty means "unscored".
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Audit actions the service writes to audit_events, target_type
// AuditTargetChannel and target_id the channel id. Details never carry the
// bot token or the webhook URL, only the webhook's host.
const (
	AuditActionChannelCreate = "notify.channel_create"
	AuditActionChannelUpdate = "notify.channel_update" // details: secret_replaced
	AuditActionChannelDelete = "notify.channel_delete"
	AuditTargetChannel       = "alert_channel"
)

// Channel is one configured delivery destination. Secrets (the Slack bot token)
// live encrypted in config; the plaintext is never returned over the API.
type Channel struct {
	ID           string
	Type         ChannelType
	Name         string
	SlackChannel string // "#alerts" or a channel ID (Slack accepts both)
	BotToken     string // Slack: decrypted only in-memory at dispatch; never serialized out
	// WebhookURL is the destination for TypeWebhook channels. It is a secret (it
	// often embeds an auth token), so it is stored encrypted alongside the bot
	// token and never returned over the API.
	WebhookURL string
	Enabled    bool
	EventTypes []EventType // empty = all events
	Severities []string    // empty = all severities
	MinScore   int
	// Ownership/environment scope (ADR 089). OwnerTeams (normalised, see
	// asset.NormalizeOwner) and RouteUnowned together form the owner scope;
	// Environments the environment scope. An empty scope admits everything, as
	// with EventTypes. RouteUnowned makes this a default channel for findings
	// nobody owns — the catch so an unowned finding still reaches someone.
	OwnerTeams      []string
	Environments    []string // prod|staging|dev|unknown
	RouteUnowned    bool
	LastDeliveredAt *time.Time
	LastStatus      string // "" | "ok" | "error"
	LastError       string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// accepts reports whether this channel's routing rules admit n.
func (c Channel) accepts(n Notification) bool {
	if !c.Enabled {
		return false
	}
	if len(n.ChannelIDs) > 0 && !slices.Contains(n.ChannelIDs, c.ID) {
		return false
	}
	if len(c.EventTypes) > 0 && !slices.Contains(c.EventTypes, n.EventType) {
		return false
	}
	// An explicit severity allow-list is scoped to the severities an operator
	// picked; an unscored notification (n.Severity == "") is not one of them,
	// so it does NOT get a free pass. Short-circuiting on n.Severity != ""
	// would let any notification that forgot to set Severity bypass a paging
	// channel's critical-only filter entirely — the zero value reading as
	// "admit", the wrong default for a filter meant to keep noise out (an
	// unmeasured field must not be the permissive case). Every current
	// producer sets a real severity; this guards a future producer that
	// forgets to.
	if len(c.Severities) > 0 && !slices.Contains(c.Severities, n.Severity) {
		return false
	}
	if n.Score < c.MinScore {
		return false
	}
	return c.ownerScopeAdmits(n) && c.envScopeAdmits(n)
}

// ownerScopeAdmits applies the owner scope. Same rule as severities: a scoped
// channel only takes notifications that carry the dimension it is scoped on, so
// an event with no owner at all (phishing, approvals) does not leak into a
// team's channel — and an unowned finding reaches only RouteUnowned channels,
// never a team's by default.
func (c Channel) ownerScopeAdmits(n Notification) bool {
	if len(c.OwnerTeams) == 0 && !c.RouteUnowned {
		return true
	}
	if c.RouteUnowned && n.Unowned {
		return true
	}
	return n.Owner != "" && containsFold(c.OwnerTeams, n.Owner)
}

// envScopeAdmits applies the environment scope. "unknown" is a value an
// operator can list; it is not folded into "prod", because a channel scoped to
// prod that also received every untagged resource would drown in them.
func (c Channel) envScopeAdmits(n Notification) bool {
	if len(c.Environments) == 0 {
		return true
	}
	return n.Environment != "" && containsFold(c.Environments, n.Environment)
}

func containsFold(list []string, v string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), v) })
}

// DeliveryResult is the outcome of one delivery. Eligible counts the enabled
// channels whose routing rules accepted the notification; Delivered counts the
// eligible channels whose send succeeded. Eligible == 0 means routing chose no
// recipient, which a retry cannot change.
type DeliveryResult struct {
	Eligible  int
	Delivered int
}

// Notification is one alert to route. Fields beyond the core are best-effort
// context used to enrich the Slack message.
type Notification struct {
	EventType EventType
	Severity  string // critical|high|medium|low|info or ""
	Score     int    // 0–100; gates against a channel's MinScore
	Title     string // bold headline
	Message   string // body text
	Fields    []Field
	LinkURL   string // optional "view in Vulngraph" link
	LinkText  string
	// Routing dimensions for owner/environment-scoped channels. All zero for an
	// event that is not about an owned resource. Owner is the normalised owner
	// team; Unowned marks a finding with no owner (or whose owner could not be
	// resolved — it must still reach someone). Environment is the asset's
	// classified environment, prod|staging|dev|unknown.
	Owner       string
	Unowned     bool
	Environment string
	// ChannelIDs, when set, restricts delivery to these channels (a saved
	// query's chosen alert channels). Each must still accept n on its own rules.
	ChannelIDs []string
}

// Field is a label/value pair rendered in the Slack attachment.
type Field struct {
	Label string
	Value string
	Short bool
}
