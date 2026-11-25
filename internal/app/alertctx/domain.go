// Package alertctx answers "what does the graph know about the thing this alert
// is about?". Alerts carry IPs, ARNs, instance ids, hostnames and emails, not
// graph asset ids, so it first resolves each identifier to assets and then
// assembles a bounded context per asset: exposure, blast radius, open findings
// and (for identities) privilege escalation. Read-only; serves both the REST
// endpoint and the MCP get_alert_context tool.
package alertctx

import (
	"errors"
	"time"
)

// Bounds on one request and its response.
const (
	MaxIdentifiers       = 10
	MaxAssets            = 5
	MaxMatchesPerID      = 5
	MaxTop               = 5
	MaxTypes             = 10
	maxFieldLen          = 200
	findingsFetchLimit   = 200
	blastDepth           = 3
	candidateIDLimit     = 200
	subLookupConcurrency = 4
)

var (
	ErrNoIdentifiers  = errors.New("alertctx: at least one identifier is required")
	ErrTooManyIDs     = errors.New("alertctx: too many identifiers")
	ErrEmptyIdentfier = errors.New("alertctx: identifier is empty")
	// ErrUnresolved: no live asset matches the identifier.
	ErrUnresolved = errors.New("alertctx: no live asset matches the identifier")
	// ErrAmbiguous: more than one live asset matches and none by exact id, so
	// picking one would let a same-named resource stand in for the real one.
	ErrAmbiguous = errors.New("alertctx: the identifier matches more than one asset")
	// ErrLookupFailed: a lookup errored or was cut off, so whether the
	// identifier names one asset is not known.
	ErrLookupFailed = errors.New("alertctx: the identifier could not be resolved")
)

// MatchType says which asset attribute an identifier matched.
type MatchType string

const (
	MatchID         MatchType = "id"
	MatchARN        MatchType = "arn"
	MatchInstanceID MatchType = "instance_id"
	MatchIP         MatchType = "ip"
	MatchDNS        MatchType = "dns"
	MatchEmail      MatchType = "email"
	MatchK8s        MatchType = "k8s"
	MatchName       MatchType = "name"
)

// Confidence grades how likely a match is the intended asset.
type Confidence string

const (
	// ConfExact: a globally unique identifier equals the asset id.
	ConfExact Confidence = "exact"
	// ConfHigh: a public attribute equal to the identifier; unique in practice.
	ConfHigh Confidence = "high"
	// ConfMedium: the attribute can legitimately repeat (private IPs across
	// VPCs, namespace/name across clusters).
	ConfMedium Confidence = "medium"
	// ConfLow: a bare name equality; names are not unique.
	ConfLow Confidence = "low"
)

func (c Confidence) rank() int {
	switch c {
	case ConfExact:
		return 3
	case ConfHigh:
		return 2
	case ConfMedium:
		return 1
	default:
		return 0
	}
}

// Resolution statuses for one input identifier.
const (
	StatusResolved   = "resolved"
	StatusUnresolved = "unresolved"
	// StatusLookupFailed means the lookup itself errored: the identifier may
	// well exist. Distinct from unresolved, which is a successful empty answer.
	StatusLookupFailed = "lookup_failed"
)

// Match links one identifier to one asset.
type Match struct {
	AssetID    string
	MatchType  MatchType
	Confidence Confidence
}

// Resolution is the outcome for one input identifier. Every input appears in
// the result exactly once, resolved or not.
type Resolution struct {
	Input      string
	Normalized string // what was actually looked up (e.g. role ARN for a session ARN)
	Status     string
	Reason     string // set for unresolved / lookup_failed
	Matches    []Match
	// MoreMatches is true when more assets matched than MaxMatchesPerID.
	MoreMatches bool
}

// Availability is embedded in every context section. The zero value means the
// section was not measured, so a forgotten or failed section can never read as
// "no risk".
type Availability struct {
	Known  bool
	Reason string // why the section is unavailable, when !Known
}

// AssetSummary is the identity of a resolved asset. Free-text fields originate
// from cloud data and are untrusted.
type AssetSummary struct {
	ID          string
	Name        string
	Type        string
	Provider    string
	AccountID   string
	Region      string
	Environment string
	Owner       string
	PublicIP    string
	PrivateIP   string
	Domain      string
	RiskScore   uint8
	// RiskScoreSource says which score RiskScore is: the graph-propagated one
	// Ladybug serves, or the pre-propagation value on the ClickHouse asset row.
	RiskScoreSource RiskScoreSource
	LastSeen        time.Time
}

// RiskScoreSource names where an asset's risk score came from.
type RiskScoreSource string

const (
	// RiskSourceLadybug: the post-BFS score Ladybug serves, raised by the risk of
	// what the asset can reach.
	RiskSourceLadybug RiskScoreSource = "ladybug"
	// RiskSourceStored: the ClickHouse asset row's score, without propagation;
	// served when the graph engine is unavailable or does not hold the asset.
	RiskSourceStored RiskScoreSource = "stored"
)

// Exposure is whether the asset is directly internet-exposed.
type Exposure struct {
	Availability
	ExposedToInternet bool
}

// ReachableAsset is one high-value asset in a blast radius.
type ReachableAsset struct {
	ID        string
	Name      string
	Type      string
	RiskScore uint8
}

// Blast is the attacker-direction blast radius summary.
type Blast struct {
	Availability
	Count        int // reachable assets, excluding the asset itself
	ByType       map[string]int
	TopReachable []ReachableAsset
	// Truncated: the walk hit its node budget, or ByType / TopReachable were cut.
	Truncated bool
}

// FindingRef is one open finding, trimmed for transport.
type FindingRef struct {
	ID            string
	Title         string
	Severity      string
	Score         uint8
	CheckID       string
	MustFixClass  string
	MustFixReason string
}

// Findings summarises open findings on the asset.
type Findings struct {
	Availability
	Total      int
	BySeverity map[string]int
	MustFix    []FindingRef
	Top        []FindingRef
	// Truncated: more findings exist than were fetched, so Total and
	// BySeverity are lower bounds.
	Truncated bool
}

// Privileges is the privilege-escalation view of an identity, from CIEM
// findings.
type Privileges struct {
	Availability
	CanEscalate bool
	// Techniques lists the CIEM rule ids (check ids) of detected paths.
	Techniques []string
}

// AssetContext is everything known about one resolved asset.
type AssetContext struct {
	Asset      AssetSummary
	MatchedBy  []IdentifierMatch
	Exposure   Exposure
	Blast      Blast
	Findings   Findings
	Privileges *Privileges // nil for assets that are not identities
	Summary    string
}

// IdentifierMatch records which input identifier led to an asset.
type IdentifierMatch struct {
	Input      string
	MatchType  MatchType
	Confidence Confidence
}

// Result is the full answer to one request.
type Result struct {
	Identifiers []Resolution
	Assets      []AssetContext
	// OmittedAssets lists resolved asset ids beyond MaxAssets that were not expanded.
	OmittedAssets []string
	Truncated     bool
	Summary       string
}
