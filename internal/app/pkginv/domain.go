// Package pkginv ingests package inventories that a customer's own scanning
// agent submits (bring-your-own-agent). An inventory is a set of facts about
// one existing VM, never a finding and never a verdict: whether it may be
// believed (InventoryKnown, CVEMatchableKnown) is decided here from what the
// server can check, not from what the agent claims.
package pkginv

import (
	"errors"
	"time"
)

// Limits on one submission.
const (
	// MaxBodyBytes caps the request body.
	MaxBodyBytes = 4 << 20
	// MaxPackages is the SSM path's package cap (10,000): a list over it is
	// refused, never truncated, because a partial list cannot support a verdict.
	MaxPackages = 10_000
	// MaxCovered caps the coverage entries.
	MaxCovered = 64
	// MaxAge is how old observed_at may be at submission.
	MaxAge = 30 * 24 * time.Hour
	// MaxFutureSkew is how far observed_at may lead the server clock.
	MaxFutureSkew = 5 * time.Minute
	// FreshFor is how long a complete capture is believed: the 7-day rule the
	// SSM path applies as stale_inventory.
	FreshFor = 7 * 24 * time.Hour
)

// Gap values the server stamps when an inventory is not known. The CVE gaps
// (asset.CVEGap*) are reused unchanged when the ecosystem cannot be matched.
const (
	GapIncomplete = "byoa_incomplete"
	GapStale      = "byoa_stale"
)

// Audit vocabulary: one row per submission, accepted or rejected.
const (
	AuditActionSubmit = "inventory.submit"
	AuditTargetAsset  = "asset"
	OutcomeAccepted   = "accepted"
	OutcomeRejected   = "rejected"
)

var (
	// ErrInvalid wraps a validation failure; the message names the field, never
	// the submitted value.
	ErrInvalid = errors.New("pkginv: invalid inventory")
	// ErrForbidden is a caller that is not an inventory-scoped key of an admin.
	ErrForbidden = errors.New("pkginv: an inventory-scoped API key is required")
	// ErrAssetNotFound covers an asset that does not exist, is not a VM, is not
	// live, or was deleted or forgotten: all read the same to the caller.
	ErrAssetNotFound = errors.New("pkginv: asset not found")
	// ErrStale is a submission older than the stored one for the same source.
	ErrStale = errors.New("pkginv: a newer inventory from this source is already stored")
	// ErrRateLimited is a key over its per-asset submission budget.
	ErrRateLimited = errors.New("pkginv: rate limited")
)

// Scanner is the provenance an agent must state.
type Scanner struct {
	Name    string
	Version string
}

// OS is the operating system an agent reports; it selects the OSV ecosystem.
type OS struct {
	ID        string
	VersionID string
	Name      string
}

// Covered says what part of the machine the agent read.
type Covered struct {
	Path     string `json:"path,omitempty"`
	VolumeID string `json:"volume_id,omitempty"`
}

// Package is one validated package. Ecosystem is "" for an OS package (the OS
// block decides it) or a language ecosystem name.
type Package struct {
	Ecosystem     string
	Name          string
	Version       string
	SourceName    string
	SourceVersion string
	Epoch         string
	Release       string
}

// Submission is a validated, normalised inventory: duplicates collapsed,
// every string pattern-checked, timestamps in range.
type Submission struct {
	AssetID         string
	CloudResourceID string
	OS              OS
	Packages        []Package
	ObservedAt      time.Time
	Scanner         Scanner
	Complete        bool
	Covered         []Covered
}

// InventoryRecord is the stored claim and the server's verdict on it. The
// *Known flags are zero-false: only Evaluate sets them.
type InventoryRecord struct {
	Source            string
	AssetID           string
	APIKeyID          string
	Scanner           Scanner
	OS                OS
	Ecosystem         string
	ObservedAt        time.Time
	ReceivedAt        time.Time
	Complete          bool
	PackageCount      int
	Covered           []Covered
	InventoryKnown    bool
	CVEMatchableKnown bool
	Gap               string
}

// Principal is the authenticated API key a submission arrives with.
type Principal struct {
	KeyID     string
	Scope     string
	OwnerRole string
}

// scopeInventory and roleAdmin mirror apikey.ScopeInventory and auth.RoleAdmin;
// the domain imports neither so it stays free of infrastructure.
const (
	scopeInventory = "inventory"
	roleAdmin      = "admin"
)

// MaySubmit reports whether p may submit inventory: an inventory-scoped key
// whose owner is still an admin. Demoting the owner switches the key off.
func (p Principal) MaySubmit() bool {
	return p.KeyID != "" && p.Scope == scopeInventory && p.OwnerRole == roleAdmin
}

// SourceKey is the replace-by-source key: one stored inventory per key, scanner
// and asset.
func SourceKey(keyID, scannerName string) string {
	return "byoa:" + keyID + ":" + scannerName
}
