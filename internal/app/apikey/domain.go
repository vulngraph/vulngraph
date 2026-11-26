// Package apikey owns API key generation, storage, and verification.
package apikey

import (
	"errors"
	"time"
)

// Scope is the access level granted to an API key.
type Scope string

const (
	ScopeRead  Scope = "read"
	ScopeWrite Scope = "write"
	ScopeAdmin Scope = "admin"
	// ScopeInventory grants only the package-inventory submission (REST and
	// MCP) for a customer's own scanning agent. It maps to viewer for every
	// other route, and only an admin may mint one.
	ScopeInventory Scope = "inventory"
)

// Valid reports whether s is one of the known scopes.
func (s Scope) Valid() bool {
	return s == ScopeRead || s == ScopeWrite || s == ScopeAdmin || s == ScopeInventory
}

// APIKey is the domain representation of an API key.
// KeyHash and any plaintext key are never present here — only the prefix is
// shown in the UI so users can identify which key is which.
type APIKey struct {
	ID         string
	UserID     string
	Name       string
	Prefix     string // first 8 chars of the key, e.g. "gph_a1b2"
	Scopes     Scope
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	// OwnerEmail, OwnerRole, OwnerCreatedAt and OwnerAdminSince are the owning
	// user's, filled by Verify: the request principal is the owner, never the
	// user-chosen key name, and the owner's account age and time as admin gate
	// executor approvals. OwnerAdminSince is zero when unknown.
	OwnerEmail            string
	OwnerRole             string
	OwnerCreatedAt        time.Time
	OwnerAdminSince       time.Time
	OwnerAuthorityVersion int64
}

// Audit actions the service writes to audit_events, target_type
// AuditTargetAPIKey and target_id the key id. Details never carry the key
// or its prefix.
const (
	AuditActionCreate = "apikey.create"
	AuditActionRevoke = "apikey.revoke"
	AuditTargetAPIKey = "api_key"
)

// DefaultMaxLifetime caps how long any key lives (API_KEY_MAX_LIFETIME_DAYS).
const DefaultMaxLifetime = 90 * 24 * time.Hour

var (
	ErrNotFound     = errors.New("apikey: not found")
	ErrInvalidScope = errors.New("apikey: invalid scope")
	ErrNameRequired = errors.New("apikey: name is required")
	ErrBadExpiry    = errors.New("apikey: expires_at must be in the future and within the maximum key lifetime")
)
