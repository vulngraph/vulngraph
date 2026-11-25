package apikey

import (
	"context"
	"fmt"
	"time"
)

// Repository is the persistence the Service needs. PGRepo implements it.
type Repository interface {
	Create(ctx context.Context, userID, name string, scope Scope, expiresAt *time.Time) (APIKey, string, error)
	List(ctx context.Context, userID string) ([]APIKey, error)
	Delete(ctx context.Context, id, userID string) error
	Verify(ctx context.Context, plaintext string) (APIKey, error)
}

// AuditRecorder writes the audit_events row of an admin action that has taken
// effect, and reports its own write failures (audit.Service).
type AuditRecorder interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

// Service contains all business logic for API keys.
type Service struct {
	repo        Repository
	maxLifetime time.Duration
	now         func() time.Time
	audit       AuditRecorder // nil: no audit rows (tests)
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo, maxLifetime: DefaultMaxLifetime, now: time.Now}
}

// WithMaxLifetime sets the longest any key may live. d <= 0 keeps the default.
func (s *Service) WithMaxLifetime(d time.Duration) *Service {
	if d > 0 {
		s.maxLifetime = d
	}
	return s
}

// WithAudit records key creation and revocation in audit_events.
func (s *Service) WithAudit(a AuditRecorder) *Service {
	s.audit = a
	return s
}

func (s *Service) record(ctx context.Context, action, keyID string, details map[string]any) {
	if s.audit != nil {
		s.audit.Record(ctx, action, AuditTargetAPIKey, keyID, details)
	}
}

// EffectiveExpiry is when k stops authenticating: its own expires_at, capped
// at created_at + the maximum lifetime. The cap also bounds a key with no
// expires_at (NULL): it expires maxLifetime after creation.
func (s *Service) EffectiveExpiry(k APIKey) time.Time {
	limit := k.CreatedAt.Add(s.maxLifetime)
	if k.ExpiresAt != nil && k.ExpiresAt.Before(limit) {
		return *k.ExpiresAt
	}
	return limit
}

// Create validates the request and delegates to the repo. It returns the new
// APIKey and the plaintext key — the plaintext must be shown to the user once
// and is not stored in recoverable form.
//
// expiresAt nil means "as long as allowed": now + the maximum lifetime. An
// explicit expiresAt beyond the maximum is refused rather than silently
// shortened. Keys are created from a session only (see the handler), so no
// key ever mints a successor.
func (s *Service) Create(ctx context.Context, userID, name string, scope Scope, expiresAt *time.Time) (APIKey, string, error) {
	if !scope.Valid() {
		return APIKey{}, "", fmt.Errorf("Create: %w", ErrInvalidScope)
	}
	if name == "" {
		return APIKey{}, "", fmt.Errorf("Create: %w", ErrNameRequired)
	}
	now := s.now()
	limit := now.Add(s.maxLifetime)
	expiry := limit
	if expiresAt != nil {
		if !expiresAt.After(now) || expiresAt.After(limit) {
			return APIKey{}, "", fmt.Errorf("Create: %w", ErrBadExpiry)
		}
		expiry = *expiresAt
	}
	key, plaintext, err := s.repo.Create(ctx, userID, name, scope, &expiry)
	if err != nil {
		return APIKey{}, "", fmt.Errorf("Create: %w", err)
	}
	s.record(ctx, AuditActionCreate, key.ID, map[string]any{
		"owner_user_id": userID, "name": name, "scope": string(scope), "expires_at": expiry.UTC().Format(time.RFC3339),
	})
	return key, plaintext, nil
}

// List returns all keys owned by userID, with ExpiresAt set to each key's
// effective expiry so the UI shows when it really stops working.
func (s *Service) List(ctx context.Context, userID string) ([]APIKey, error) {
	keys, err := s.repo.List(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	for i := range keys {
		exp := s.EffectiveExpiry(keys[i])
		keys[i].ExpiresAt = &exp
	}
	return keys, nil
}

// Delete removes a key by id, restricted to the owning user.
func (s *Service) Delete(ctx context.Context, id, userID string) error {
	if err := s.repo.Delete(ctx, id, userID); err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	s.record(ctx, AuditActionRevoke, id, map[string]any{"owner_user_id": userID})
	return nil
}

// Verify authenticates a raw key string and returns the matching APIKey with
// ExpiresAt set to its effective expiry. A key past created_at + the maximum
// lifetime is ErrNotFound even when its own expires_at is later (or NULL).
func (s *Service) Verify(ctx context.Context, plaintext string) (APIKey, error) {
	key, err := s.repo.Verify(ctx, plaintext)
	if err != nil {
		return APIKey{}, fmt.Errorf("Verify: %w", err)
	}
	exp := s.EffectiveExpiry(key)
	if !exp.After(s.now()) {
		return APIKey{}, fmt.Errorf("Verify: %w", ErrNotFound)
	}
	key.ExpiresAt = &exp
	return key, nil
}
