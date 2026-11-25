package suppress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Repo persists suppressions. PGRepo implements it.
type Repo interface {
	Upsert(ctx context.Context, s Suppression) (Suppression, error)
	Delete(ctx context.Context, findingID string) error
	Get(ctx context.Context, findingID string) (Suppression, error)
	List(ctx context.Context) ([]Suppression, error)
	Review(ctx context.Context, findingID, by string, expiresAt time.Time) (Suppression, error)
	Expiries(ctx context.Context) (map[string]time.Time, error)
	DueExpiryNotice(ctx context.Context, after, until time.Time) ([]Suppression, error)
	MarkExpiryNotified(ctx context.Context, findingIDs []string) error
}

// Auditor appends to the insert-only audit trail. *CHAuditRepo implements it.
type Auditor interface {
	RecordAudit(ctx context.Context, e AuditEvent) error
}

// FindingGate decides, for the findings an API-key request would silence,
// why each may not be ("" when it may): enrich.AgentRefusal, the rule the MCP
// suppress_finding tool applies. A finding missing from the result does not
// exist.
type FindingGate interface {
	AgentRefusals(ctx context.Context, findingIDs []string) (map[string]string, error)
}

type Service struct {
	repo  Repo
	audit Auditor     // nil = auditing disabled (unit tests)
	gate  FindingGate // nil: every API-key suppression is refused
	now   func() time.Time
}

func NewService(repo Repo) *Service { return &Service{repo: repo, now: time.Now} }

// WithAudit attaches the audit sink. An option rather than a constructor
// argument so existing construction sites keep compiling; every wiring that
// serves HTTP must set it.
func (s *Service) WithAudit(a Auditor) *Service {
	s.audit = a
	return s
}

// WithFindingGate wires the check an API-key suppression must pass. Without
// it an API key cannot suppress or review anything: an unchecked finding's
// urgency is unknown, not low.
func (s *Service) WithFindingGate(g FindingGate) *Service {
	s.gate = g
	return s
}

// agentCheck applies the agent rules to a request that authenticated with an
// API key, which an agent may hold: the AgentMaxExpiry cap, and every finding
// must pass the FindingGate. A refusal is audited and nothing is written. A
// session request passes unchanged.
func (s *Service) agentCheck(ctx context.Context, op string, findingIDs []string, by string, expiresAt time.Time) error {
	if _, viaKey := auth.APIKeyFromContext(ctx); !viaKey {
		return nil
	}
	if err := validateAgentExpiry(s.now(), expiresAt); err != nil {
		return err
	}
	ids := make([]string, 0, len(findingIDs))
	for _, id := range findingIDs {
		if id != "" {
			ids = append(ids, id)
		}
	}
	refusals := map[string]string{}
	if s.gate != nil && len(ids) > 0 {
		var err error
		if refusals, err = s.gate.AgentRefusals(ctx, ids); err != nil {
			return fmt.Errorf("agent check: %w", err)
		}
	}
	for _, id := range ids {
		why, found := refusals[id]
		switch {
		case s.gate == nil:
			why = "urgency cannot be checked"
		case !found:
			return fmt.Errorf("%w: %s", ErrUnknownFinding, id)
		}
		if why != "" {
			s.recordAudit(ctx, AuditActionRefused, id, by, map[string]any{"reason": why, "operation": op})
			return &NeedsPersonError{FindingID: id, Reason: why}
		}
	}
	return nil
}

// SuppressUntil silences a finding with a reason until expiresAt. Re-suppressing
// updates the reason, actor and expiry (upsert) — which is why the audit row
// matters: the row it overwrote is gone.
func (s *Service) SuppressUntil(ctx context.Context, findingID, reason, by string, expiresAt time.Time) (Suppression, error) {
	if reason == "" {
		return Suppression{}, ErrMissingReason
	}
	if err := ValidateExpiry(s.now(), expiresAt); err != nil {
		return Suppression{}, fmt.Errorf("SuppressUntil: %w", err)
	}
	if err := s.agentCheck(ctx, "suppress", []string{findingID}, by, expiresAt); err != nil {
		return Suppression{}, fmt.Errorf("SuppressUntil: %w", err)
	}
	sup, err := s.repo.Upsert(ctx, Suppression{FindingID: findingID, Reason: reason, SuppressedBy: by, ExpiresAt: expiresAt})
	if err != nil {
		return Suppression{}, fmt.Errorf("SuppressUntil: %w", err)
	}
	s.recordAudit(ctx, AuditActionSuppress, findingID, by, map[string]any{
		"reason": reason, "expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	return sup, nil
}

// Review renews a suppression: a human looked at it again and set a new expiry.
// Works on an expired suppression too (its row is kept), which re-instates it.
// ErrNotFound if the finding was never suppressed.
func (s *Service) Review(ctx context.Context, findingID, by string, expiresAt time.Time) (Suppression, error) {
	if err := ValidateExpiry(s.now(), expiresAt); err != nil {
		return Suppression{}, fmt.Errorf("Review: %w", err)
	}
	if err := s.agentCheck(ctx, "review", []string{findingID}, by, expiresAt); err != nil {
		return Suppression{}, fmt.Errorf("Review: %w", err)
	}
	prev, err := s.repo.Get(ctx, findingID)
	if err != nil {
		return Suppression{}, fmt.Errorf("Review: %w", err)
	}
	sup, err := s.repo.Review(ctx, findingID, by, expiresAt)
	if err != nil {
		return Suppression{}, fmt.Errorf("Review: %w", err)
	}
	s.recordAudit(ctx, AuditActionReview, findingID, by, map[string]any{
		"expires_at":          expiresAt.UTC().Format(time.RFC3339),
		"previous_expires_at": prev.ExpiresAt.UTC().Format(time.RFC3339),
		"was_expired":         prev.Expired(s.now()),
	})
	return sup, nil
}

// Unsuppress lifts a suppression. Returns ErrNotFound if the finding wasn't suppressed.
//
// The underlying delete is a hard DELETE — without the audit row, a
// suppress→unsuppress cycle leaves the database in exactly the state it started
// in, with no evidence either ever happened.
func (s *Service) Unsuppress(ctx context.Context, findingID, by string) error {
	if err := s.repo.Delete(ctx, findingID); err != nil {
		return fmt.Errorf("Unsuppress: %w", err)
	}
	s.recordAudit(ctx, AuditActionUnsuppress, findingID, by, nil)
	return nil
}

// recordAudit appends one row. A failed audit write is logged, never fatal: the
// state change is already committed, and failing the request would leave the
// caller believing nothing happened when something did.
func (s *Service) recordAudit(ctx context.Context, action, findingID, actor string, details map[string]any) {
	if s.audit == nil {
		return
	}
	if actor == "" {
		actor = AuditActorUnknown
	}
	encoded := []byte("{}")
	if len(details) > 0 {
		if b, err := json.Marshal(details); err == nil {
			encoded = b
		}
	}
	event := AuditEvent{
		TS:         s.now().UTC(),
		Actor:      actor,
		Action:     action,
		TargetType: AuditTargetFinding,
		TargetID:   findingID,
		Details:    string(encoded),
	}
	if err := s.audit.RecordAudit(ctx, event); err != nil {
		log.FromContext(ctx).Error().Err(err).
			Str("actor", actor).Str("audit_action", action).Str("finding_id", findingID).
			Msg("suppress: AUDIT WRITE FAILED — a suppression change has no audit row")
	}
}

// SuppressMany silences a set of findings in one call — the bulk-triage path so a
// team isn't stuck suppressing one finding at a time. It is best-effort
// per id: it applies to as many as it can and returns the count plus a combined
// error naming any that failed, rather than aborting the whole batch on the first
// bad id. A single reason and expiry apply to all.
func (s *Service) SuppressMany(ctx context.Context, findingIDs []string, reason, by string, expiresAt time.Time) (int, error) {
	if reason == "" {
		return 0, ErrMissingReason
	}
	if err := ValidateExpiry(s.now(), expiresAt); err != nil {
		return 0, fmt.Errorf("SuppressMany: %w", err)
	}
	// All or nothing on a key: one finding a person must judge refuses the batch.
	if err := s.agentCheck(ctx, "bulk_suppress", findingIDs, by, expiresAt); err != nil {
		return 0, fmt.Errorf("SuppressMany: %w", err)
	}
	var applied int
	var errs []error
	for _, id := range findingIDs {
		if id == "" {
			continue
		}
		if _, err := s.repo.Upsert(ctx, Suppression{FindingID: id, Reason: reason, SuppressedBy: by, ExpiresAt: expiresAt}); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		s.recordAudit(ctx, AuditActionSuppress, id, by, map[string]any{
			"reason": reason, "expires_at": expiresAt.UTC().Format(time.RFC3339), "bulk": true,
		})
		applied++
	}
	if len(errs) > 0 {
		return applied, fmt.Errorf("SuppressMany: %d of %d failed: %w", len(errs), len(findingIDs), errors.Join(errs...))
	}
	return applied, nil
}

// UnsuppressMany lifts suppressions for a set of findings. Best-effort per id;
// an id that wasn't suppressed is not an error (idempotent bulk unsuppress).
func (s *Service) UnsuppressMany(ctx context.Context, findingIDs []string, by string) (int, error) {
	var applied int
	var errs []error
	for _, id := range findingIDs {
		if id == "" {
			continue
		}
		if err := s.repo.Delete(ctx, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		s.recordAudit(ctx, AuditActionUnsuppress, id, by, map[string]any{"bulk": true})
		applied++
	}
	if len(errs) > 0 {
		return applied, fmt.Errorf("UnsuppressMany: %d of %d failed: %w", len(errs), len(findingIDs), errors.Join(errs...))
	}
	return applied, nil
}

// CarryForward copies an unexpired suppression from a superseded finding to
// the finding that replaced it (same resource, a check split or renamed), so
// a decision a person already made — an intentionally public website bucket —
// does not come back as a fresh, unsuppressed finding. It keeps the original
// reason, actor and expiry, and never overwrites a suppression the new finding
// already has (an expired one included: someone let that lapse). Reports
// whether a suppression was carried.
func (s *Service) CarryForward(ctx context.Context, toFindingID, fromFindingID string) (bool, error) {
	from, err := s.repo.Get(ctx, fromFindingID)
	switch {
	case errors.Is(err, ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("CarryForward: %w", err)
	}
	if from.Expired(s.now()) {
		return false, nil
	}
	switch _, err := s.repo.Get(ctx, toFindingID); {
	case err == nil:
		return false, nil
	case !errors.Is(err, ErrNotFound):
		return false, fmt.Errorf("CarryForward: %w", err)
	}
	if _, err := s.repo.Upsert(ctx, Suppression{
		FindingID: toFindingID, Reason: from.Reason, SuppressedBy: from.SuppressedBy, ExpiresAt: from.ExpiresAt,
	}); err != nil {
		return false, fmt.Errorf("CarryForward: %w", err)
	}
	s.recordAudit(ctx, AuditActionCarry, toFindingID, from.SuppressedBy, map[string]any{
		"reason": from.Reason, "expires_at": from.ExpiresAt.UTC().Format(time.RFC3339), "carried_from": fromFindingID,
	})
	return true, nil
}

// IsSuppressed reports whether a finding is currently suppressed. An expired
// suppression does not count: the finding re-enters the pipeline.
func (s *Service) IsSuppressed(ctx context.Context, findingID string) (bool, error) {
	sup, err := s.repo.Get(ctx, findingID)
	switch {
	case errors.Is(err, ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("IsSuppressed: %w", err)
	}
	return !sup.Expired(s.now()), nil
}

// State reports one finding's suppression standing for the detail view. A
// failed read is an error, never the zero State: a toggle showing "not
// suppressed" for a suppressed finding invites a duplicate suppression.
func (s *Service) State(ctx context.Context, findingID string) (State, error) {
	sup, err := s.repo.Get(ctx, findingID)
	switch {
	case errors.Is(err, ErrNotFound):
		return State{}, nil
	case err != nil:
		return State{}, fmt.Errorf("State: %w", err)
	}
	expired := sup.Expired(s.now())
	return State{Suppressed: !expired, Expired: expired, Suppression: sup}, nil
}

// List returns all suppressions, newest first, expired ones included.
func (s *Service) List(ctx context.Context) ([]Suppression, error) {
	out, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	return out, nil
}

// SuppressionStates splits suppressed finding ids into those still suppressed
// and those whose exception has expired, for annotating a finding list without
// N lookups.
func (s *Service) SuppressionStates(ctx context.Context) (active, expired map[string]struct{}, err error) {
	expiries, err := s.repo.Expiries(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("SuppressionStates: %w", err)
	}
	now := s.now()
	active = make(map[string]struct{}, len(expiries))
	expired = map[string]struct{}{}
	for id, at := range expiries {
		if (Suppression{ExpiresAt: at}).Expired(now) {
			expired[id] = struct{}{}
			continue
		}
		active[id] = struct{}{}
	}
	return active, expired, nil
}

// ExpiryNoticesDue lists the still-active suppressions that expire within
// ExpiryNoticeWindow and have not been announced for their current expiry,
// soonest first.
func (s *Service) ExpiryNoticesDue(ctx context.Context) ([]Suppression, error) {
	now := s.now()
	out, err := s.repo.DueExpiryNotice(ctx, now, now.Add(ExpiryNoticeWindow))
	if err != nil {
		return nil, fmt.Errorf("ExpiryNoticesDue: %w", err)
	}
	return out, nil
}

// MarkExpiryNoticesSent records that the notice for these suppressions' current
// expiry went out, so a worker restart does not announce them again.
func (s *Service) MarkExpiryNoticesSent(ctx context.Context, findingIDs []string) error {
	if len(findingIDs) == 0 {
		return nil
	}
	if err := s.repo.MarkExpiryNotified(ctx, findingIDs); err != nil {
		return fmt.Errorf("MarkExpiryNoticesSent: %w", err)
	}
	return nil
}

// ExpiredNow reports whether sup has expired on the service clock, so the
// transport never reads a wall clock of its own.
func (s *Service) ExpiredNow(sup Suppression) bool { return sup.Expired(s.now()) }
