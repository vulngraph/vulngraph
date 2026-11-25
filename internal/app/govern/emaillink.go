package govern

// This file holds the email-link resolution path, used only by the
// non-session-authenticated email-link endpoints: the signed token is the
// credential, so everything a link may do is bounded by what it signs.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

// LinkNonces makes email approval links single-use. PGRepo implements it.
type LinkNonces interface {
	// Consume marks nonce spent. first is false when it was already spent.
	Consume(ctx context.Context, nonce string, expiresAt time.Time) (first bool, err error)
	// Spent reports whether nonce has been used.
	Spent(ctx context.Context, nonce string) (bool, error)
}

// linkApprovable is the set of action classes an email link may APPROVE. A
// link is a 48-hour bearer credential in a mailbox — forwarded, scanned,
// sitting in a phone's notifications — and its actor is a mailbox, not a
// signed-in person. That is enough to say yes to a fix that can be undone; an
// isolate or destroy verdict is left to an admin in the queue
// (POST /api/queue/resolve, which takes a session and refuses an API key).
// A link verdict does what the same verdict from the queue does (Resolve):
// verdict and audit rows, a pattern verdict, and for an approval the approval
// notifiers (the approval webhook, approval alerts). Vulngraph runs no fix on
// it: the executor reads no verdict, and runs a fix only on a signed-in
// session (and whatever MFA sign-in took) or on an API key holding a grant a
// different admin minted from one, with that second admin required for a
// destructive fix either way. A webhook receiver that acts on approvals is
// outside those rules (docs/security-hardening.md#approval-webhook).
// A denial is not free either: it records verdicts that keep the
// denied findings out of the queue until their context changes, and a pattern
// verdict for later ones. So a link may deny only findings that are not
// urgent (respond.UrgentEvidence); denying an urgent one takes an admin in
// the queue.
var linkApprovable = map[string]bool{
	string(respond.ClassObserve):   true,
	string(respond.ClassRemediate): true,
	string(respond.ClassModify):    true,
}

// LinkCanApprove reports whether an email link may approve actionClass.
func LinkCanApprove(actionClass string) bool { return linkApprovable[actionClass] }

// ErrLinksDisabled means the single-use store is not wired, so links are refused.
var ErrLinksDisabled = errors.New("govern: email approval links are not configured")

// WithLinkNonces wires the single-use store. Without it every link is refused.
func (s *Service) WithLinkNonces(n LinkNonces) *Service {
	s.nonces = n
	return s
}

// LinkUsable reports whether a validated link can still be acted on, for the
// non-mutating confirmation page: unspent, and its decisions unchanged.
func (s *Service) LinkUsable(ctx context.Context, c LinkClaims) error {
	if s.nonces == nil {
		return ErrLinksDisabled
	}
	spent, err := s.nonces.Spent(ctx, c.Nonce)
	if err != nil {
		return fmt.Errorf("LinkUsable: %w", err)
	}
	if spent {
		return ErrAlreadyResolved
	}
	if _, err := s.linkTargets(ctx, c); err != nil {
		return fmt.Errorf("LinkUsable: %w", err)
	}
	return nil
}

// ResolveByLink records the verdict a validated email link carries, on exactly
// the decisions it signed. The link is refused if those decisions are no
// longer pending, were already resolved, or changed context since the email
// was sent; otherwise its nonce is spent and the verdict recorded with the
// actor "email-link:<recipient>".
func (s *Service) ResolveByLink(ctx context.Context, c LinkClaims) error {
	if s.nonces == nil {
		return ErrLinksDisabled
	}
	targets, err := s.linkTargets(ctx, c)
	if err != nil {
		return fmt.Errorf("ResolveByLink: %w", err)
	}
	first, err := s.nonces.Consume(ctx, c.Nonce, c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("ResolveByLink: %w", err)
	}
	if !first {
		return fmt.Errorf("ResolveByLink: %w: link already used", ErrAlreadyResolved)
	}
	actor := "email-link"
	if c.Recipient != "" {
		actor += ":" + c.Recipient
	}
	return s.Resolve(ctx, ResolveInput{
		FindingIDs:  targets.ids,
		ActionClass: c.ActionClass,
		Verdict:     c.Verdict,
		Actor:       actor,
	})
}

// linkTargets checks the signed decision set against the pending queue.
func (s *Service) linkTargets(ctx context.Context, c LinkClaims) (resolveTargets, error) {
	if !ValidVerdict(c.Verdict) {
		return resolveTargets{}, ErrBadVerdict
	}
	if c.Verdict == VerdictApproved && !LinkCanApprove(c.ActionClass) {
		return resolveTargets{}, fmt.Errorf("%w: %q", ErrLinkCannotApprove, c.ActionClass)
	}
	targets, err := s.pendingTargets(ctx, c.FindingIDs)
	if err != nil {
		return resolveTargets{}, err
	}
	if c.Verdict == VerdictDenied {
		if err := s.refuseUrgentDenial(ctx, targets.ids); err != nil {
			return resolveTargets{}, err
		}
	}
	if targets.actionClass != c.ActionClass {
		return resolveTargets{}, fmt.Errorf("%w: link is for %q, the decisions are now %q",
			ErrTargetMismatch, c.ActionClass, targets.actionClass)
	}
	if decisionSetHash(targets.ids, targets.fingerprints) != c.SetHash {
		return resolveTargets{}, fmt.Errorf("%w: the decisions changed after the link was sent", ErrTargetMismatch)
	}
	return targets, nil
}

// refuseUrgentDenial refuses a link denial when any target is urgent: a
// mailbox bearer token must not be able to take an urgent finding out of the
// queue. A finding that cannot be read counts as urgent — unknown is not safe.
func (s *Service) refuseUrgentDenial(ctx context.Context, ids []string) error {
	fs, err := s.findings.ByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("refuseUrgentDenial: %w", err)
	}
	byID := make(map[string]finding.Finding, len(fs))
	for _, f := range fs {
		byID[f.ID] = f
	}
	for _, id := range ids {
		f, ok := byID[id]
		if !ok {
			return fmt.Errorf("%w: finding %s could not be read", ErrLinkCannotDeny, id)
		}
		if why := linkDenyBlocker(f); why != "" {
			return fmt.Errorf("%w: finding %s is %s", ErrLinkCannotDeny, id, why)
		}
	}
	return nil
}

// linkDenyBlocker says why a link may not deny f ("" when it may): it is
// urgent, or not enriched yet — an empty band is not a low one, so an
// unscored finding fails closed.
func linkDenyBlocker(f finding.Finding) string {
	if why := respond.UrgentEvidence(f); why != "" {
		return why
	}
	if f.ScoreBand == "" {
		return "not yet scored"
	}
	return ""
}
