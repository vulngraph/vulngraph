package govern

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
)

// resolveTargets is the server-side view of what a verdict applies to.
type resolveTargets struct {
	ids          []string          // deduplicated, request order
	actionClass  string            // shared by every target's pending decision
	fingerprints map[string]string // finding id -> current context fingerprint
	entries      []reasoncache.Entry
}

// pendingTargets validates the requested finding ids against the decisions
// awaiting a governor. Every id must have a pending decision that has not
// already been resolved at its current fingerprint, and all of them must
// share one action class — that class, not the request's, is what the memory
// outcome and the pattern verdict are filed under.
func (s *Service) pendingTargets(ctx context.Context, findingIDs []string) (resolveTargets, error) {
	pend, err := s.pending.ListPending(ctx, pendingScanLimit, "")
	if err != nil {
		return resolveTargets{}, fmt.Errorf("pendingTargets: %w", err)
	}
	resolved, err := s.verdicts.ResolvedFingerprints(ctx)
	if err != nil {
		return resolveTargets{}, fmt.Errorf("pendingTargets: %w", err)
	}
	byID := make(map[string]reasoncache.Entry, len(pend))
	for _, e := range pend {
		byID[e.FindingID] = e
	}

	t := resolveTargets{fingerprints: map[string]string{}}
	for _, id := range findingIDs {
		if _, dup := t.fingerprints[id]; dup {
			continue
		}
		e, ok := byID[id]
		if !ok {
			return resolveTargets{}, fmt.Errorf("%w: %s", ErrNotPending, id)
		}
		if fp, done := resolved[id]; done && fp == e.Fingerprint {
			return resolveTargets{}, fmt.Errorf("%w: %s", ErrAlreadyResolved, id)
		}
		switch {
		case t.actionClass == "":
			t.actionClass = e.ActionClass
		case t.actionClass != e.ActionClass:
			return resolveTargets{}, fmt.Errorf("%w: findings span action classes %q and %q",
				ErrTargetMismatch, t.actionClass, e.ActionClass)
		}
		t.ids = append(t.ids, id)
		t.fingerprints[id] = e.Fingerprint
		t.entries = append(t.entries, e)
	}
	if len(t.ids) == 0 {
		return resolveTargets{}, ErrNoTargets
	}
	return t, nil
}

// decisionSetHash identifies an exact set of decisions: each finding id with
// the context fingerprint it was decided under, order-independent. It keys
// the memory outcome a verdict writes and is what an email approval link
// signs, so neither can be reused for a different or changed set.
func decisionSetHash(ids []string, fingerprints map[string]string) string {
	pairs := make([]string, len(ids))
	for i, id := range ids {
		pairs[i] = id + "\x1f" + fingerprints[id]
	}
	sort.Strings(pairs)
	sum := sha256.Sum256([]byte(strings.Join(pairs, "\x1e")))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// approvalPayload summarises a resolved cluster for the approval notifier.
// Resources/CoVeConcerns/SampleTargets are aggregated the same way
// clusterQueue does for the UI-facing queue — left out they reach the webhook
// as zero values, and CoVeConcerns is what explains WHY the decision went to
// a human in the first place.
func approvalPayload(in ResolveInput, clusterKey, actionClass string, entries []reasoncache.Entry,
	findings []finding.Finding, now time.Time) ApprovalPayload {
	p := ApprovalPayload{
		Source: "graph", EventType: "decision_approved",
		ApprovedBy: in.Actor, ApprovedAt: now.UTC().Format("2006-01-02T15:04:05Z"), Note: in.Note,
		ClusterKey: clusterKey, ActionClass: actionClass, BlastRadiusKnown: true,
	}
	concerns := map[string]bool{}
	for i, e := range entries {
		if i == 0 {
			p.Summary, p.ConfidenceBand = e.Summary, e.ConfidenceBand
		}
		p.Count++
		p.FindingIDs = append(p.FindingIDs, e.FindingID)
		if e.BlastRadius > p.BlastRadius {
			p.BlastRadius = e.BlastRadius
		}
		p.BlastRadiusKnown = p.BlastRadiusKnown && e.BlastRadiusKnown
		for _, c := range e.CoVeConcerns {
			concerns[c] = true
		}
	}
	resources := map[string]bool{}
	for _, f := range findings {
		if f.Score > p.WorstScore {
			p.WorstScore, p.WorstBand, p.Title, p.CheckID = f.Score, f.ScoreBand, f.Title, f.CheckID
		}
		if f.ResourceID != "" {
			// Dedupe on distinct resources before marking seen, as clusterQueue does.
			_, seen := resources[f.ResourceID]
			resources[f.ResourceID] = true
			if !seen && len(p.SampleTargets) < 5 {
				p.SampleTargets = append(p.SampleTargets, f.ResourceID)
			}
		}
	}
	p.Resources = len(resources)
	for c := range concerns {
		p.CoVeConcerns = append(p.CoVeConcerns, c)
	}
	sort.Strings(p.CoVeConcerns)
	return p
}
