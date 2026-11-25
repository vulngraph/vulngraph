package respond

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// DecisionLister reads the agent decision trail. CHRepo implements it.
type DecisionLister interface {
	ListDecisions(ctx context.Context, cursorTS time.Time, cursorID string, limit int, filter DecisionFilter) ([]AuditEvent, error)
	DecisionsSummary(ctx context.Context) (DecisionsSummary, error)
}

// Findings resolves a decision's opaque target id to human-readable context.
// finding.Service implements it.
type Findings interface {
	ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

// RepeatHotspots reads the repeat counters on the reasoning cache. It takes
// precedence over the audit-trail COUNT for the escalation-hotspot panel: a
// byte-identical repeat skips the audit write, so a COUNT over audit_events
// cannot see repeats, while this counter is incremented on exactly that skip
// path. Optional: without it the handler falls back to the trail count, which
// misses repeats.
//
// No concrete type in this tree returns []RepeatHotspot directly —
// reasoncache.Service.TopEscalatedRepeats returns []reasoncache.Entry, and
// this interface deliberately doesn't name that type (respond's seams never
// carry another package's types). Wire it with RepeatHotspotsFunc.
type RepeatHotspots interface {
	TopEscalatedRepeats(ctx context.Context, limit int) ([]RepeatHotspot, error)
}

// RepeatHotspotsFunc adapts a plain closure to RepeatHotspots: the caller
// (cmd/graph) converts reasoncache.Entry to RepeatHotspot itself, so this
// package never imports reasoncache.
type RepeatHotspotsFunc func(ctx context.Context, limit int) ([]RepeatHotspot, error)

func (f RepeatHotspotsFunc) TopEscalatedRepeats(ctx context.Context, limit int) ([]RepeatHotspot, error) {
	return f(ctx, limit)
}

// RepeatHotspot is one repeatedly-escalated finding, from the reasoning cache.
type RepeatHotspot struct {
	FindingID string
	Count     int
	Latest    time.Time
}

// RemediationGuide describes the executor action, if any, that would carry out
// actionClass on the finding's resource. Wire it with RemediationGuideFunc.
type RemediationGuide interface {
	Guide(f finding.Finding, actionClass string) (Remediation, bool)
}

// RemediationGuideFunc adapts a closure to RemediationGuide, so cmd/graph can
// translate executor.GuideFor without this package importing executor.
type RemediationGuideFunc func(f finding.Finding, actionClass string) (Remediation, bool)

func (fn RemediationGuideFunc) Guide(f finding.Finding, actionClass string) (Remediation, bool) {
	return fn(f, actionClass)
}

type Handler struct {
	decisions DecisionLister
	findings  Findings
	repeats   RepeatHotspots
	guide     RemediationGuide
}

func NewHandler(d DecisionLister, f Findings) *Handler { return &Handler{decisions: d, findings: f} }

// WithRepeatHotspots wires the reasoning-cache repeat counters as the source of
// the escalation-hotspot panel. Optional dependency, set at construction.
func (h *Handler) WithRepeatHotspots(r RepeatHotspots) *Handler { h.repeats = r; return h }

// WithRemediationGuide wires the per-decision fix guidance. Optional: without
// it decisions carry no remediation block.
func (h *Handler) WithRemediationGuide(g RemediationGuide) *Handler { h.guide = g; return h }

type decisionResponse struct {
	ID             string    `json:"id"`
	TS             time.Time `json:"ts"`
	Actor          string    `json:"actor"`
	Action         string    `json:"action"`
	TargetType     string    `json:"target_type,omitempty"`
	TargetID       string    `json:"target_id,omitempty"`
	TargetTitle    string    `json:"target_title,omitempty"`    // resolved finding title
	TargetResource string    `json:"target_resource,omitempty"` // resolved resource id
	// TargetMustFixReason is enrich's compact evidence for why the finding
	// matters ("internet-reachable (2 hops) · KEV · blast 42").
	TargetMustFixReason string `json:"target_must_fix_reason,omitempty"`
	// TargetRemediation is the finding source's own fix advice.
	TargetRemediation string               `json:"target_remediation,omitempty"`
	Remediation       *remediationResponse `json:"remediation,omitempty"`
	Details           string               `json:"details,omitempty"`
}

// remediationResponse is the executor action that would carry out the
// decision's plan — present only when one fits the plan's action class and
// the finding's resource type.
type remediationResponse struct {
	Action      string `json:"action"`
	Change      string `json:"change"`
	Destructive bool   `json:"destructive"`
	Reversible  bool   `json:"reversible"`
	Rollback    string `json:"rollback"`
	CLI         string `json:"cli"`
}

type decisionsPage struct {
	Items      []decisionResponse `json:"items"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

// ListDecisions returns the agent decision trail, newest first, one keyset page —
// each decision's opaque target id resolved to its finding title + resource, so
// the trail is human-readable. Route:
// GET /api/decisions?cursor&limit&outcome&action_class.
//
// outcome and action_class are optional AND-ed filters, applied server-side
// so a filtered view is never silently truncated to whatever page happened to
// be loaded. outcome additionally accepts the two UI-derived groupings
// needs_action and safe_to_fix (see DecisionFilter).
func (h *Handler) ListDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := decisionsPageLimit
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	// Clamp here, not just in the repo: len(events) == limit below is how a
	// full page is told apart from an exhausted one (whether to emit
	// next_cursor). Comparing against an unclamped limit would make a request
	// over decisionsPageLimit end its clamped page with no next_cursor,
	// presenting a truncated page as the complete answer.
	if limit > decisionsPageLimit {
		limit = decisionsPageLimit
	}
	cursorTS, cursorID, err := decodeCursor(q.Get("cursor"))
	if err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid cursor"))
		return
	}

	filter := DecisionFilter{Outcome: q.Get("outcome"), ActionClass: q.Get("action_class")}
	if filter.Outcome != "" && !ValidOutcomeFilters[filter.Outcome] {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid outcome: "+filter.Outcome))
		return
	}
	if filter.ActionClass != "" && !ValidActionClassFilters[filter.ActionClass] {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid action_class: "+filter.ActionClass))
		return
	}

	events, err := h.decisions.ListDecisions(r.Context(), cursorTS, cursorID, limit, filter)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list decisions failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list decisions"))
		return
	}

	// Resolve the page's targets to finding context (best-effort — a missing
	// finding just leaves the row showing its id).
	targets := h.resolve(r.Context(), events)

	page := decisionsPage{Items: make([]decisionResponse, len(events))}
	for i, e := range events {
		f := targets[e.TargetID]
		page.Items[i] = decisionResponse{
			ID: e.ID, TS: e.TS, Actor: e.Actor, Action: e.Action,
			TargetType: e.TargetType, TargetID: e.TargetID,
			TargetTitle: f.Title, TargetResource: f.ResourceID,
			TargetMustFixReason: f.MustFixReason, TargetRemediation: f.Remediation,
			Remediation: h.remediation(f, e.Details),
			Details:     e.Details,
		}
	}
	if len(events) == limit {
		last := events[len(events)-1]
		page.NextCursor = encodeCursor(last.TS, last.ID)
	}
	writeJSON(r.Context(), w, http.StatusOK, page)
}

type hotspotResponse struct {
	TargetID       string    `json:"target_id"`
	TargetTitle    string    `json:"target_title,omitempty"`
	TargetResource string    `json:"target_resource,omitempty"`
	Count          int       `json:"count"`
	Latest         time.Time `json:"latest"`
}

type decisionsSummaryResponse struct {
	Total               int               `json:"total"`
	Observed            int               `json:"observed"`
	Escalated           int               `json:"escalated"`
	Parked              int               `json:"parked_for_approval"`
	SuppressedByVerdict int               `json:"suppressed_by_verdict"`
	QuickWins           int               `json:"quick_wins"`
	UniqueResources     int               `json:"unique_resources"`
	ActionClasses       map[string]int    `json:"action_classes"`
	ConfidenceBands     map[string]int    `json:"confidence_bands"`
	EscalationReasons   map[string]int    `json:"escalation_reasons"`
	Hotspots            []hotspotResponse `json:"hotspots"`
}

// DecisionsSummary returns whole-trail aggregates for the Decisions banner and
// Home footer — server-side, so the numbers cover every decision, not just the
// pages the client happened to load. Route: GET /api/decisions/summary.
func (h *Handler) DecisionsSummary(w http.ResponseWriter, r *http.Request) {
	s, err := h.decisions.DecisionsSummary(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("decisions summary failed")
		errs.WriteHTTPError(w, errs.Internal("failed to summarize decisions"))
		return
	}

	// Hotspots come from the reasoning cache's repeat counters when wired: the
	// trail-derived count only sees decisions that were actually audited, but
	// a byte-identical repeat is never re-audited, so that count freezes and
	// slowly becomes historical trivia, while the counter keeps measuring the
	// live "escalating over and over" signal. Best-effort: on a failure keep
	// the trail-derived list rather than dropping the panel.
	hotspots := s.Hotspots
	if h.repeats != nil {
		if live, err := h.repeats.TopEscalatedRepeats(r.Context(), hotspotLimit); err != nil {
			log.FromContext(r.Context()).Warn().Err(err).
				Msg("repeat hotspots unavailable; falling back to the audit-trail count")
		} else {
			hotspots = make([]EscalationHotspot, 0, len(live))
			for _, l := range live {
				// A count of 1 is not a hotspot — it has never repeated.
				if l.Count < 2 {
					continue
				}
				hotspots = append(hotspots, EscalationHotspot{
					TargetID: l.FindingID, Count: l.Count, Latest: l.Latest,
				})
			}
		}
	}

	// Resolve the (<=5) hotspot findings to titles/resources, same best-effort
	// contract as the list path.
	events := make([]AuditEvent, len(hotspots))
	for i, hs := range hotspots {
		events[i] = AuditEvent{TargetID: hs.TargetID}
	}
	targets := h.resolve(r.Context(), events)

	resp := decisionsSummaryResponse{
		Total: s.Total, Observed: s.Observed,
		Escalated: s.Escalated, Parked: s.Parked, QuickWins: s.QuickWins,
		SuppressedByVerdict: s.SuppressedByVerdict,
		UniqueResources:     s.UniqueResources,
		ActionClasses:       s.ActionClasses, ConfidenceBands: s.ConfidenceBands,
		EscalationReasons: s.EscalationReasons,
		Hotspots:          make([]hotspotResponse, len(hotspots)),
	}
	for i, hs := range hotspots {
		resp.Hotspots[i] = hotspotResponse{
			TargetID: hs.TargetID, TargetTitle: targets[hs.TargetID].Title,
			TargetResource: targets[hs.TargetID].ResourceID, Count: hs.Count, Latest: hs.Latest,
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

// resolve maps decision target ids to their findings via one batch read.
func (h *Handler) resolve(ctx context.Context, events []AuditEvent) map[string]finding.Finding {
	out := map[string]finding.Finding{}
	if h.findings == nil || len(events) == 0 {
		return out
	}
	ids := make([]string, 0, len(events))
	for _, e := range events {
		if e.TargetID != "" {
			ids = append(ids, e.TargetID)
		}
	}
	found, err := h.findings.ByIDs(ctx, ids)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("decision target resolution failed")
		return out
	}
	for _, f := range found {
		out[f.ID] = f
	}
	return out
}

// remediation looks up the executor action that would carry out the
// decision's plan. Nothing for an observe plan (it changes nothing), an
// unresolved finding, or details that name no action class.
func (h *Handler) remediation(f finding.Finding, details string) *remediationResponse {
	if h.guide == nil || f.ID == "" {
		return nil
	}
	d, err := ParseDecisionDetails(details)
	if err != nil || d.ActionClass == "" || d.ActionClass == string(ClassObserve) {
		return nil
	}
	g, ok := h.guide.Guide(f, d.ActionClass)
	if !ok {
		return nil
	}
	return &remediationResponse{
		Action: g.Action, Change: g.Change, Destructive: g.Destructive,
		Reversible: g.Reversible, Rollback: g.Rollback, CLI: g.CLI,
	}
}

// Cursor is the opaque keyset token: base64("unixnano|id").
func encodeCursor(ts time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(ts.UnixNano(), 10) + "|" + id))
}

func decodeCursor(token string) (time.Time, string, error) {
	if token == "" {
		return time.Time{}, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", errs.InvalidInput("malformed cursor")
	}
	ns, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, "", err
	}
	return time.Unix(0, ns), parts[1], nil
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
