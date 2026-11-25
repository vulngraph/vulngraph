package finding

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Suppressions reports which findings are currently suppressed and which had a
// suppression that expired, so the list can flag both. suppress.Service
// implements it; nil disables the annotation.
// Findings live in ClickHouse and suppressions in Postgres, so this cross-store
// join lives in the handler (transport), keeping the finding repo/service
// single-store.
type Suppressions interface {
	SuppressionStates(ctx context.Context) (active, expired map[string]struct{}, err error)
}

type Handler struct {
	svc          *Service
	suppressions Suppressions
}

func NewHandler(svc *Service, suppressions Suppressions) *Handler {
	return &Handler{svc: svc, suppressions: suppressions}
}

type findingResponse struct {
	ID             string `json:"id"`
	Source         string `json:"source"`
	Type           string `json:"type"`
	Severity       string `json:"severity"`
	Score          uint8  `json:"score"`
	KnownExploited bool   `json:"known_exploited,omitempty"`
	IsSuppressed   bool   `json:"is_suppressed,omitempty"`
	// SuppressionKnown is false when the suppression lookup failed (or no
	// suppression source is wired): is_suppressed/exception_expired are then
	// unmeasured, not "active", and a client must not present them as such.
	SuppressionKnown bool `json:"suppression_known"`
	// ExceptionExpired: the finding was suppressed, the suppression lapsed, and
	// it is back in the pipeline — the "previously excepted" flag.
	ExceptionExpired bool      `json:"exception_expired,omitempty"`
	Title            string    `json:"title"`
	ResourceType     string    `json:"resource_type,omitempty"`
	ResourceID       string    `json:"resource_id,omitempty"`
	Region           string    `json:"region,omitempty"`
	CheckID          string    `json:"check_id,omitempty"`
	DetectedAt       time.Time `json:"detected_at"`

	// Enrichment state — never omitempty, and enriched_at is exposed, because a
	// client otherwise cannot tell "the pipeline scored this and the answer is
	// nothing" from "the pipeline never ran". Without it a client must guess
	// (score === 0 && !score_band), which is indistinguishable from a genuinely
	// zero-scored finding. score_band/safety_class/must_fix_class below lose their
	// omitempty for the same reason: "" is a REAL value on each of them (see
	// finding.EnrichmentState), and an absent JSON key cannot carry it.
	EnrichmentState EnrichmentState `json:"enrichment_state"`
	EnrichedAt      *time.Time      `json:"enriched_at,omitempty"`
	ScoreBand       string          `json:"score_band"`

	// Structural "safe to fix" signal (advisory; internal/app/enrich/safety.go).
	// safety_class is safe|caution|risky ("" = no verdict); dependents/unused are
	// the "will it break?" evidence; fix_target is a compact "where to fix" hint.
	SafetyClass string `json:"safety_class"`
	Dependents  uint16 `json:"dependents,omitempty"`
	Unused      bool   `json:"unused,omitempty"`
	FixTarget   string `json:"fix_target,omitempty"`

	// Evidence-backed urgency:
	// must_fix|elevated|contained|controlled|routine. "routine" means "weighed, no
	// positive exploitability evidence" — a deliberate scope boundary, not a gap
	// (mustfix.go) — and is the majority verdict. "" means enrichment has not run:
	// read it together with enrichment_state.
	MustFixClass  string `json:"must_fix_class"`
	MustFixReason string `json:"must_fix_reason,omitempty"`

	// Lifecycle. last_observed_at is when the emitting check/collector
	// last re-observed this finding; resolved_at is set once it stopped being
	// observed, and resolution_reason says WHY — "fixed" (the control was
	// corrected) reads very differently to "resource_gone" (it evaporated on its
	// own), and conflating them is what made check quality unmeasurable. Resolved
	// findings appear only with ?include_resolved=true.
	LastObservedAt   *time.Time       `json:"last_observed_at,omitempty"`
	ResolvedAt       *time.Time       `json:"resolved_at,omitempty"`
	ResolutionReason ResolutionReason `json:"resolution_reason,omitempty"`

	// Routing context (ADR 089). owner_source and environment are never
	// omitted: "" on either means enrichment has not stamped it yet, which a
	// client must be able to tell apart from "none" (unowned) and "unknown".
	OwnerTeam       string `json:"owner_team,omitempty"`
	OwnerSource     string `json:"owner_source"`
	OwnerConfidence string `json:"owner_confidence,omitempty"`
	Environment     string `json:"environment"`
}

// validEnvironments are the values ?environment= accepts — the classifier's
// closed set (asset.Environment).
var validEnvironments = map[string]bool{"prod": true, "staging": true, "dev": true, "unknown": true}

// lifecycleTime maps the zero/sentinel DateTime to nil so JSON omits it.
func lifecycleTime(t time.Time) *time.Time {
	if t.IsZero() || t.Year() <= 2000 {
		return nil
	}
	return &t
}

// findingPage is the paginated list response. next_cursor is set only
// when the page is full (more may follow); absent on the last page.
type findingPage struct {
	Items      []findingResponse `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

// List returns a page of findings, filterable by ?source= and ?severity= with
// ?limit=. Results are sorted by enriched score (the surfaced risk value) by
// default; ?sort=detected reverts to newest-first. Pass ?cursor= (from a prior
// response's next_cursor) to page forward.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := Filter{
		Source:          q.Get("source"),
		Severity:        Severity(q.Get("severity")),
		ResourceID:      q.Get("resource_id"),
		CheckID:         q.Get("check_id"),
		SortByScore:     q.Get("sort") != "detected",
		SafeOnly:        q.Get("safe") == "true",
		MustFixOnly:     q.Get("must_fix") == "true",
		IncludeResolved: q.Get("include_resolved") == "true",
		Cursor:          q.Get("cursor"),
		// Owners are stored normalised, so "@acme/Payments" and "payments"
		// select the same team.
		Owner:       asset.NormalizeOwner(q.Get("owner")),
		Environment: q.Get("environment"),
	}
	if f.Environment != "" && !validEnvironments[f.Environment] {
		errs.WriteHTTPError(w, errs.InvalidInput("environment must be one of prod, staging, dev, unknown"))
		return
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			errs.WriteHTTPError(w, errs.InvalidInput("limit must be a non-negative integer"))
			return
		}
		f.Limit = n
	}
	if raw := q.Get("min_score"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 100 {
			errs.WriteHTTPError(w, errs.InvalidInput("min_score must be between 0 and 100"))
			return
		}
		f.MinScore = uint8(n)
	}

	findings, err := h.svc.List(r.Context(), f)
	if errors.Is(err, ErrBadCursor) {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid cursor"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list findings failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list findings"))
		return
	}

	suppressed, expired, suppressionKnown := h.suppressionStates(r.Context())

	now := time.Now()
	out := make([]findingResponse, len(findings))
	for i, f := range findings {
		_, isSuppressed := suppressed[f.ID]
		_, exceptionExpired := expired[f.ID]
		out[i] = findingResponse{
			ID: f.ID, Source: f.Source, Type: f.Type, Severity: string(f.Severity),
			Score: f.Score, ScoreBand: f.ScoreBand, KnownExploited: f.KnownExploited,
			IsSuppressed: isSuppressed, SuppressionKnown: suppressionKnown, ExceptionExpired: exceptionExpired,
			Title: f.Title, ResourceType: f.ResourceType, ResourceID: f.ResourceID,
			Region: f.Region, CheckID: f.CheckID, DetectedAt: f.DetectedAt,
			EnrichmentState: f.EnrichmentStateAt(now), EnrichedAt: lifecycleTime(f.EnrichedAt),
			SafetyClass: f.SafetyClass, Dependents: f.Dependents, Unused: f.Unused, FixTarget: f.FixTarget,
			MustFixClass: f.MustFixClass, MustFixReason: f.MustFixReason,
			LastObservedAt: lifecycleTime(f.LastObservedAt), ResolvedAt: lifecycleTime(f.ResolvedAt),
			ResolutionReason: f.ResolutionReason,
			OwnerTeam:        f.OwnerTeam, OwnerSource: f.OwnerSource, OwnerConfidence: f.OwnerConfidence,
			Environment: f.Environment,
		}
	}

	// A full page may have more behind it — hand back a cursor to seek past the
	// last row. A short page is the end, so no cursor.
	page := findingPage{Items: out}
	effLimit := f.Limit
	if effLimit <= 0 || effLimit > DefaultLimit {
		effLimit = DefaultLimit
	}
	if len(findings) == effLimit {
		page.NextCursor = EncodeCursor(findings[len(findings)-1], f.SortByScore)
	}
	writeJSON(r.Context(), w, http.StatusOK, page)
}

// suppressionStates fetches the active and expired suppression sets once for the
// list. A suppression lookup failure must not fail the findings list, but it
// must not pass for "nothing is suppressed" either: known=false marks every
// row's suppression standing as unmeasured (suppression_known, as findingctx).
func (h *Handler) suppressionStates(ctx context.Context) (active, expired map[string]struct{}, known bool) {
	if h.suppressions == nil {
		return nil, nil, false
	}
	active, expired, err := h.suppressions.SuppressionStates(ctx)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("suppression state lookup failed; suppression_known=false")
		return nil, nil, false
	}
	return active, expired, true
}

type resolveRequest struct {
	Reason string `json:"reason"`
}

type resolveResponse struct {
	ID         string    `json:"id"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// Resolve manually marks one finding resolved — the human-driven counterpart
// to the sync-time auto-resolve, for when a live check (e.g. "Verify
// live" against the cloud) refutes a finding the emitting check hasn't
// re-synced yet. Admin-only (gated by the router). ReasonManual, not
// ReasonFixed: folding manual triage into "fixed" would let it inflate a
// check's measured effectiveness (see resolution.go). The person's free-text
// reason is kept on the finding and in the finding.resolve audit row
// (Service.ResolveManually). On an API key a finding only a person may close
// is refused with 403.
func (h *Handler) Resolve(w http.ResponseWriter, r *http.Request) {
	var req resolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON with a reason"))
		return
	}
	if req.Reason == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("a reason is required to resolve a finding"))
		return
	}

	f, err := h.svc.ResolveManually(r.Context(), r.PathValue("id"), req.Reason, actor(r))
	var refused *NeedsPersonError
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("finding not found"))
		return
	case errors.As(err, &refused):
		errs.WriteHTTPError(w, errs.Forbidden(
			"this finding can only be resolved from a signed-in session, not an API key ("+refused.Reason+")"))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("resolve finding failed")
		errs.WriteHTTPError(w, errs.Internal("failed to resolve finding"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, resolveResponse{ID: f.ID, ResolvedAt: f.ResolvedAt})
}

// actor identifies who performed the manual action, from the session.
func actor(r *http.Request) string {
	if u, ok := auth.UserFromContext(r.Context()); ok {
		if u.Email != "" {
			return u.Email
		}
		return u.ID
	}
	return ""
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
