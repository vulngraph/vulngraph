package govern

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type Handler struct {
	svc         *Service
	tokenSecret string // optional; required for approve-link / deny-link endpoints
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// WithTokenSecret enables the token-validated link endpoints. Must be set when
// EmailApprovalNotifier is active (on the worker), with the same secret,
// validated by the caller with ValidateTokenSecret. The service must also be
// wired WithLinkNonces, or every link is refused.
func (h *Handler) WithTokenSecret(secret string) *Handler {
	h.tokenSecret = secret
	return h
}

type queueItemResponse struct {
	ClusterKey     string `json:"cluster_key"`
	Title          string `json:"title"`
	CheckID        string `json:"check_id,omitempty"`
	ActionClass    string `json:"action_class"`
	Summary        string `json:"summary,omitempty"`
	Outcome        string `json:"outcome"`
	ConfidenceBand string `json:"confidence_band,omitempty"`
	WorstScore     uint8  `json:"worst_score"`
	WorstBand      string `json:"worst_band,omitempty"`
	BlastRadius    int    `json:"blast_radius"`
	// BlastRadiusKnown is false when at least one finding in this cluster
	// had a failed blast-radius walk — BlastRadius is a max across the
	// cluster, so it must never be read as "small" when it's really
	// "partially unmeasured".
	BlastRadiusKnown bool      `json:"blast_radius_known"`
	CoVeConcerns     []string  `json:"cove_concerns,omitempty"`
	SafetyBand       string    `json:"safety_band,omitempty"`
	UnusedCount      int       `json:"unused_count"`
	Count            int       `json:"count"`
	Resources        int       `json:"resources"`
	FindingIDs       []string  `json:"finding_ids"`
	SampleTargets    []string  `json:"sample_targets,omitempty"`
	DecidedAt        time.Time `json:"decided_at"`
	// ConfidenceEffectiveN, ConfidenceGap, and Unlocks are the teaching-value
	// annotation (empty/zero when no confidence reader is wired).
	ConfidenceEffectiveN float64 `json:"confidence_effective_n"`
	ConfidenceGap        float64 `json:"confidence_gap"`
	Unlocks              int     `json:"unlocks"`
	// ConfidenceKnown is false when the confidence lookup failed or no reader is
	// wired — the teaching-value fields above carry no signal in that case, and
	// the queue sorts this item after every item with known confidence.
	ConfidenceKnown bool `json:"confidence_known"`
}

type queueResponse struct {
	Items []queueItemResponse `json:"items"`
}

// Queue returns the decisions awaiting a human governor. Route:
// GET /api/queue?action_class.
//
// action_class is an optional filter, applied server-side — mirrors
// respond.ListDecisions' action_class filter (the same truncation-bug shape:
// filtering an already-fetched, capped slice client-side silently hides
// matches beyond the cap instead of narrowing the query that produces it).
func (h *Handler) Queue(w http.ResponseWriter, r *http.Request) {
	actionClass := r.URL.Query().Get("action_class")
	if actionClass != "" && !respond.ValidActionClassFilters[actionClass] {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid action_class: "+actionClass))
		return
	}
	items, err := h.svc.Queue(r.Context(), actionClass)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("governor queue failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load the decision queue"))
		return
	}
	out := queueResponse{Items: make([]queueItemResponse, len(items))}
	for i, it := range items {
		out.Items[i] = queueItemResponse{
			ClusterKey:           it.ClusterKey,
			Title:                it.Title,
			CheckID:              it.CheckID,
			ActionClass:          it.ActionClass,
			Summary:              it.Summary,
			Outcome:              it.Outcome,
			ConfidenceBand:       it.ConfidenceBand,
			WorstScore:           it.WorstScore,
			WorstBand:            it.WorstBand,
			BlastRadius:          it.BlastRadius,
			BlastRadiusKnown:     it.BlastRadiusKnown,
			CoVeConcerns:         it.CoVeConcerns,
			SafetyBand:           it.SafetyBand,
			UnusedCount:          it.UnusedCount,
			Count:                it.Count,
			Resources:            it.Resources,
			FindingIDs:           it.FindingIDs,
			SampleTargets:        it.SampleTargets,
			DecidedAt:            it.DecidedAt,
			ConfidenceEffectiveN: it.ConfidenceEffectiveN,
			ConfidenceGap:        it.ConfidenceGap,
			Unlocks:              it.Unlocks,
			ConfidenceKnown:      it.ConfidenceKnown,
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

// resolveRequest is the queue card's verdict. cluster_key is accepted for
// compatibility but ignored: the cluster is derived from the pending decisions.
type resolveRequest struct {
	FindingIDs  []string `json:"finding_ids"`
	ActionClass string   `json:"action_class"`
	Verdict     string   `json:"verdict"`
	Note        string   `json:"note"`
}

// Resolve records a governor's verdict on a queued cluster. The actor is the
// session's user, never the request body. Route: POST /api/queue/resolve.
//
// An API key is refused before anything else: a key may be held by an agent,
// and a verdict is a person's judgment that the memory ledger, the pattern
// verdicts and the approval webhook all treat as one.
func (h *Handler) Resolve(w http.ResponseWriter, r *http.Request) {
	if _, viaKey := auth.APIKeyFromContext(r.Context()); viaKey {
		errs.WriteHTTPError(w, errs.Forbidden("API keys cannot record queue verdicts; sign in to approve or deny"))
		return
	}
	var req resolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	err := h.svc.Resolve(r.Context(), ResolveInput{
		FindingIDs:  req.FindingIDs,
		ActionClass: req.ActionClass,
		Verdict:     Verdict(req.Verdict),
		Actor:       actor(r),
		Note:        req.Note,
	})
	switch {
	case errors.Is(err, ErrBadVerdict):
		errs.WriteHTTPError(w, errs.InvalidInput("verdict must be approved, risk_accepted, or denied"))
	case errors.Is(err, ErrNoTargets):
		errs.WriteHTTPError(w, errs.InvalidInput("no decisions to resolve"))
	case errors.Is(err, ErrNotPending), errors.Is(err, ErrAlreadyResolved), errors.Is(err, ErrTargetMismatch):
		errs.WriteHTTPError(w, errs.Conflict("the queue has changed since this card was loaded — refresh and try again"))
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("resolve decision failed")
		errs.WriteHTTPError(w, errs.Internal("failed to resolve the decision"))
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// actor identifies the governor from the session.
func actor(r *http.Request) string {
	if u, ok := auth.UserFromContext(r.Context()); ok && u.Email != "" {
		return u.Email
	}
	return "unknown"
}

// ApproveLink / DenyLink (GET) render a confirmation page — they do NOT mutate.
// A GET must be safe/idempotent: email and antivirus link-prefetchers, proxy
// scanners, and accidental clicks would otherwise auto-record a verdict nobody
// gave, and an approval also fires the approval webhook, whose receiver may act
// on it. The verdict is recorded only by the POST handlers below, after an
// explicit confirmation click on this page.
// Route: GET /api/queue/approve-link/{token}, GET /api/queue/deny-link/{token}
func (h *Handler) ApproveLink(w http.ResponseWriter, r *http.Request) {
	h.renderConfirm(w, r, VerdictApproved)
}

func (h *Handler) DenyLink(w http.ResponseWriter, r *http.Request) {
	h.renderConfirm(w, r, VerdictDenied)
}

// ApproveLinkConfirm / DenyLinkConfirm (POST) record the verdict after the user
// confirms on the page rendered by the GET handler. The token is the credential.
// Route: POST /api/queue/approve-link/{token}, POST /api/queue/deny-link/{token}
func (h *Handler) ApproveLinkConfirm(w http.ResponseWriter, r *http.Request) {
	h.resolveByLink(w, r, VerdictApproved)
}

func (h *Handler) DenyLinkConfirm(w http.ResponseWriter, r *http.Request) {
	h.resolveByLink(w, r, VerdictDenied)
}

// confirmTmpl is the non-mutating GET landing page. html/template escapes the
// verb and URL-escapes the form action, so the base64url token is safe to embed.
var confirmTmpl = template.Must(template.New("confirm").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Confirm {{.Verb}}</title></head>
<body style="font-family:sans-serif;max-width:480px;margin:64px auto;text-align:center">
<h2>Confirm {{.Verb}}</h2>
<p>You are about to <strong>{{.Verb}}</strong> this decision. The action is recorded immediately.</p>
<form method="POST" action="{{.PostURL}}">
<button type="submit" style="padding:10px 24px;font-size:16px;cursor:pointer">Confirm {{.Verb}}</button>
</form>
</body></html>`))

func (h *Handler) renderConfirm(w http.ResponseWriter, r *http.Request, expected Verdict) {
	claims, ok := h.validateLinkToken(w, r, expected)
	if !ok {
		return
	}
	if err := h.svc.LinkUsable(r.Context(), claims); err != nil {
		h.writeLinkError(w, r, err)
		return
	}
	verb, segment := "approve", "approve-link"
	if expected == VerdictDenied {
		verb, segment = "deny", "deny-link"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = confirmTmpl.Execute(w, struct{ Verb, PostURL string }{
		Verb:    verb,
		PostURL: "/api/queue/" + segment + "/" + r.PathValue("token"),
	})
}

func (h *Handler) resolveByLink(w http.ResponseWriter, r *http.Request, expected Verdict) {
	claims, ok := h.validateLinkToken(w, r, expected)
	if !ok {
		return
	}
	if err := h.svc.ResolveByLink(r.Context(), claims); err != nil {
		h.writeLinkError(w, r, err)
		return
	}
	http.Redirect(w, r, "/decisions", http.StatusSeeOther)
}

// writeLinkError explains why a validly signed link cannot be acted on. A
// spent link, or decisions that changed or were resolved since the email was
// sent, is an expected outcome rendered as a page, not a server error.
func (h *Handler) writeLinkError(w http.ResponseWriter, r *http.Request, err error) {
	var msg string
	switch {
	case errors.Is(err, ErrAlreadyResolved):
		msg = "This link was already used, or the decision was already resolved."
	case errors.Is(err, ErrNotPending), errors.Is(err, ErrTargetMismatch):
		msg = "This decision has changed since the email was sent. Review it in the decision queue instead."
	case errors.Is(err, ErrLinkCannotApprove):
		msg = "This kind of change can only be approved by signing in to Vulngraph. Review it in the decision queue."
	case errors.Is(err, ErrLinkCannotDeny):
		msg = "This finding is urgent, so it can only be denied by signing in to Vulngraph. Review it in the decision queue."
	case errors.Is(err, ErrLinksDisabled):
		errs.WriteHTTPError(w, errs.Unavailable("email approval links are not configured"))
		return
	default:
		log.FromContext(r.Context()).Error().Err(err).Msg("resolve-by-link failed")
		errs.WriteHTTPError(w, errs.Internal("failed to record verdict"))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	_, _ = io.WriteString(w, "<!doctype html><p>"+msg+"</p>")
}

// validateLinkToken checks the token's signature, expiry, and that its signed
// verdict matches the link the user followed. Writes the error response
// itself; ok is false when the caller should stop.
func (h *Handler) validateLinkToken(w http.ResponseWriter, r *http.Request, expected Verdict) (LinkClaims, bool) {
	if h.tokenSecret == "" {
		errs.WriteHTTPError(w, errs.Unavailable("email approval links are not configured"))
		return LinkClaims{}, false
	}
	claims, err := ValidateApprovalToken(r.PathValue("token"), h.tokenSecret)
	switch {
	case errors.Is(err, ErrTokenExpired):
		errs.WriteHTTPError(w, errs.InvalidInput("approval link has expired"))
		return LinkClaims{}, false
	case errors.Is(err, ErrTokenInvalid):
		errs.WriteHTTPError(w, errs.InvalidInput("approval link is invalid"))
		return LinkClaims{}, false
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("approve-link token validation failed")
		errs.WriteHTTPError(w, errs.Internal("failed to validate approval link"))
		return LinkClaims{}, false
	}
	// Guard against a token from the wrong link (approve vs deny).
	if claims.Verdict != expected {
		errs.WriteHTTPError(w, errs.InvalidInput("approval link is invalid"))
		return LinkClaims{}, false
	}
	return claims, true
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
