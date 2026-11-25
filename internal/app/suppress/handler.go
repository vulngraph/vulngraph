package suppress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

type suppressionResponse struct {
	FindingID    string    `json:"finding_id"`
	Reason       string    `json:"reason"`
	SuppressedBy string    `json:"suppressed_by"`
	SuppressedAt time.Time `json:"suppressed_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	// Expired is true once ExpiresAt has passed: the suppression no longer
	// matches and the finding is back in the pipeline.
	Expired        bool       `json:"expired"`
	LastReviewedAt *time.Time `json:"last_reviewed_at"`
	ReviewedBy     string     `json:"reviewed_by"`
}

// suppressRequest requires an explicit expiry: the API never invents one, so a
// client cannot create a suppression without someone choosing when it lapses.
type suppressRequest struct {
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

type reviewRequest struct {
	ExpiresAt time.Time `json:"expires_at"`
}

// Suppress silences a finding. Admin-only (gated by the router). The actor is
// taken from the session, never the request body. On an API key the service
// applies the agent rules (Service.agentCheck): 403 for a finding only a
// person may silence, at most 30 days.
func (h *Handler) Suppress(w http.ResponseWriter, r *http.Request) {
	var req suppressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON with a reason and expires_at (RFC 3339)"))
		return
	}
	sup, err := h.svc.SuppressUntil(r.Context(), r.PathValue("id"), req.Reason, actor(r), req.ExpiresAt)
	switch {
	case errors.Is(err, ErrMissingReason):
		errs.WriteHTTPError(w, errs.InvalidInput("a reason is required to suppress a finding"))
		return
	case writeExpiryError(w, err), writeAgentError(w, err):
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("suppress finding failed")
		errs.WriteHTTPError(w, errs.Internal("failed to suppress finding"))
		return
	}
	writeJSON(r.Context(), w, http.StatusCreated, h.toResponse(sup))
}

// Review renews a suppression with a new expiry and records who reviewed it.
// Admin-only. Renewing an expired suppression re-instates it.
func (h *Handler) Review(w http.ResponseWriter, r *http.Request) {
	var req reviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON with expires_at (RFC 3339)"))
		return
	}
	sup, err := h.svc.Review(r.Context(), r.PathValue("id"), actor(r), req.ExpiresAt)
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("finding is not suppressed"))
		return
	case writeExpiryError(w, err), writeAgentError(w, err):
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("review suppression failed")
		errs.WriteHTTPError(w, errs.Internal("failed to review suppression"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, h.toResponse(sup))
}

// writeExpiryError maps an expiry validation failure to a 400 and reports
// whether it wrote one.
func writeExpiryError(w http.ResponseWriter, err error) bool {
	var msg string
	switch {
	case errors.Is(err, ErrMissingExpiry):
		msg = "expires_at is required: every suppression must expire"
	case errors.Is(err, ErrExpiryInPast):
		msg = "expires_at must be in the future"
	case errors.Is(err, ErrExpiryTooFar):
		msg = "expires_at may be at most 365 days away"
	case errors.Is(err, ErrAgentExpiryTooFar):
		msg = "expires_at may be at most 30 days away on an API key"
	default:
		return false
	}
	errs.WriteHTTPError(w, errs.InvalidInput(msg))
	return true
}

// writeAgentError maps an API-key refusal (Service.agentCheck) and reports
// whether it wrote one.
func writeAgentError(w http.ResponseWriter, err error) bool {
	var refused *NeedsPersonError
	switch {
	case errors.As(err, &refused):
		errs.WriteHTTPError(w, errs.Forbidden(fmt.Sprintf(
			"finding %s can only be suppressed from a signed-in session, not an API key (%s)", refused.FindingID, refused.Reason)))
	case errors.Is(err, ErrUnknownFinding):
		errs.WriteHTTPError(w, errs.NotFound("finding not found"))
	default:
		return false
	}
	return true
}

// Unsuppress lifts a suppression. Admin-only.
func (h *Handler) Unsuppress(w http.ResponseWriter, r *http.Request) {
	err := h.svc.Unsuppress(r.Context(), r.PathValue("id"), actor(r))
	if errors.Is(err, ErrNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("finding is not suppressed"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("unsuppress finding failed")
		errs.WriteHTTPError(w, errs.Internal("failed to unsuppress finding"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type bulkSuppressRequest struct {
	FindingIDs []string  `json:"finding_ids"`
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type bulkUnsuppressRequest struct {
	FindingIDs []string `json:"finding_ids"`
}

type bulkResult struct {
	Applied int `json:"applied"`
}

// BulkSuppress silences many findings in one call (bulk triage). Admin-only.
// Best-effort per id: partial failures still apply the rest and are surfaced.
func (h *Handler) BulkSuppress(w http.ResponseWriter, r *http.Request) {
	var req bulkSuppressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON with finding_ids, a reason and expires_at (RFC 3339)"))
		return
	}
	if len(req.FindingIDs) == 0 {
		errs.WriteHTTPError(w, errs.InvalidInput("finding_ids must not be empty"))
		return
	}
	applied, err := h.svc.SuppressMany(r.Context(), req.FindingIDs, req.Reason, actor(r), req.ExpiresAt)
	switch {
	case errors.Is(err, ErrMissingReason):
		errs.WriteHTTPError(w, errs.InvalidInput("a reason is required to suppress findings"))
		return
	case writeExpiryError(w, err), writeAgentError(w, err):
		return
	case err != nil:
		// Partial success is still worth returning; log the detail, report what applied.
		log.FromContext(r.Context()).Warn().Err(err).Int("applied", applied).Msg("bulk suppress partial failure")
	}
	writeJSON(r.Context(), w, http.StatusOK, bulkResult{Applied: applied})
}

// BulkUnsuppress lifts suppressions for many findings. Admin-only. Idempotent.
func (h *Handler) BulkUnsuppress(w http.ResponseWriter, r *http.Request) {
	var req bulkUnsuppressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON with finding_ids"))
		return
	}
	if len(req.FindingIDs) == 0 {
		errs.WriteHTTPError(w, errs.InvalidInput("finding_ids must not be empty"))
		return
	}
	applied, err := h.svc.UnsuppressMany(r.Context(), req.FindingIDs, actor(r))
	if err != nil {
		log.FromContext(r.Context()).Warn().Err(err).Int("applied", applied).Msg("bulk unsuppress partial failure")
	}
	writeJSON(r.Context(), w, http.StatusOK, bulkResult{Applied: applied})
}

// List returns all suppressions, expired ones included (flagged).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	sups, err := h.svc.List(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list suppressions failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list suppressions"))
		return
	}
	out := make([]suppressionResponse, len(sups))
	for i, s := range sups {
		out[i] = h.toResponse(s)
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

// actor identifies who performed the suppression, from the session.
func actor(r *http.Request) string {
	if u, ok := auth.UserFromContext(r.Context()); ok {
		if u.Email != "" {
			return u.Email
		}
		return u.ID
	}
	return ""
}

func (h *Handler) toResponse(s Suppression) suppressionResponse {
	resp := suppressionResponse{
		FindingID:    s.FindingID,
		Reason:       s.Reason,
		SuppressedBy: s.SuppressedBy,
		SuppressedAt: s.SuppressedAt,
		ExpiresAt:    s.ExpiresAt,
		Expired:      h.svc.ExpiredNow(s),
		ReviewedBy:   s.ReviewedBy,
	}
	if !s.LastReviewedAt.IsZero() {
		reviewed := s.LastReviewedAt
		resp.LastReviewedAt = &reviewed
	}
	return resp
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
