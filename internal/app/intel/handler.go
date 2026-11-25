package intel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/errs"
)

// Handler exposes the intel domain over HTTP.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		errs.WriteHTTPErrorCtx(ctx, w, "encode response", http.StatusInternalServerError)
	}
}

// GET /api/intel/domains
func (h *Handler) ListDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := h.svc.ListDomains(r.Context())
	if err != nil {
		errs.WriteHTTPError(w, errs.Internal("list domains failed"))
		return
	}
	type row struct {
		ID        string `json:"id"`
		Domain    string `json:"domain"`
		CreatedAt string `json:"created_at"`
	}
	out := make([]row, len(domains))
	for i, d := range domains {
		out[i] = row{ID: d.ID, Domain: d.Domain, CreatedAt: d.CreatedAt.Format("2006-01-02T15:04:05Z")}
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"domains": out})
}

// POST /api/intel/domains  body: {"domain":"example.com"}
func (h *Handler) AddDomain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid JSON"))
		return
	}
	if req.Domain == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("domain is required"))
		return
	}
	md, err := h.svc.AddDomain(r.Context(), req.Domain)
	if err != nil {
		if errors.Is(err, ErrDomainExists) {
			errs.WriteHTTPError(w, errs.Conflict("domain already monitored"))
			return
		}
		if errors.Is(err, ErrInvalidDomain) {
			errs.WriteHTTPError(w, errs.InvalidInput("not a valid domain name (e.g. example.com)"))
			return
		}
		errs.WriteHTTPError(w, errs.Internal("add domain failed"))
		return
	}
	writeJSON(r.Context(), w, http.StatusCreated, map[string]any{
		"id": md.ID, "domain": md.Domain, "created_at": md.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}

// DELETE /api/intel/domains/{domain}
func (h *Handler) RemoveDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")
	if domain == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("domain is required"))
		return
	}
	if err := h.svc.RemoveDomain(r.Context(), domain); err != nil {
		if errors.Is(err, ErrNotFound) {
			errs.WriteHTTPError(w, errs.NotFound("domain not found"))
			return
		}
		errs.WriteHTTPError(w, errs.Internal("remove domain failed"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/intel/phishing?status=pending|confirmed|dismissed|auto_dismissed
//
// "pending" (the default) is the human queue and means GENUINELY SUSPECTED:
// candidates cleared without a person (triage or re-score) live under auto_dismissed and are counted there, never
// here. An unknown status is a 400 rather than an empty list — a typo'd filter
// returning "no phishing candidates" is the wrong kind of quiet.
func (h *Handler) ListCandidates(w http.ResponseWriter, r *http.Request) {
	status := CandidateStatus(r.URL.Query().Get("status"))
	switch status {
	case "", StatusPending, StatusConfirmed, StatusDismissed, StatusAutoDismissed:
	default:
		errs.WriteHTTPError(w, errs.InvalidInput("unknown status (pending|confirmed|dismissed|auto_dismissed)"))
		return
	}
	candidates, total, err := h.svc.ListCandidates(r.Context(), status)
	if err != nil {
		errs.WriteHTTPError(w, errs.Internal("list candidates failed"))
		return
	}
	type row struct {
		ID              string  `json:"id"`
		Domain          string  `json:"domain"`
		MonitoredDomain string  `json:"monitored_domain"`
		Source          string  `json:"source"`
		SimilarityScore float32 `json:"similarity_score"`
		Issuer          string  `json:"issuer"`
		NotBefore       string  `json:"not_before"`
		NotAfter        string  `json:"not_after"`
		Status          string  `json:"status"`
		AIIsPhishing    bool    `json:"ai_is_phishing"`
		AIConfidence    float32 `json:"ai_confidence"`
		AIReasoning     string  `json:"ai_reasoning"`
		TriageSource    string  `json:"triage_source"`
		ClearedBy       string  `json:"cleared_by"`
		DetectedAt      string  `json:"detected_at"`
		ConfirmedBy     string  `json:"confirmed_by,omitempty"`
		ConfirmedAt     string  `json:"confirmed_at,omitempty"`
	}
	out := make([]row, len(candidates))
	for i, c := range candidates {
		var confirmedAt string
		if c.ConfirmedAt != nil {
			confirmedAt = c.ConfirmedAt.Format("2006-01-02T15:04:05Z")
		}
		out[i] = row{
			ID: c.ID, Domain: c.Domain, MonitoredDomain: c.MonitoredDomain,
			Source: c.Source, SimilarityScore: c.SimilarityScore, Issuer: c.Issuer,
			NotBefore:    c.NotBefore.Format("2006-01-02"),
			NotAfter:     c.NotAfter.Format("2006-01-02"),
			Status:       string(c.Status),
			AIIsPhishing: c.AIIsPhishing,
			AIConfidence: c.AIConfidence, AIReasoning: c.AIReasoning,
			TriageSource: string(c.TriageSource),
			ClearedBy:    string(c.ClearedBy()),
			DetectedAt:   c.DetectedAt.Format("2006-01-02T15:04:05Z"),
			ConfirmedBy:  c.ConfirmedBy, ConfirmedAt: confirmedAt,
		}
	}
	// total is the true population for the status — the list is capped at 500,
	// so len(out) would silently freeze once a bucket outgrows the cap.
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"candidates": out, "total": total})
}

// POST /api/intel/phishing/{id}/confirm
func (h *Handler) ConfirmCandidate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	user, _ := auth.UserFromContext(r.Context())
	if err := h.svc.Confirm(r.Context(), id, user.Email); err != nil {
		if errors.Is(err, ErrNotFound) {
			errs.WriteHTTPError(w, errs.NotFound("candidate not found"))
			return
		}
		errs.WriteHTTPError(w, errs.Internal("confirm failed"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/intel/phishing/{id}/dismiss
func (h *Handler) DismissCandidate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.svc.Dismiss(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			errs.WriteHTTPError(w, errs.NotFound("candidate not found"))
			return
		}
		errs.WriteHTTPError(w, errs.Internal("dismiss failed"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
