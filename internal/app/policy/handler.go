package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// policyService is the narrow interface Handler needs — *Service satisfies it.
type policyService interface {
	Get(ctx context.Context) (Policy, error)
	Update(ctx context.Context, p Policy) error
}

// Handler is the HTTP transport layer for the remediation policy.
type Handler struct {
	svc policyService
}

// NewHandler returns a Handler backed by svc.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// policyResponse is the wire shape for the policy — keeps internal types off
// the API surface.
type policyResponse struct {
	ID               string                `json:"id"`
	SuggestThreshold int                   `json:"suggest_threshold"`
	ActionRules      map[string]ActionMode `json:"action_rules"`
	UpdatedAt        time.Time             `json:"updated_at"`
	UpdatedBy        string                `json:"updated_by"`
}

func toResponse(p Policy) policyResponse {
	rules := p.ActionRules
	if rules == nil {
		rules = map[string]ActionMode{}
	}
	return policyResponse{
		ID:               p.ID,
		SuggestThreshold: p.SuggestThreshold,
		ActionRules:      rules,
		UpdatedAt:        p.UpdatedAt,
		UpdatedBy:        p.UpdatedBy,
	}
}

// Get returns the current remediation policy. Route: GET /api/policy.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p, err := h.svc.Get(r.Context())
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("remediation policy not found"))
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("policy get failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load remediation policy"))
	default:
		writeJSON(r.Context(), w, http.StatusOK, toResponse(p))
	}
}

type updateRequest struct {
	SuggestThreshold int                   `json:"suggest_threshold"`
	ActionRules      map[string]ActionMode `json:"action_rules"`
}

// Update replaces the remediation policy. Route: PUT /api/policy (admin only).
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}

	actor := "unknown"
	if u, ok := auth.UserFromContext(r.Context()); ok && u.Email != "" {
		actor = u.Email
	}

	err := h.svc.Update(r.Context(), Policy{
		SuggestThreshold: req.SuggestThreshold,
		ActionRules:      req.ActionRules,
		UpdatedBy:        actor,
	})
	switch {
	case errors.Is(err, ErrBadThreshold), errors.Is(err, ErrBadMode):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("remediation policy not found"))
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("policy update failed")
		errs.WriteHTTPError(w, errs.Internal("failed to update remediation policy"))
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
