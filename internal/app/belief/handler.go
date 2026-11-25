package belief

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("belief: write response failed")
	}
}

// Handler is the read transport for beliefs.
type Handler struct{ svc *Service }

// NewHandler wires the belief service to HTTP.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// beliefResponse shapes the wire output. Evidence is reused directly — it is a
// clean value type whose json tags already match the contract (no internal
// fields to hide).
type beliefResponse struct {
	FindingID  string     `json:"finding_id"`
	ResourceID string     `json:"resource_id"`
	Claim      string     `json:"claim"`
	Severity   string     `json:"severity"`
	Confidence string     `json:"confidence"`
	Status     string     `json:"status"`
	Provenance string     `json:"provenance"`
	Evidence   []Evidence `json:"evidence"`
}

// Get returns the current belief for a finding: GET /api/beliefs/{finding_id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("finding_id")
	b, err := h.svc.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("no belief for finding"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("finding_id", id).Msg("belief get failed")
		errs.WriteHTTPError(w, errs.Internal("failed to read belief"))
		return
	}
	// Dedup on read too, not only at write time, so the response never renders
	// paraphrased-duplicate evidence bullets whatever the stored row holds.
	// Writers must carry real per-instance Fact values (see dedupeEvidence), or
	// two genuinely different pieces of evidence collide here and one silently
	// disappears from the response.
	ev := dedupeEvidence(b.Evidence)
	if ev == nil {
		ev = []Evidence{}
	}
	writeJSON(r.Context(), w, http.StatusOK, beliefResponse{
		FindingID: b.FindingID, ResourceID: b.ResourceID, Claim: b.Claim,
		Severity: string(b.Severity), Confidence: b.Confidence, Status: b.Status,
		Provenance: b.Provenance, Evidence: ev,
	})
}
