package identity

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Handler serves the identity census.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Summary returns the identity census. Route: GET /api/identity/summary.
//
// This endpoint exists so the browser stops deriving headline identity numbers
// by arithmetic on /api/assets/summary's by_type counts. Those counts are raw
// asset rows; a person is not a row, "workload identity" is not one asset type,
// and a stale account's rows are not current identities. All three judgements
// need the graph and the principal metadata, so they belong here.
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	c, err := h.svc.Census(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("identity census failed")
		errs.WriteHTTPError(w, errs.Internal("failed to summarize identities"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, c)
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
