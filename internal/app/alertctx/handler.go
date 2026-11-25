package alertctx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Contexter assembles alert context. *Service implements it.
type Contexter interface {
	Context(ctx context.Context, identifiers []string) (Result, error)
}

type Handler struct {
	svc Contexter
}

func NewHandler(svc Contexter) *Handler { return &Handler{svc: svc} }

type request struct {
	Identifiers []string `json:"identifiers"`
}

// Context serves POST /api/context/alert. Read-only: POST only because the
// identifiers (ARNs, URLs) are awkward in a query string and the list is
// multi-valued.
func (h *Handler) Context(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON with an identifiers array"))
		return
	}
	res, err := h.svc.Context(r.Context(), req.Identifiers)
	switch {
	case errors.Is(err, ErrNoIdentifiers), errors.Is(err, ErrTooManyIDs):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("alert context failed")
		errs.WriteHTTPError(w, errs.Internal("failed to assemble alert context"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(ToResponse(res)); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("write response failed")
	}
}
