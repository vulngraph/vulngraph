package kevwatch

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Handler serves the KEV additions feed.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// AdditionsResponse is the wire shape of GET /api/kev/additions.
type AdditionsResponse struct {
	Additions []AdditionResponse `json:"additions"`
}

// AdditionResponse is one `kev.added` record. DateAdded is null when CISA's
// value did not parse.
type AdditionResponse struct {
	CVEID                   string     `json:"cve_id"`
	Name                    string     `json:"name"`
	DateAdded               *time.Time `json:"date_added"`
	OpenFindingsAtDetection int        `json:"open_findings_at_detection"`
	DetectedAt              time.Time  `json:"detected_at"`
}

// Additions handles GET /api/kev/additions?limit=N.
func (h *Handler) Additions(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > MaxListLimit {
			errs.WriteHTTPError(w, errs.InvalidInput("limit must be an integer from 1 to "+strconv.Itoa(MaxListLimit)))
			return
		}
		limit = n
	}
	adds, err := h.svc.Recent(r.Context(), limit)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list kev additions failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list KEV additions"))
		return
	}
	resp := AdditionsResponse{Additions: make([]AdditionResponse, len(adds))}
	for i, a := range adds {
		resp.Additions[i] = AdditionResponse{
			CVEID:                   a.CVEID,
			Name:                    a.Name,
			OpenFindingsAtDetection: a.OpenFindings,
			DetectedAt:              a.DetectedAt,
		}
		if !a.DateAdded.IsZero() {
			d := a.DateAdded
			resp.Additions[i].DateAdded = &d
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
