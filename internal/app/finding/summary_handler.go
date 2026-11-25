package finding

import (
	"net/http"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type summaryResponse struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByBand     map[string]int `json:"by_band"`
	// Owner/environment facets: "" is the not-yet-resolved bucket, "unowned"
	// the resolved-to-nobody one (see finding.Summary).
	ByOwner       map[string]int `json:"by_owner"`
	ByEnvironment map[string]int `json:"by_environment"`
}

// Summary returns aggregate finding counts for the overview dashboard, optionally
// scoped by ?source=. Route: GET /api/findings/summary.
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	sum, err := h.svc.Summary(r.Context(), Filter{Source: r.URL.Query().Get("source")})
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("finding summary failed")
		errs.WriteHTTPError(w, errs.Internal("failed to summarise findings"))
		return
	}

	resp := summaryResponse{
		Total: sum.Total, BySeverity: map[string]int{}, ByBand: sum.ByBand,
		ByOwner: countsOrEmpty(sum.ByOwner), ByEnvironment: countsOrEmpty(sum.ByEnvironment),
	}
	for sev, n := range sum.BySeverity {
		resp.BySeverity[string(sev)] = n
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

// countsOrEmpty keeps a facet an object on the wire even when nothing was
// counted — the contract declares a map, never null.
func countsOrEmpty(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}
