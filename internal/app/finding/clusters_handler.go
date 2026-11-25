package finding

import (
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type clusterResponse struct {
	CheckID        string    `json:"check_id"`
	Title          string    `json:"title"`
	Severity       string    `json:"severity"`
	Source         string    `json:"source"`
	Remediation    string    `json:"remediation,omitempty"`
	MaxScore       uint8     `json:"max_score"`
	WorstBand      string    `json:"worst_band,omitempty"`
	Instances      int       `json:"instances"`
	Resources      int       `json:"resources"`
	KnownExploited bool      `json:"known_exploited"`
	LastDetected   time.Time `json:"last_detected"`
}

// Clusters returns findings grouped by check (the triage view), worst-score
// first, optionally scoped by ?source=. Route: GET /api/findings/clusters.
func (h *Handler) Clusters(w http.ResponseWriter, r *http.Request) {
	clusters, totalChecks, err := h.svc.Clusters(r.Context(), Filter{Source: r.URL.Query().Get("source")})
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("finding clusters failed")
		errs.WriteHTTPError(w, errs.Internal("failed to cluster findings"))
		return
	}

	out := make([]clusterResponse, len(clusters))
	for i, c := range clusters {
		out[i] = clusterResponse{
			CheckID: c.CheckID, Title: c.Title, Severity: string(c.Severity), Source: c.Source,
			Remediation: c.Remediation,
			MaxScore:    c.MaxScore, WorstBand: c.WorstBand, Instances: c.Instances,
			Resources: c.Resources, KnownExploited: c.KnownExploited, LastDetected: c.LastDetected,
		}
	}
	// total_checks is the true cluster population before the server-side LIMIT —
	// the UI must disclose truncation rather than present len(items) as a total.
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"items":        out,
		"total_checks": totalChecks,
		"truncated":    totalChecks > len(out),
	})
}
