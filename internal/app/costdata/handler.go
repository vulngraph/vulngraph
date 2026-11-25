package costdata

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Svc is the service interface the Handler depends on.
type Svc interface {
	GetSnapshots(ctx context.Context, connectorID string, days int) ([]CostSnapshot, error)
	GetAnomalies(ctx context.Context, connectorID string) ([]CostAnomaly, error)
	Statuses(ctx context.Context) ([]CollectStatus, error)
}

// Handler serves cost data endpoints.
type Handler struct {
	svc Svc
}

func NewHandler(svc Svc) *Handler { return &Handler{svc: svc} }

// snapshotResponse is the wire shape of a single cost snapshot.
type snapshotResponse struct {
	ConnectorID string  `json:"connector_id"`
	AccountID   string  `json:"account_id"`
	Service     string  `json:"service"`
	CostUSD     float64 `json:"cost_usd"`
	PeriodDate  string  `json:"period_date"`
}

// anomalyResponse is the wire shape of a detected cost anomaly.
type anomalyResponse struct {
	ConnectorID   string  `json:"connector_id"`
	Service       string  `json:"service"`
	LatestCostUSD float64 `json:"latest_cost_usd"`
	RollingAvgUSD float64 `json:"rolling_avg_usd"`
	DeltaUSD      float64 `json:"delta_usd"`
	PeriodDate    string  `json:"period_date"`
}

// Snapshots handles GET /api/cost/snapshots?connector_id=X[&days=N].
func (h *Handler) Snapshots(w http.ResponseWriter, r *http.Request) {
	connectorID := r.URL.Query().Get("connector_id")
	if connectorID == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("connector_id is required"))
		return
	}

	days := 30
	if raw := r.URL.Query().Get("days"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > 365 {
			errs.WriteHTTPError(w, errs.InvalidInput("days must be between 1 and 365"))
			return
		}
		days = n
	}

	snaps, err := h.svc.GetSnapshots(r.Context(), connectorID, days)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("connector_id", connectorID).Msg("list cost snapshots failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list cost snapshots"))
		return
	}

	out := make([]snapshotResponse, len(snaps))
	for i, s := range snaps {
		out[i] = snapshotResponse{
			ConnectorID: s.ConnectorID,
			AccountID:   s.AccountID,
			Service:     s.Service,
			CostUSD:     s.CostUSD,
			PeriodDate:  s.PeriodDate.Format(time.DateOnly),
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"items": out})
}

// Anomalies handles GET /api/cost/anomalies?connector_id=X.
func (h *Handler) Anomalies(w http.ResponseWriter, r *http.Request) {
	connectorID := r.URL.Query().Get("connector_id")
	if connectorID == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("connector_id is required"))
		return
	}

	anomalies, err := h.svc.GetAnomalies(r.Context(), connectorID)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("connector_id", connectorID).Msg("detect cost anomalies failed")
		errs.WriteHTTPError(w, errs.Internal("failed to detect cost anomalies"))
		return
	}

	out := make([]anomalyResponse, len(anomalies))
	for i, a := range anomalies {
		out[i] = anomalyResponse{
			ConnectorID:   a.ConnectorID,
			Service:       a.Service,
			LatestCostUSD: a.LatestCostUSD,
			RollingAvgUSD: a.RollingAvgUSD,
			DeltaUSD:      a.DeltaUSD,
			PeriodDate:    a.PeriodDate.Format(time.DateOnly),
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"items": out})
}

// collectStatusResponse is the wire shape of one connector's collection state.
type collectStatusResponse struct {
	ConnectorID     string `json:"connector_id"`
	AccountID       string `json:"account_id,omitempty"`
	Outcome         string `json:"outcome"`
	Detail          string `json:"detail,omitempty"`
	AttemptAt       string `json:"attempt_at,omitempty"`
	SnapshotsStored int    `json:"snapshots_stored"`
	LastCollectedAt string `json:"last_collected_at,omitempty"`
}

// costStatusResponse tells a client WHY the cost panels are empty. Without it,
// "no anomalies" was the rendering of a permission denial, a config skip, and a
// genuine zero alike.
type costStatusResponse struct {
	Connectors            []collectStatusResponse `json:"connectors"`
	SnapshotsTotal        int                     `json:"snapshots_total"`
	Collected             bool                    `json:"collected"`
	RequiredIAMPermission string                  `json:"required_iam_permission"`
}

// Status handles GET /api/cost/status: per-connector collection outcomes plus the
// IAM permission collection needs, so an operator sees the cause instead of an
// empty list.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	statuses, err := h.svc.Statuses(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("cost collection status failed")
		errs.WriteHTTPError(w, errs.Internal("failed to read cost collection status"))
		return
	}

	resp := costStatusResponse{
		Connectors:            make([]collectStatusResponse, len(statuses)),
		RequiredIAMPermission: RequiredIAMPermission,
	}
	for i, s := range statuses {
		resp.SnapshotsTotal += s.SnapshotsStored
		row := collectStatusResponse{
			ConnectorID:     s.ConnectorID,
			AccountID:       s.AccountID,
			Outcome:         s.Outcome,
			Detail:          s.Detail,
			SnapshotsStored: s.SnapshotsStored,
		}
		if !s.AttemptAt.IsZero() {
			row.AttemptAt = s.AttemptAt.UTC().Format(time.RFC3339)
		}
		if !s.LastCollectedAt.IsZero() {
			row.LastCollectedAt = s.LastCollectedAt.UTC().Format(time.RFC3339)
		}
		resp.Connectors[i] = row
	}
	resp.Collected = resp.SnapshotsTotal > 0
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
