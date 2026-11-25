package savedquery

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

// Handler exposes saved-query CRUD + run + history over HTTP.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		errs.WriteHTTPErrorCtx(ctx, w, "encode response", http.StatusInternalServerError)
	}
}

type queryResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Cypher      string `json:"cypher"`
	CreatedBy   string `json:"created_by,omitempty"`
	Schedule    string `json:"schedule"`
	// ScheduleError is set when a stored schedule can never fire (saved before
	// schedules were validated), so the detection is visibly not running.
	ScheduleError   string   `json:"schedule_error,omitempty"`
	AlertChannelIDs []string `json:"alert_channel_ids"`
	AlertOnChange   bool     `json:"alert_on_change"`
	AlertSeverity   string   `json:"alert_severity"`
	Enabled         bool     `json:"enabled"`
	// LastRunAt/LastResultCount are the change-detection baseline: they move
	// only on a good scheduled run.
	LastRunAt       string `json:"last_run_at,omitempty"`
	LastResultCount int    `json:"last_result_count"`
	// LastAttempt* describe the newest run of any outcome — absent when the
	// query has never run.
	LastAttemptAt      string `json:"last_attempt_at,omitempty"`
	LastAttemptStatus  string `json:"last_attempt_status,omitempty"`
	LastAttemptError   string `json:"last_attempt_error,omitempty"`
	LastAttemptTrigger string `json:"last_attempt_trigger,omitempty"`
}

func toResponse(q SavedQuery) queryResponse {
	ids := q.AlertChannelIDs
	if ids == nil {
		ids = []string{}
	}
	var last string
	if q.LastRunAt != nil {
		last = q.LastRunAt.Format("2006-01-02T15:04:05Z")
	}
	var schedErr string
	if err := ScheduleError(q.Schedule); err != nil {
		schedErr = err.Error()
	}
	out := queryResponse{
		ID: q.ID, Name: q.Name, Description: q.Description, Cypher: q.Cypher,
		CreatedBy: q.CreatedBy, Schedule: q.Schedule, ScheduleError: schedErr, AlertChannelIDs: ids,
		AlertOnChange: q.AlertOnChange, AlertSeverity: q.AlertSeverity, Enabled: q.Enabled, LastRunAt: last,
		LastResultCount: q.LastResultCount,
	}
	if a := q.LastAttempt; a != nil {
		out.LastAttemptAt = a.RanAt.UTC().Format(time.RFC3339)
		out.LastAttemptStatus = a.Status()
		out.LastAttemptError = a.Error
		out.LastAttemptTrigger = a.Trigger
	}
	return out
}

type queryRequest struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Cypher          string   `json:"cypher"`
	Schedule        string   `json:"schedule"`
	AlertChannelIDs []string `json:"alert_channel_ids"`
	AlertOnChange   bool     `json:"alert_on_change"`
	AlertSeverity   string   `json:"alert_severity"`
	Enabled         bool     `json:"enabled"`
}

func (req queryRequest) toQuery() SavedQuery {
	return SavedQuery{
		Name: req.Name, Description: req.Description, Cypher: req.Cypher,
		Schedule: req.Schedule, AlertChannelIDs: req.AlertChannelIDs,
		AlertOnChange: req.AlertOnChange, AlertSeverity: req.AlertSeverity, Enabled: req.Enabled,
	}
}

// GET /api/saved-queries
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	qs, err := h.svc.List(r.Context())
	if err != nil {
		errs.WriteHTTPError(w, errs.Internal("list saved queries failed"))
		return
	}
	out := make([]queryResponse, len(qs))
	for i, q := range qs {
		out[i] = toResponse(q)
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"queries": out})
}

// POST /api/saved-queries
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req queryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid JSON"))
		return
	}
	q := req.toQuery()
	if u, ok := auth.UserFromContext(r.Context()); ok {
		q.CreatedBy = u.Email
	}
	created, err := h.svc.Create(r.Context(), q)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusCreated, toResponse(created))
}

// PUT /api/saved-queries/{id}
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var req queryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid JSON"))
		return
	}
	q := req.toQuery()
	q.ID = r.PathValue("id")
	updated, err := h.svc.Update(r.Context(), q)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toResponse(updated))
}

// DELETE /api/saved-queries/{id}
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.Delete(r.Context(), r.PathValue("id")); err != nil {
		h.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/saved-queries/{id}/run — execute now (manual trigger).
func (h *Handler) Run(w http.ResponseWriter, r *http.Request) {
	q, err := h.svc.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	run, err := h.svc.Run(r.Context(), q, TriggerManual)
	if errors.Is(err, ErrResultTruncated) {
		// The query ran; its result is just partial. Report the counts with the
		// truncation in the error field rather than presenting them as complete.
		writeJSON(r.Context(), w, http.StatusOK, map[string]any{
			"node_count": run.NodeCount, "edge_count": run.EdgeCount, "error": run.Error,
		})
		return
	}
	if err != nil {
		// Don't echo the raw backend error to the client (it can leak query
		// internals / engine detail); log it and return a static message.
		log.FromContext(r.Context()).Error().Err(err).Str("id", q.ID).Msg("saved query run failed")
		errs.WriteHTTPError(w, errs.Internal("failed to run saved query"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"node_count": run.NodeCount, "edge_count": run.EdgeCount, "error": run.Error,
	})
}

// GET /api/saved-queries/{id}/runs — run history.
func (h *Handler) Runs(w http.ResponseWriter, r *http.Request) {
	runs, err := h.svc.ListRuns(r.Context(), r.PathValue("id"), 50)
	if err != nil {
		errs.WriteHTTPError(w, errs.Internal("list runs failed"))
		return
	}
	type runResp struct {
		RanAt     string `json:"ran_at"`
		NodeCount int    `json:"node_count"`
		EdgeCount int    `json:"edge_count"`
		Trigger   string `json:"trigger"`
		Error     string `json:"error,omitempty"`
	}
	out := make([]runResp, len(runs))
	for i, run := range runs {
		out[i] = runResp{
			RanAt: run.RanAt.Format("2006-01-02T15:04:05Z"), NodeCount: run.NodeCount,
			EdgeCount: run.EdgeCount, Trigger: run.Trigger, Error: run.Error,
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"runs": out})
}

func (h *Handler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("saved query not found"))
	case errors.Is(err, ErrMissingName):
		errs.WriteHTTPError(w, errs.InvalidInput("name is required"))
	case errors.Is(err, ErrEmptyCypher):
		errs.WriteHTTPError(w, errs.InvalidInput("cypher is required"))
	case errors.Is(err, ErrWriteQuery):
		errs.WriteHTTPError(w, errs.InvalidInput("query must be read-only Cypher"))
	case errors.Is(err, ErrInvalidSchedule):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
	case errors.Is(err, ErrInvalidSeverity):
		errs.WriteHTTPError(w, errs.InvalidInput("alert_severity must be critical, high, medium, low or info"))
	default:
		errs.WriteHTTPError(w, errs.Internal("saved query operation failed"))
	}
}
