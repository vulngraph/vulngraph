package scan

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Triggerer enqueues a scan run. Implemented by the jobs package so the handler
// stays free of River.
type Triggerer interface {
	EnqueueScan(ctx context.Context) error
}

type Handler struct {
	svc       *Service
	triggerer Triggerer
}

func NewHandler(svc *Service, triggerer Triggerer) *Handler {
	return &Handler{svc: svc, triggerer: triggerer}
}

type runResponse struct {
	ID            string     `json:"id"`
	Status        string     `json:"status"`
	TargetCount   int        `json:"target_count"`
	TargetURLs    []string   `json:"target_urls,omitempty"`
	FindingCount  int        `json:"finding_count"`
	TemplateTags  []string   `json:"template_tags,omitempty"`
	TemplateCount int        `json:"template_count,omitempty"`
	ScannerName   string     `json:"scanner_name,omitempty"`
	Error         string     `json:"error,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

// Trigger enqueues a scan. Admin-only (gated by the router). Returns 204.
func (h *Handler) Trigger(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.StartScan(r.Context(), h.triggerer); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("enqueue scan failed")
		errs.WriteHTTPError(w, errs.Internal("failed to trigger scan"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// List returns recent scan runs.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	runs, err := h.svc.ListRuns(r.Context(), 0)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list scan runs failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list scan runs"))
		return
	}
	out := make([]runResponse, len(runs))
	for i, run := range runs {
		out[i] = toResponse(run)
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

// GetFindings returns findings produced by a specific scan run (time-range query).
func (h *Handler) GetFindings(w http.ResponseWriter, r *http.Request) {
	run, findings, err := h.svc.GetRunFindings(r.Context(), r.PathValue("id"))
	if err != nil {
		errs.WriteHTTPError(w, errs.NotFound("scan run not found"))
		return
	}
	type row struct {
		ID           string `json:"id"`
		Severity     string `json:"severity"`
		Score        uint8  `json:"score"`
		ScoreBand    string `json:"score_band"`
		Title        string `json:"title"`
		ResourceID   string `json:"resource_id"`
		ResourceType string `json:"resource_type"`
		CheckID      string `json:"check_id"`
		DetectedAt   string `json:"detected_at"`
	}
	rows := make([]row, len(findings))
	for i, f := range findings {
		rows[i] = row{
			ID: f.ID, Severity: string(f.Severity), Score: f.Score, ScoreBand: f.ScoreBand,
			Title: f.Title, ResourceID: f.ResourceID, ResourceType: f.ResourceType,
			CheckID: f.CheckID, DetectedAt: f.DetectedAt.Format("2006-01-02T15:04:05Z"),
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"scan_id": run.ID, "findings": rows, "count": len(rows),
	})
}

// Get returns one scan run by ID.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	run, err := h.svc.GetRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("scan run not found"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("get scan run failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load scan run"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toResponse(run))
}

// Cancel marks a running scan's row cancelled; it does not stop the scan
// (see Service.CancelRun). Admin-only.
// Route: DELETE /api/scans/{id}.
func (h *Handler) Cancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.svc.CancelRun(r.Context(), id); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("scan_id", id).Msg("cancel scan failed")
		errs.WriteHTTPError(w, errs.Internal("failed to cancel scan"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func toResponse(r Run) runResponse {
	return runResponse{
		ID: r.ID, Status: string(r.Status), TargetCount: r.TargetCount,
		TargetURLs: r.TargetURLs, FindingCount: r.FindingCount,
		TemplateTags: r.TemplateTags, TemplateCount: r.TemplateCount,
		ScannerName: r.ScannerName,
		Error:       r.Error, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt,
	}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
