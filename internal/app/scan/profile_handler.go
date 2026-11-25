package scan

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ProfileHandler serves the scan profile management API endpoints.
type ProfileHandler struct {
	profileSvc *ProfileService
}

// NewProfileHandler creates a ProfileHandler.
func NewProfileHandler(svc *ProfileService) *ProfileHandler {
	return &ProfileHandler{profileSvc: svc}
}

// profileResponse is the wire shape for a ScanProfile — never exposes the
// domain type directly.
type profileResponse struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	TemplateTags     []string `json:"template_tags,omitempty"`
	TemplateStrategy string   `json:"template_strategy"`
	ScannerType      string   `json:"scanner_type"`
	Schedule         string   `json:"schedule,omitempty"`
	// ScheduleError is set when a stored schedule can never fire (saved
	// before schedules were validated), so the profile is visibly not running.
	ScheduleError string `json:"schedule_error,omitempty"`
	Enabled       bool   `json:"enabled"`
	TargetQuery   string `json:"target_query,omitempty"`
	DriftEnabled  bool   `json:"drift_enabled"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

func toProfileResponse(p ScanProfile) profileResponse {
	var schedErr string
	if err := ScheduleError(p.Schedule); err != nil {
		schedErr = err.Error()
	}
	return profileResponse{
		ID:               p.ID,
		Name:             p.Name,
		Description:      p.Description,
		TemplateTags:     p.TemplateTags,
		TemplateStrategy: string(p.TemplateStrategy),
		ScannerType:      p.ScannerType,
		Schedule:         p.Schedule,
		ScheduleError:    schedErr,
		Enabled:          p.Enabled,
		TargetQuery:      p.TargetQuery,
		DriftEnabled:     p.DriftEnabled,
		CreatedAt:        p.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:        p.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// ListProfiles returns all scan profiles.
// GET /api/scans/profiles
func (h *ProfileHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.profileSvc.ListProfiles(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list scan profiles failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list scan profiles"))
		return
	}
	out := make([]profileResponse, len(profiles))
	for i, p := range profiles {
		out[i] = toProfileResponse(p)
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

// workflowRequest is the shared request body for create and update.
type workflowRequest struct {
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	TemplateTags     []string `json:"template_tags"`
	TemplateStrategy string   `json:"template_strategy"` // "all"|"tags"; "ai_contextual" is rejected
	ScannerType      string   `json:"scanner_type"`      // "nuclei" (default)
	Enabled          bool     `json:"enabled"`
	// Workflow fields
	TargetQuery  string `json:"target_query"`  // Cypher: WHO to scan
	DriftEnabled bool   `json:"drift_enabled"` // WHEN: trigger on asset change
	Schedule     string `json:"schedule"`      // WHEN: cron expression ("" = manual)
}

// CreateProfile creates a new scan workflow profile. Admin-only.
// POST /api/scan-profiles
func (h *ProfileHandler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	var req workflowRequest
	req.Enabled = true // sensible default
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	if req.Name == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("name is required"))
		return
	}
	profile, err := h.profileSvc.CreateProfile(r.Context(),
		req.Name, req.Description, req.TemplateTags, req.Enabled,
		req.TargetQuery, req.DriftEnabled, req.Schedule,
		req.ScannerType, req.TemplateStrategy,
	)
	// An unbounded target query is the caller's mistake, not a server fault:
	// target resolution refuses a result that hit the node budget, so the
	// profile would fail every run — hours later, long after whoever could fix
	// it left the form. Reject now, with the fix in the message.
	if errors.Is(err, ErrUnboundedTargetQuery) || errors.Is(err, ErrInvalidSchedule) || errors.Is(err, ErrStrategyUnavailable) {
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("create scan profile failed")
		errs.WriteHTTPError(w, errs.Internal("failed to create scan profile"))
		return
	}
	writeJSON(r.Context(), w, http.StatusCreated, toProfileResponse(profile))
}

// GetProfile returns a single scan profile by ID.
// GET /api/scans/profiles/{id}
func (h *ProfileHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	profile, err := h.profileSvc.GetProfile(r.Context(), id)
	if errors.Is(err, ErrProfileNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("scan profile not found"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("profile_id", id).Msg("get scan profile failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load scan profile"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toProfileResponse(profile))
}

// UpdateProfile replaces a scan workflow profile's fields. Admin-only.
// PUT /api/scan-profiles/{id}
func (h *ProfileHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req workflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	if req.Name == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("name is required"))
		return
	}
	profile, err := h.profileSvc.UpdateProfile(r.Context(),
		id, req.Name, req.Description, req.TemplateTags, req.Enabled,
		req.TargetQuery, req.DriftEnabled, req.Schedule,
		req.ScannerType, req.TemplateStrategy,
	)
	if errors.Is(err, ErrProfileNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("scan profile not found"))
		return
	}
	if errors.Is(err, ErrUnboundedTargetQuery) || errors.Is(err, ErrInvalidSchedule) || errors.Is(err, ErrStrategyUnavailable) {
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("profile_id", id).Msg("update scan profile failed")
		errs.WriteHTTPError(w, errs.Internal("failed to update scan profile"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, toProfileResponse(profile))
}

// DeleteProfile removes a scan profile. Admin-only (gated by the router).
// DELETE /api/scans/profiles/{id}
func (h *ProfileHandler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.profileSvc.DeleteProfile(r.Context(), id); err != nil {
		if errors.Is(err, ErrProfileNotFound) {
			errs.WriteHTTPError(w, errs.NotFound("scan profile not found"))
			return
		}
		log.FromContext(r.Context()).Error().Err(err).Str("profile_id", id).Msg("delete scan profile failed")
		errs.WriteHTTPError(w, errs.Internal("failed to delete scan profile"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// WorkflowPresets returns the catalog of pre-built target and trigger presets
// for the workflow builder UI. No auth required — purely static data.
// GET /api/workflows/presets
func WorkflowPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"targets":  TargetPresets,
		"triggers": TriggerPresets,
	})
}

// TriggerProfileScan enqueues a scan run scoped to a specific profile. Admin-only.
// POST /api/scan-profiles/{id}/trigger
func (h *ProfileHandler) TriggerProfileScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	runID, err := h.profileSvc.StartProfileScan(r.Context(), id)
	if errors.Is(err, ErrProfileNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("scan profile not found"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("profile_id", id).Msg("trigger profile scan failed")
		errs.WriteHTTPError(w, errs.Internal("failed to trigger scan for profile"))
		return
	}
	writeJSON(r.Context(), w, http.StatusAccepted, map[string]string{"run_id": runID})
}
