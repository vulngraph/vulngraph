package driftanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// maxSince is the longest lookback a caller may ask for: batches are pruned
// after the retention period, so a longer window finds nothing more.
const maxSince = retention

// Reader is what the handler needs from the service.
type Reader interface {
	List(ctx context.Context, p ListParams) (Listing, error)
	Get(ctx context.Context, batchID string) (Batch, error)
}

// Handler serves the drift analysis read API. There is no write route: the
// verdict is advisory and nothing here starts a scan.
type Handler struct {
	svc Reader
	now func() time.Time
}

func NewHandler(svc Reader) *Handler { return &Handler{svc: svc, now: time.Now} }

// ListResponse is the wire shape of GET /api/drift/analyses. Enabled false
// means no analysis runs, which is not a verdict.
type ListResponse struct {
	Enabled  bool               `json:"enabled"`
	Analyses []AnalysisResponse `json:"analyses"`
}

// AnalysisResponse is the wire shape of one batch. HTTP and MCP share it.
// ScanRecommendation is recommended, not_needed or unknown; unknown is never
// "no scan needed".
type AnalysisResponse struct {
	BatchID               string             `json:"batch_id"`
	ConnectorID           string             `json:"connector_id"`
	WindowStart           time.Time          `json:"window_start"`
	WindowEnd             time.Time          `json:"window_end"`
	Status                string             `json:"status"`
	UnknownReason         string             `json:"unknown_reason"`
	Summary               string             `json:"summary"`
	Changes               []ChangeResponse   `json:"changes"`
	ExposureJudgement     string             `json:"exposure_judgement"`
	ScanRecommendation    string             `json:"scan_recommendation"`
	Reason                string             `json:"reason"`
	SuggestedProfileID    string             `json:"suggested_profile_id"`
	SuggestedTemplateTags []string           `json:"suggested_template_tags"`
	Confidence            string             `json:"confidence"`
	Evidence              []EvidenceResponse `json:"evidence"`
	AutoScanProfileIDs    []string           `json:"auto_scan_profile_ids"`
	Truncated             bool               `json:"truncated"`
	Source                string             `json:"source"`
	Advisory              bool               `json:"advisory"`
}

type ChangeResponse struct {
	Kind    string `json:"kind"`
	AssetID string `json:"asset_id"`
	Note    string `json:"note"`
}

type EvidenceResponse struct {
	Source string `json:"source"`
	Ref    string `json:"ref"`
	Fact   string `json:"fact"`
}

// ToResponse maps a batch to its wire shape. Without a verdict the
// recommendation is unknown.
func ToResponse(b Batch) AnalysisResponse {
	v := b.Verdict
	out := AnalysisResponse{
		BatchID: b.ID, ConnectorID: b.ConnectorID,
		WindowStart: b.WindowStart, WindowEnd: b.WindowEnd,
		Status: b.Status, UnknownReason: b.UnknownReason,
		Summary: v.Summary, ExposureJudgement: v.ExposureJudgement,
		ScanRecommendation: v.Recommendation(), Reason: v.Reason,
		SuggestedProfileID: v.SuggestedProfileID, Confidence: v.Confidence,
		SuggestedTemplateTags: nonNil(v.SuggestedTemplateTags),
		AutoScanProfileIDs:    nonNil(v.AutoScanProfileIDs),
		Changes:               make([]ChangeResponse, len(v.Changes)),
		Evidence:              make([]EvidenceResponse, len(v.Evidence)),
		Truncated:             b.Truncated, Source: "llm", Advisory: true,
	}
	for i, c := range v.Changes {
		out.Changes[i] = ChangeResponse(c)
	}
	for i, e := range v.Evidence {
		out.Evidence[i] = EvidenceResponse(e)
	}
	return out
}

// ToListResponse maps a listing to its wire shape.
func ToListResponse(l Listing) ListResponse {
	out := ListResponse{Enabled: l.Enabled, Analyses: make([]AnalysisResponse, len(l.Analyses))}
	for i, b := range l.Analyses {
		out.Analyses[i] = ToResponse(b)
	}
	return out
}

// List handles GET /api/drift/analyses?since=720h&limit=50.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	var p ListParams
	if raw := r.URL.Query().Get("since"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 || d > maxSince {
			errs.WriteHTTPError(w, errs.InvalidInput("since must be a positive Go duration up to 2160h, e.g. 24h (there is no d unit)"))
			return
		}
		p.Since = h.now().Add(-d)
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxListLimit {
			errs.WriteHTTPError(w, errs.InvalidInput("limit must be an integer from 1 to "+strconv.Itoa(maxListLimit)))
			return
		}
		p.Limit = n
	}
	listing, err := h.svc.List(r.Context(), p)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("list drift analyses failed")
		errs.WriteHTTPError(w, errs.Internal("failed to list drift analyses"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, ToListResponse(listing))
}

// Get handles GET /api/drift/analyses/{batch_id}.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("batch_id")
	b, err := h.svc.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		errs.WriteHTTPError(w, errs.NotFound("drift analysis not found"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("batch_id", id).Msg("get drift analysis failed")
		errs.WriteHTTPError(w, errs.Internal("failed to load drift analysis"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, ToResponse(b))
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
