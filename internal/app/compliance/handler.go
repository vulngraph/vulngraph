package compliance

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Get returns CIS coverage. Route: GET /api/compliance.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	cov, err := h.svc.Compute(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("compute compliance failed")
		errs.WriteHTTPError(w, errs.Internal("failed to compute compliance"))
		return
	}
	writeJSON(w, r, coverageResponse(cov))
}

// ControlResponse is one control and the checks that evidence it.
type ControlResponse struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	CheckIDs   []string `json:"check_ids"`
	Frameworks []string `json:"frameworks"`
}

// ControlStatusResponse is one control's coverage state.
type ControlStatusResponse struct {
	Control ControlResponse `json:"control"`
	State   string          `json:"state"`
	Passing bool            `json:"passing"`
}

// FrameworkCoverageResponse is the per-state rollup for one framework.
type FrameworkCoverageResponse struct {
	Framework   string `json:"framework"`
	Total       int    `json:"total"`
	Passing     int    `json:"passing"`
	Failing     int    `json:"failing"`
	Partial     int    `json:"partial"`
	NotAssessed int    `json:"not_assessed"`
}

// CoverageResponse is the overall control coverage summary.
type CoverageResponse struct {
	Total       int                         `json:"total"`
	Passing     int                         `json:"passing"`
	Failing     int                         `json:"failing"`
	Partial     int                         `json:"partial"`
	NotAssessed int                         `json:"not_assessed"`
	Controls    []ControlStatusResponse     `json:"controls"`
	Frameworks  []FrameworkCoverageResponse `json:"frameworks"`
}

func coverageResponse(c Coverage) CoverageResponse {
	resp := CoverageResponse{
		Total: c.Total, Passing: c.Passing, Failing: c.Failing, Partial: c.Partial, NotAssessed: c.NotAssessed,
		Controls:   make([]ControlStatusResponse, 0, len(c.Controls)),
		Frameworks: make([]FrameworkCoverageResponse, 0, len(c.Frameworks)),
	}
	for _, st := range c.Controls {
		resp.Controls = append(resp.Controls, ControlStatusResponse{
			Control: ControlResponse{ID: st.Control.ID, Title: st.Control.Title,
				CheckIDs: orEmpty(st.Control.CheckIDs), Frameworks: orEmpty(st.Control.Frameworks)},
			State: st.State, Passing: st.Passing,
		})
	}
	for _, f := range c.Frameworks {
		resp.Frameworks = append(resp.Frameworks, FrameworkCoverageResponse(f))
	}
	return resp
}

// FrameworkSummaryResponse is one framework's requirement counts.
type FrameworkSummaryResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
	Total   int    `json:"total"`
	Passing int    `json:"passing"`
	Failing int    `json:"failing"`
	Unknown int    `json:"unknown"`
	Manual  int    `json:"manual"`
}

// FrameworkListResponse lists every requirement-level framework.
type FrameworkListResponse struct {
	Frameworks []FrameworkSummaryResponse `json:"frameworks"`
}

// RequirementResponse is one requirement's live state and its evidence.
type RequirementResponse struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	State             string   `json:"state"`
	Controls          []string `json:"controls"`
	CheckIDs          []string `json:"check_ids"`
	FailingChecks     []string `json:"failing_checks"`
	UnevaluatedChecks []string `json:"unevaluated_checks"`
	Gaps              []string `json:"gaps"`
	OutOfScope        []string `json:"out_of_scope"`
	// UnjoinedSourceChecks: source mappings with no Vulngraph control (a partial
	// mapping; never passing). PartialMapping words it for people.
	UnjoinedSourceChecks int    `json:"unjoined_source_checks"`
	PartialMapping       string `json:"partial_mapping"`
	// EvidenceGaps: in-scope controls whose cloud cannot vouch for its
	// inventory. EvidenceAsOf: oldest last successful sync behind the
	// requirement, null when unknown.
	EvidenceGaps []string   `json:"evidence_gaps"`
	EvidenceAsOf *time.Time `json:"evidence_as_of"`
}

// CloudResponse is one provider's evidence health.
type CloudResponse struct {
	Provider     string     `json:"provider"`
	Connectors   int        `json:"connectors"`
	HasInventory bool       `json:"has_inventory"`
	EvidenceAsOf *time.Time `json:"evidence_as_of"`
	Stale        bool       `json:"stale"`
}

// FrameworkResponse is one framework with every requirement.
type FrameworkResponse struct {
	FrameworkSummaryResponse
	Clouds       []CloudResponse       `json:"clouds"`
	Requirements []RequirementResponse `json:"requirements"`
}

// timeOrNil maps the unknown (zero) time to null, never 0001-01-01.
func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func summaryResponse(s FrameworkSummary) FrameworkSummaryResponse {
	return FrameworkSummaryResponse(s)
}

// orEmpty keeps a JSON list a list: the contract types these as arrays.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ListFrameworks returns each framework's summary. Route:
// GET /api/compliance/frameworks.
func (h *Handler) ListFrameworks(w http.ResponseWriter, r *http.Request) {
	fws, err := h.svc.Frameworks(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("compute compliance frameworks failed")
		errs.WriteHTTPError(w, errs.Internal("failed to compute compliance frameworks"))
		return
	}
	resp := FrameworkListResponse{Frameworks: make([]FrameworkSummaryResponse, 0, len(fws))}
	for _, f := range fws {
		resp.Frameworks = append(resp.Frameworks, summaryResponse(f))
	}
	writeJSON(w, r, resp)
}

// GetFramework returns one framework's requirement-level status. Route:
// GET /api/compliance/frameworks/{id}.
func (h *Handler) GetFramework(w http.ResponseWriter, r *http.Request) {
	fs, err := h.svc.Framework(r.Context(), r.PathValue("id"))
	if err != nil {
		writeFrameworkError(w, r, err)
		return
	}
	resp := FrameworkResponse{FrameworkSummaryResponse: summaryResponse(fs.FrameworkSummary),
		Clouds:       make([]CloudResponse, 0, len(fs.Clouds)),
		Requirements: make([]RequirementResponse, 0, len(fs.Requirements))}
	for _, c := range fs.Clouds {
		resp.Clouds = append(resp.Clouds, CloudResponse{Provider: c.Provider, Connectors: c.Connectors,
			HasInventory: c.HasInventory, EvidenceAsOf: timeOrNil(c.EvidenceAsOf), Stale: c.Stale})
	}
	for _, q := range fs.Requirements {
		resp.Requirements = append(resp.Requirements, RequirementResponse{
			ID: q.ID, Title: q.Title, State: q.State, Controls: orEmpty(q.Controls), CheckIDs: orEmpty(q.CheckIDs),
			FailingChecks: orEmpty(q.FailingChecks), UnevaluatedChecks: orEmpty(q.UnevaluatedChecks),
			Gaps: orEmpty(q.Gaps), OutOfScope: orEmpty(q.OutOfScope),
			UnjoinedSourceChecks: q.UnjoinedSourceChecks, PartialMapping: partialMapping(q.UnjoinedSourceChecks),
			EvidenceGaps: orEmpty(q.EvidenceGaps), EvidenceAsOf: timeOrNil(q.EvidenceAsOf),
		})
	}
	writeJSON(w, r, resp)
}

// exportHeader is the auditor CSV's columns.
var exportHeader = []string{"framework", "framework_version", "requirement", "title", "status",
	"mapped_controls", "mapped_checks", "failing_checks", "unevaluated_checks", "gaps", "partial_mapping", "evidence_gaps", "evidence_as_of", "failing_resources"}

// ExportFramework writes one framework as CSV for auditors: per requirement,
// its status, mapped controls and checks, and how many distinct resources fail
// it. Route: GET /api/compliance/frameworks/{id}/export (analyst and above).
func (h *Handler) ExportFramework(w http.ResponseWriter, r *http.Request) {
	fs, err := h.svc.ExportFramework(r.Context(), r.PathValue("id"))
	if err != nil {
		writeFrameworkError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fs.ID+`-requirements.csv"`)
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	rows := [][]string{exportHeader}
	for _, q := range fs.Requirements {
		rows = append(rows, []string{fs.Name, fs.Version, q.ID, q.Title, q.State,
			join(q.Controls), join(q.CheckIDs), join(q.FailingChecks), join(q.UnevaluatedChecks), join(q.Gaps), partialMapping(q.UnjoinedSourceChecks),
			join(q.EvidenceGaps), asOfCell(q.EvidenceAsOf), resourcesCell(q)})
	}
	for _, row := range rows {
		for i := range row {
			row[i] = csvSafe(row[i])
		}
	}
	if err := cw.WriteAll(rows); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("write compliance export failed")
	}
}

func join(s []string) string { return strings.Join(s, "; ") }

func asOfCell(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

// resourcesCell is "n/a" when a failing check's findings name no resource:
// a zero there would read as "fails on nothing".
func resourcesCell(q RequirementStatus) string {
	if !q.FailingResourcesKnown {
		return "n/a"
	}
	return strconv.Itoa(q.FailingResources)
}

// partialMapping words an unjoined count for people ("" when the mapping is
// complete).
func partialMapping(unjoined int) string {
	if unjoined == 0 {
		return ""
	}
	noun := "checks"
	if unjoined == 1 {
		noun = "check"
	}
	return fmt.Sprintf("partial mapping: %d source %s without a graph control", unjoined, noun)
}

// csvSafe defuses spreadsheet formula injection: a cell a spreadsheet would
// evaluate (leading = + - @, tab or CR) is prefixed with an apostrophe.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func writeFrameworkError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrFrameworkNotFound):
		errs.WriteHTTPError(w, errs.NotFound("compliance framework not found"))
	default:
		log.FromContext(r.Context()).Error().Err(err).Msg("compute compliance framework failed")
		errs.WriteHTTPError(w, errs.Internal("failed to compute compliance framework"))
	}
}

func writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("write response failed")
	}
}
