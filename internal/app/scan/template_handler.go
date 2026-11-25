package scan

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
	"github.com/vulngraph/vulngraph/pkg/sse"
)

// TemplateValidator lints a nuclei YAML template without executing it.
// *nuclei adapter satisfies this — defined here to avoid import cycles. ctx is
// the request's: a client that goes away cancels the engine build.
type TemplateValidator interface {
	Validate(ctx context.Context, yamlContent string) TemplateValidation
}

// TemplateTester runs a nuclei template against one URL.
type TemplateTester interface {
	Test(ctx context.Context, yamlContent, targetURL string) ([]Result, error)
}

// TemplateAIGenerator generates nuclei templates from natural-language descriptions.
// Attempts is the number of LLM calls made — >1 means the model self-corrected.
type TemplateAIGenerator interface {
	Generate(ctx context.Context, description string) (yaml string, v TemplateValidation, attempts int, err error)
}

// TemplateHandler serves the template editor API endpoints.
type TemplateHandler struct {
	validator TemplateValidator
	tester    TemplateTester
	generator TemplateAIGenerator // nil when no LLM provider is configured
	// allowInternal permits test targets on private/loopback addresses (never
	// link-local or cloud metadata); see AllowInternalTargetsEnv.
	allowInternal bool
}

// NewTemplateHandler creates a handler. generator may be nil.
func NewTemplateHandler(v TemplateValidator, t TemplateTester, g TemplateAIGenerator) *TemplateHandler {
	return &TemplateHandler{validator: v, tester: t, generator: g, allowInternal: AllowInternalTargets()}
}

// Validate lints a nuclei YAML template without executing it.
// POST /api/scans/templates/validate  {"yaml": "..."}
func (h *TemplateHandler) Validate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.YAML == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("yaml field is required"))
		return
	}
	result := h.validator.Validate(r.Context(), req.YAML)
	writeJSON(r.Context(), w, http.StatusOK, result)
}

const testTimeout = 5 * time.Minute

// Test runs a nuclei template against one URL.
// POST /api/scans/templates/test  {"yaml": "...", "target": "https://..."}
func (h *TemplateHandler) Test(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML   string `json:"yaml"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("invalid request body"))
		return
	}
	if req.YAML == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("yaml field is required"))
		return
	}
	if req.Target == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("target field is required"))
		return
	}
	target, err := url.Parse(req.Target)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("target must be an http or https URL"))
		return
	}
	// Pre-check for a clear 400; the tester enforces the same policy at dial time.
	if !h.allowInternal {
		if err := safenet.CheckPublicHost(r.Context(), target.Hostname()); err != nil {
			msg := "target host could not be resolved"
			if errors.Is(err, safenet.ErrPrivateAddress) {
				msg = "target resolves to a private, loopback or link-local address; set " +
					AllowInternalTargetsEnv + "=true to allow scanning internal ranges"
			}
			errs.WriteHTTPError(w, errs.InvalidInput(msg))
			return
		}
	}
	// Link-local and cloud metadata stay refused even with internal targets allowed.
	if err := checkTargetHost(r.Context(), target.Hostname(), true); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("target is link-local or a cloud metadata endpoint, which is never scanned"))
		return
	}

	// Validate before executing so errors surface immediately.
	v := h.validator.Validate(r.Context(), req.YAML)
	if !v.Valid {
		writeJSON(r.Context(), w, http.StatusUnprocessableEntity, map[string]any{
			"error":  "template validation failed",
			"errors": v.Errors,
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), testTimeout)
	defer cancel()
	// Lift the server's 60s WriteTimeout so the response can still be written
	// when a test runs long. The request context remains capped by the
	// server's per-request deadline unless this route is exempted from it.
	sse.ExtendWriteDeadline(ctx, w, testTimeout+15*time.Second)

	results, err := h.tester.Test(ctx, req.YAML, req.Target)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("template test failed")
		errs.WriteHTTPError(w, errs.Internal("template test execution failed"))
		return
	}

	type testResult struct {
		TemplateID string `json:"template_id"`
		Name       string `json:"name"`
		Severity   string `json:"severity"`
		MatchedURL string `json:"matched_url,omitempty"`
	}
	out := make([]testResult, len(results))
	for i, res := range results {
		out[i] = testResult{
			TemplateID: res.TemplateID, Name: res.Name,
			Severity: res.Severity, MatchedURL: res.MatchedURL,
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"results": out, "count": len(out), "target": req.Target,
	})
}

// Generate uses AI to produce a nuclei template from a description.
// POST /api/scans/templates/generate  {"description": "..."}
func (h *TemplateHandler) Generate(w http.ResponseWriter, r *http.Request) {
	if h.generator == nil {
		errs.WriteHTTPError(w, errs.Internal("AI template generation is not configured"))
		return
	}
	var req struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Description == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("description field is required"))
		return
	}

	yaml, validation, attempts, err := h.generator.Generate(r.Context(), req.Description)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("template generation failed")
		errs.WriteHTTPError(w, errs.Internal("template generation failed"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{
		"yaml": yaml, "validation": validation, "attempts": attempts,
	})
}
