package nuclei

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	nucleiSdk "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"gopkg.in/yaml.v3"

	"github.com/vulngraph/vulngraph/internal/app/scan"
)

// templateDoc is the minimal YAML shape for validation without the full SDK.
type templateDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name        string `yaml:"name"`
		Author      any    `yaml:"author"`
		Severity    string `yaml:"severity"`
		Description string `yaml:"description"`
		Tags        any    `yaml:"tags"`
	} `yaml:"info"`
	// Protocol blocks, one per top-level key nuclei v3.11.1 reads
	// (pkg/templates/templates.go). requests is the deprecated spelling of
	// http, tcp the newer spelling of network.
	HTTP       []any `yaml:"http"`
	Requests   []any `yaml:"requests"`
	DNS        []any `yaml:"dns"`
	Network    []any `yaml:"network"`
	TCP        []any `yaml:"tcp"`
	SSL        []any `yaml:"ssl"`
	Websocket  []any `yaml:"websocket"`
	WHOIS      []any `yaml:"whois"`
	JavaScript []any `yaml:"javascript"`
	Headless   []any `yaml:"headless"`
	File       []any `yaml:"file"`
	Code       []any `yaml:"code"`
	Workflows  []any `yaml:"workflows"`
}

// Template-test caps. A test is one admin-submitted template against one URL,
// run inside serve, so it gets the scan rate limit but one template, one host
// and a short deadline, and a smaller response read bound than the SDK's 10 MiB.
const (
	maxTestDuration     = 2 * time.Minute
	maxTestResponseRead = 1 << 20
)

// testRunOptions are the caps TestTemplate applies; the scan path's equivalents
// live in Engine.Scan.
func testRunOptions(ctx context.Context) []nucleiSdk.NucleiSDKOptions {
	return []nucleiSdk.NucleiSDKOptions{
		nucleiSdk.WithGlobalRateLimitCtx(ctx, globalRateLimit, globalRateInterval),
		nucleiSdk.WithConcurrency(concurrency(1, 1, 1)),
		nucleiSdk.WithResponseReadSize(maxTestResponseRead),
	}
}

// sdkValidateTimeout bounds building the engine and loading the template.
const sdkValidateTimeout = 10 * time.Second

// unsupportedProtocols are the template kinds Vulngraph's engines cannot run,
// each with the reason Validate reports. The SDK would skip them at load,
// which reads as a parse failure.
var unsupportedProtocols = []struct {
	present func(templateDoc) bool
	message string
}{
	{func(d templateDoc) bool { return len(d.File) > 0 }, "file templates are not supported: Vulngraph runs templates against URLs, and nuclei runs file templates only against local paths with -file enabled"},
	{func(d templateDoc) bool { return len(d.Code) > 0 }, "code templates are not supported: they run commands on the scanner host, and Vulngraph never enables them"},
	{func(d templateDoc) bool { return len(d.Headless) > 0 }, "headless templates are not supported: the scanner runs nuclei without a browser (headless is not enabled)"},
	{func(d templateDoc) bool { return len(d.Workflows) > 0 }, "workflow templates are not supported: submit each template the workflow runs on its own"},
}

// Validate lints and validates a nuclei template YAML in two phases: a fast
// structural check (missing id/info.name/info.author/info.severity, invalid
// severity, no protocol block, a template kind Vulngraph cannot run), then
// loading it through the nuclei SDK's template loader, which parses matchers,
// operators and protocol fields. The template's own tags are passed as
// include tags, so nuclei's default ignore list (dos, fuzz, ...) does not
// reject a well-formed template by tag.
//
// Accepted protocols: http (and its deprecated spelling requests), dns,
// network (and tcp), ssl, websocket, whois and javascript. Nuclei loads a
// javascript template only when it is signed by a trusted key, so an unsigned
// one fails phase 2 with that reason. Rejected by name: file, code, headless
// and workflow templates (unsupportedProtocols).
//
// Loading does not send requests, so a matcher that parses but never matches
// still passes; TestTemplate against a real URL is the check for that. ctx
// bounds the SDK phase together with sdkValidateTimeout.
//
// Returns scan.TemplateValidation with Valid=true and TemplateInfo on
// success, or Valid=false with one or more error messages on failure.
func Validate(ctx context.Context, yamlContent string) scan.TemplateValidation {
	// Phase 1: lightweight structural check (fast, no SDK overhead).
	var doc templateDoc
	if err := yaml.Unmarshal([]byte(yamlContent), &doc); err != nil {
		return scan.TemplateValidation{
			Errors: []scan.TemplateValidationError{{Message: "YAML parse error: " + err.Error()}},
		}
	}

	var structErrs []scan.TemplateValidationError
	if doc.ID == "" {
		structErrs = append(structErrs, scan.TemplateValidationError{Message: "missing required field: id"})
	}
	if doc.Info.Name == "" {
		structErrs = append(structErrs, scan.TemplateValidationError{Message: "missing required field: info.name"})
	}
	if anyToString(doc.Info.Author) == "" {
		structErrs = append(structErrs, scan.TemplateValidationError{Message: "missing required field: info.author"})
	}
	if doc.Info.Severity == "" {
		structErrs = append(structErrs, scan.TemplateValidationError{Message: "missing required field: info.severity"})
	} else {
		switch strings.ToLower(doc.Info.Severity) {
		case "info", "low", "medium", "high", "critical":
		default:
			structErrs = append(structErrs, scan.TemplateValidationError{
				Message: fmt.Sprintf("invalid severity %q: must be info|low|medium|high|critical", doc.Info.Severity),
			})
		}
	}
	unsupported := false
	for _, u := range unsupportedProtocols {
		if u.present(doc) {
			unsupported = true
			structErrs = append(structErrs, scan.TemplateValidationError{Message: u.message})
		}
	}
	protocols := detectProtocols(doc)
	if len(protocols) == 0 && !unsupported {
		structErrs = append(structErrs, scan.TemplateValidationError{
			Message: "template has no protocol block (http, dns, network/tcp, ssl, websocket, whois or javascript)",
		})
	}
	if len(structErrs) > 0 {
		return scan.TemplateValidation{Errors: structErrs}
	}

	// Phase 2: load the template through the nuclei SDK (validateWithSDK).
	if sdkErr := validateWithSDK(ctx, yamlContent, templateIncludeTags(doc), len(doc.JavaScript) > 0); sdkErr != nil {
		return scan.TemplateValidation{
			Errors: []scan.TemplateValidationError{{Message: "nuclei SDK: " + sdkErr.Error()}},
		}
	}

	return scan.TemplateValidation{
		Valid: true,
		Info: &scan.TemplateInfo{
			ID:          doc.ID,
			Name:        doc.Info.Name,
			Author:      anyToString(doc.Info.Author),
			Severity:    strings.ToLower(doc.Info.Severity),
			Description: doc.Info.Description,
			Tags:        anyToStringSlice(doc.Info.Tags),
			Protocols:   protocols,
		},
	}
}

// validateWithSDK writes the template to a temp file and loads it through the
// nuclei engine's template loader. A template the loader does not keep is
// rejected. tags are the template's own tags, passed as include tags so the
// default ignore list cannot drop it. javascript says the template has a
// javascript block, which nuclei skips unless it is signed.
func validateWithSDK(ctx context.Context, yamlContent string, tags []string, javascript bool) error {
	f, err := os.CreateTemp("", "graph-validate-*.yaml")
	if err != nil {
		// Don't report the template as valid when we never validated it — surface
		// the infrastructure failure instead of a false "valid".
		return fmt.Errorf("validate: create temp file: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString(yamlContent); err != nil {
		_ = f.Close()
		return fmt.Errorf("validate: write temp file: %w", err)
	}
	_ = f.Close()

	ctx, cancel := context.WithTimeout(ctx, sdkValidateTimeout)
	defer cancel()

	ne, err := nucleiSdk.NewNucleiEngineCtx(ctx, append([]nucleiSdk.NucleiSDKOptions{
		nucleiSdk.WithTemplatesOrWorkflows(nucleiSdk.TemplateSources{
			Templates: []string{f.Name()},
		}),
		nucleiSdk.WithTemplateFilters(nucleiSdk.TemplateFilters{IncludeTags: tags}),
	}, egressOptions()...)...)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("validation did not finish: %w", ctxErr)
		}
		// Remove SDK boilerplate from the error message for a cleaner UX.
		msg := err.Error()
		if idx := strings.Index(msg, "could not create nuclei engine"); idx >= 0 {
			msg = strings.TrimPrefix(msg[idx:], "could not create nuclei engine: ")
		}
		return fmt.Errorf("%s", msg)
	}
	defer ne.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("validation did not finish: %w", ctxErr)
	}
	// The engine does not parse templates at construction; LoadAllTemplates
	// does, and its loader logs and skips a template it cannot parse instead
	// of returning an error, so zero loaded templates is the rejection signal.
	if err := ne.LoadAllTemplates(); err != nil {
		return fmt.Errorf("load template: %w", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("validation did not finish: %w", ctxErr)
	}
	if len(ne.GetTemplates()) == 0 {
		if javascript {
			return fmt.Errorf("nuclei did not load the template: it runs a javascript template only when it is signed by a trusted key (nuclei template signing), or the template failed to parse")
		}
		return fmt.Errorf("nuclei did not load the template (it failed to parse)")
	}
	return nil
}

// detectProtocols names every runnable protocol block the template has, with
// the deprecated spellings folded into their current name.
func detectProtocols(doc templateDoc) []string {
	var p []string
	for _, b := range []struct {
		name    string
		present bool
	}{
		{"http", len(doc.HTTP) > 0 || len(doc.Requests) > 0},
		{"dns", len(doc.DNS) > 0},
		{"network", len(doc.Network) > 0 || len(doc.TCP) > 0},
		{"ssl", len(doc.SSL) > 0},
		{"websocket", len(doc.Websocket) > 0},
		{"whois", len(doc.WHOIS) > 0},
		{"javascript", len(doc.JavaScript) > 0},
	} {
		if b.present {
			p = append(p, b.name)
		}
	}
	return p
}

func anyToString(v any) string {
	if v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []any:
		parts := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				parts = append(parts, str)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

// templateIncludeTags is the template's own tags in the form nuclei stores
// them (trimmed, lowercased). Nuclei normalises a template's tags that way but
// its index filter compares include tags against the ignore list as given, so
// a raw "DOS" would not lift the "dos" exclusion and the template would be
// dropped.
func templateIncludeTags(doc templateDoc) []string {
	tags := anyToStringSlice(doc.Info.Tags)
	for i, t := range tags {
		tags[i] = strings.ToLower(strings.TrimSpace(t))
	}
	return tags
}

func anyToStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch s := v.(type) {
	case string:
		var out []string
		for _, t := range strings.Split(s, ",") {
			if t = strings.TrimSpace(t); t != "" {
				out = append(out, t)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	default:
		return nil
	}
}

// TestTemplate runs a nuclei template YAML against a single target URL, under
// the rate limit, concurrency, deadline and response bound of testRunOptions.
// Unless allowInternal, connections to private, loopback, link-local and
// metadata addresses are refused at dial time. That covers hosts hard-coded
// in the template itself, not only targetURL. The template's own tags are
// include tags, as in Validate: without them a template tagged with a default
// ignore-list tag (dos, fuzz, ...) is silently not run, and zero results would
// read as "no match".
func TestTemplate(ctx context.Context, yamlContent, targetURL string, allowInternal bool) ([]scan.Result, error) {
	if strings.TrimSpace(targetURL) == "" {
		return nil, fmt.Errorf("TestTemplate: target URL is required")
	}
	ctx, cancel := context.WithTimeout(ctx, maxTestDuration)
	defer cancel()

	var doc templateDoc
	if err := yaml.Unmarshal([]byte(yamlContent), &doc); err != nil {
		return nil, fmt.Errorf("TestTemplate: parse template: %w", err)
	}

	f, err := os.CreateTemp("", "graph-template-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("TestTemplate: create temp: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString(yamlContent); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("TestTemplate: write temp: %w", err)
	}
	_ = f.Close()

	ne, err := nucleiSdk.NewNucleiEngineCtx(ctx, append([]nucleiSdk.NucleiSDKOptions{
		nucleiSdk.WithTemplatesOrWorkflows(nucleiSdk.TemplateSources{
			Templates: []string{f.Name()},
		}),
		nucleiSdk.WithTemplateFilters(nucleiSdk.TemplateFilters{IncludeTags: templateIncludeTags(doc)}),
		sandboxOption(allowInternal),
	}, append(testRunOptions(ctx), egressOptions()...)...)...)
	if err != nil {
		return nil, fmt.Errorf("TestTemplate: engine: %w", err)
	}
	defer ne.Close()

	ne.LoadTargets([]string{targetURL}, false)

	var (
		mu      sync.Mutex
		results []scan.Result
	)
	err = ne.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		if ev == nil {
			return
		}
		mu.Lock()
		results = append(results, scan.Result{
			Scanner:    "nuclei",
			TemplateID: ev.TemplateID,
			Name:       ev.Info.Name,
			Severity:   ev.Info.SeverityHolder.Severity.String(),
			MatchedURL: ev.Matched,
		})
		mu.Unlock()
	})
	if err != nil {
		return nil, fmt.Errorf("TestTemplate: execute: %w", err)
	}
	return results, nil
}
