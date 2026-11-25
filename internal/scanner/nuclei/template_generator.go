package nuclei

import (
	"context"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/llm"
)

// maxGenerationAttempts is how many times we retry generation when the
// validator rejects the output. Each retry includes the previous errors in
// the prompt so the model can self-correct.
const maxGenerationAttempts = 3

// emptyReplyPlaceholder stands in for an attempt that produced no text in the
// self-correction conversation.
const emptyReplyPlaceholder = "(empty reply — no template was produced)"

const nucleiTemplateSystemPrompt = `You are a nuclei security template expert for nuclei v3. Generate a valid nuclei YAML template.

OUTPUT FORMAT:
- Output ONLY the raw YAML — no markdown fences (no ` + "```" + `), no explanation, no comments before the template
- The very first line must be "id: ..."

REQUIRED FIELDS (all mandatory — validator will reject if missing):
  id: kebab-case-identifier   # pattern: ^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$
  info:
    name: Human-readable name
    author: security-graph
    severity: info|low|medium|high|critical   # ONLY these exact values
    description: What it checks for
    tags: comma,separated,tags

VALID MATCHER TYPES (use only these exact strings):
  word, regex, status, binary, xpath, dsl, size

VALID PROTOCOL BLOCKS (must include at least one):
  http, dns, network (or tcp), ssl, websocket, whois
  (file, code, headless and workflow templates are rejected: they never run here;
  javascript runs only when signed, so do not generate it)

NUCLEI v3 HTTP TEMPLATE STRUCTURE:
id: example-check
info:
  name: Example Security Check
  author: security-graph
  severity: medium
  description: Checks for exposed admin endpoint
  tags: exposure,misconfig
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "Admin Dashboard"
        part: body

MATCHER REFERENCE:
  # word matcher
  - type: word
    words: ["string1", "string2"]
    condition: or|and      # default: or
    part: body|header|all  # default: body

  # regex matcher
  - type: regex
    regex: ["pattern1", "pattern2"]
    part: body|header

  # status matcher
  - type: status
    status: [200, 301, 302]

  # dsl matcher (for complex logic)
  - type: dsl
    dsl:
      - "status_code == 200 && contains(body, 'secret')"

DNS TEMPLATE STRUCTURE:
id: dns-takeover-check
info:
  name: DNS Subdomain Takeover Check
  author: security-graph
  severity: high
  tags: dns,takeover
dns:
  - name: "{{FQDN}}"
    type: CNAME
    matchers:
      - type: word
        words: ["amazonaws.com", "azurewebsites.net"]

RULES:
- ONE check per template — do not combine unrelated tests
- Use {{BaseURL}} for HTTP paths (not full URLs)
- Matchers must be precise to avoid false positives
- Tags: lowercase, comma-separated, no spaces
- If checking for a CVE: add CVE id to tags and add classification block`

// TemplateGenerator generates nuclei templates from natural-language descriptions.
// It uses a self-correcting loop: if the validator rejects the output, the errors
// are fed back to the LLM for up to maxGenerationAttempts retries.
type TemplateGenerator struct {
	client llm.Client
	model  string // "" = the provider's default model
}

// NewTemplateGenerator creates a generator on the configured LLM client.
func NewTemplateGenerator(client llm.Client, model string) *TemplateGenerator {
	return &TemplateGenerator{client: client, model: model}
}

// Generate creates a nuclei YAML template from a natural-language description,
// validates it, and retries with error context if invalid.
//
// The self-correcting loop:
//  1. Ask the LLM to generate a template for the description.
//  2. Validate the output with the nuclei SDK.
//  3. If invalid, build a correction prompt with the previous YAML + errors.
//  4. Repeat up to maxGenerationAttempts times.
//
// Returns the best YAML produced (last attempt's output), the final
// validation result, the number of attempts used, and any LLM error.
func (g *TemplateGenerator) Generate(ctx context.Context, description string) (string, scan.TemplateValidation, int, error) {
	if strings.TrimSpace(description) == "" {
		return "", scan.TemplateValidation{}, 0, fmt.Errorf("Generate: description is required")
	}

	if g.client == nil {
		return "", scan.TemplateValidation{}, 0, fmt.Errorf("Generate: no LLM provider configured")
	}

	// Conversation history for multi-turn self-correction.
	messages := []llm.Message{llm.UserText(description)}

	var lastYAML string
	var lastValidation scan.TemplateValidation

	for attempt := 1; attempt <= maxGenerationAttempts; attempt++ {
		resp, err := g.client.Complete(ctx, llm.Request{
			Model:     g.model,
			MaxTokens: 2048,
			System:    []llm.SystemBlock{{Text: nucleiTemplateSystemPrompt}},
			Messages:  messages,
		})
		if err != nil {
			return lastYAML, lastValidation, attempt - 1, fmt.Errorf("Generate: LLM attempt %d: %w", attempt, err)
		}
		if resp.StopReason == llm.StopRefusal {
			// Retrying the same request with "fix the errors" appended will not
			// change a policy decision.
			return lastYAML, lastValidation, attempt, fmt.Errorf("Generate: LLM attempt %d: model refused: %s", attempt, resp.Refusal.Explanation)
		}

		rawYAML := cleanYAML(resp.Text)
		lastYAML = rawYAML

		// Validate with the nuclei SDK.
		lastValidation = Validate(ctx, rawYAML)
		if lastValidation.Valid {
			return rawYAML, lastValidation, attempt, nil
		}

		// Still invalid — build a correction turn if we have retries left.
		if attempt < maxGenerationAttempts {
			errorList := buildErrorList(lastValidation.Errors)
			correctionPrompt := fmt.Sprintf(
				"The template you generated has validation errors. Fix ALL of them and output ONLY the corrected YAML.\n\n"+
					"Previous template:\n%s\n\nErrors to fix:\n%s",
				rawYAML, errorList,
			)
			// Append assistant reply + correction request to the conversation.
			// An empty reply still needs a non-blank assistant turn: a blank one
			// is dropped by the llm layer, which would fold the correction into
			// the original request and lose the record of the failed attempt.
			reply := rawYAML
			if reply == "" {
				reply = emptyReplyPlaceholder
			}
			messages = append(messages, llm.AssistantText(reply), llm.UserText(correctionPrompt))
		}
	}

	// All attempts exhausted — return the last output with its validation.
	return lastYAML, lastValidation, maxGenerationAttempts, nil
}

// cleanYAML strips markdown fences and trims whitespace from LLM output.
func cleanYAML(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "```") {
		return raw
	}
	var lines []string
	for _, l := range strings.Split(raw, "\n") {
		if strings.HasPrefix(l, "```") {
			continue
		}
		lines = append(lines, l)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// buildErrorList formats validation errors as a numbered list for the correction prompt.
func buildErrorList(errs []scan.TemplateValidationError) string {
	var b strings.Builder
	for i, e := range errs {
		if e.Line > 0 {
			fmt.Fprintf(&b, "%d. Line %d: %s\n", i+1, e.Line, e.Message)
		} else {
			fmt.Fprintf(&b, "%d. %s\n", i+1, e.Message)
		}
	}
	return b.String()
}
