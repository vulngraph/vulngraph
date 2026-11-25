package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// supportsAdaptiveThinking reports whether model accepts Thinking:
// {type:"adaptive"}. LLM_MODEL / REASON_MODEL / ADJUDICATOR_MODEL can name any
// model string, so this is checked before forcing adaptive thinking onto a
// model that rejects it (400) — a Reasoning request on any other model goes
// out with no Thinking config and reports Response.ReasoningSkipped.
//
// A family/version rule rather than an exact-match list, so a new release or a
// dated snapshot (claude-opus-5-5, claude-sonnet-5-5, claude-fable-5-1,
// claude-opus-4-6-20260101) is covered without an edit here:
//   - Fable and Mythos: every version (thinking is always on).
//   - Opus and Sonnet: 4.6 and later.
//   - Haiku (4.5 and earlier) and every older naming (claude-3-5-sonnet-…):
//     no — they need the deprecated {type:"enabled"} shape or no thinking.
//
// Provider prefixes and suffixes are ignored: "anthropic.claude-opus-5-5"
// (Bedrock), "claude-opus-4-6@20260101" (Vertex), "claude-opus-4-8[1m]",
// "anthropic/claude-opus-4.8" (OpenRouter).
func supportsAdaptiveThinking(model string) bool {
	i := strings.Index(model, "claude-")
	if i < 0 {
		return false
	}
	name := model[i:]
	if j := strings.IndexAny(name, "@["); j >= 0 {
		name = name[:j]
	}
	// OpenRouter-style ids spell the version with a dot (claude-opus-4.8).
	parts := strings.Split(strings.ReplaceAll(name, ".", "-"), "-")
	if len(parts) < 3 {
		return false
	}
	major, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}
	minor := 0
	// A third number is a minor version only when it is short; an 8-digit
	// value is a snapshot date (claude-opus-4-20250514 is Opus 4.0).
	if len(parts) > 3 && len(parts[3]) <= 2 {
		if m, err := strconv.Atoi(parts[3]); err == nil {
			minor = m
		}
	}
	switch parts[1] {
	case "fable", "mythos":
		return major >= 5
	case "opus", "sonnet":
		return major > 4 || (major == 4 && minor >= 6)
	default:
		return false
	}
}

type anthropicClient struct {
	cfg    Config
	client anthropic.Client
}

func newAnthropic(c Config) *anthropicClient {
	opts := []option.RequestOption{option.WithAPIKey(c.APIKey)}
	if c.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(c.BaseURL))
	}
	return &anthropicClient{cfg: c, client: anthropic.NewClient(opts...)}
}

func (a *anthropicClient) Provider() Provider { return ProviderAnthropic }

func (a *anthropicClient) Complete(ctx context.Context, req Request) (*Response, error) {
	params, skipped := buildAnthropicParams(a.cfg.modelFor(req), req)
	msg, err := a.client.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("anthropic: %w", err)
	}
	resp := fromAnthropicMessage(msg, params)
	resp.ReasoningSkipped = skipped
	resp.Usage.Reported = msg.Usage.JSON.OutputTokens.Valid()
	return resp, nil
}

func (a *anthropicClient) Stream(ctx context.Context, req Request, onText func(string)) (*Response, error) {
	params, skipped := buildAnthropicParams(a.cfg.modelFor(req), req)
	stream := a.client.Messages.NewStreaming(ctx, params)
	accumulated := anthropic.Message{}
	stopped, usageFinal := false, false
	for stream.Next() {
		event := stream.Current()
		_ = accumulated.Accumulate(event)
		switch ev := event.AsAny().(type) {
		case anthropic.ContentBlockDeltaEvent:
			if delta, ok := ev.Delta.AsAny().(anthropic.TextDelta); ok && delta.Text != "" && onText != nil {
				onText(delta.Text)
			}
		case anthropic.MessageDeltaEvent:
			// message_delta carries the cumulative final usage; message_start's
			// usage is only the input side plus a placeholder output count.
			usageFinal = true
		case anthropic.MessageStopEvent:
			stopped = true
		}
	}
	resp := fromAnthropicMessage(&accumulated, params)
	resp.ReasoningSkipped = skipped
	resp.Usage.Reported = usageFinal
	if err := stream.Err(); err != nil {
		return resp, fmt.Errorf("anthropic stream: %w", err)
	}
	if !stopped {
		// The connection ended before message_stop: whatever arrived is a
		// fragment, not a reply that happened to stop.
		return resp, fmt.Errorf("anthropic stream: ended before message_stop: %w", io.ErrUnexpectedEOF)
	}
	return resp, nil
}

// buildAnthropicParams is a pure translation of a Request into SDK params, so
// the thinking/token-budget/schema/caching behaviors are unit-testable with no
// network call.
//
// Thinking and the larger Reasoning.MaxTokens budget are both scoped to
// useThinking (Reasoning requested AND supportsAdaptiveThinking(model)) — never applied to the larger budget alone
// without thinking actually being on. skipped reports Reasoning was requested
// but the model does not accept adaptive thinking, so the caller can log it rather than
// silently degrade.
func buildAnthropicParams(model string, req Request) (params anthropic.MessageNewParams, skipped bool) {
	useThinking := req.Reasoning != nil && supportsAdaptiveThinking(model)
	tokens := req.MaxTokens
	if useThinking && req.Reasoning.MaxTokens > 0 {
		tokens = req.Reasoning.MaxTokens
	}
	params = anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: tokens,
		Messages:  toAnthropicMessages(req.Messages),
	}
	for _, s := range req.System {
		block := anthropic.TextBlockParam{Text: s.Text}
		if s.Cache {
			// The 5-min TTL refreshes on every hit, so a busy deploy keeps a
			// stable prefix (tools + system prompt) warm indefinitely.
			block.CacheControl = anthropic.CacheControlEphemeralParam{TTL: anthropic.CacheControlEphemeralTTLTTL5m}
		}
		params.System = append(params.System, block)
	}
	for _, t := range req.Tools {
		tool := anthropic.ToolParam{
			Name:        t.Name,
			Description: anthropic.String(t.Description),
			InputSchema: toAnthropicSchema(t.InputSchema),
		}
		params.Tools = append(params.Tools, anthropic.ToolUnionParam{OfTool: &tool})
	}
	if req.JSONSchema != nil {
		// Not gated by supportsAdaptiveThinking — that rule covers
		// {type:"adaptive"} support specifically. A model without structured-output
		// support 400s loudly on the first call rather than degrading silently.
		params.OutputConfig = anthropic.OutputConfigParam{
			Format: anthropic.JSONOutputFormatParam{Schema: req.JSONSchema},
		}
	}
	if useThinking {
		params.Thinking = anthropic.ThinkingConfigParamUnion{OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{}}
	}
	return params, req.Reasoning != nil && !useThinking
}

func toAnthropicMessages(msgs []Message) []anthropic.MessageParam {
	msgs = normalizeMessages(msgs)
	out := make([]anthropic.MessageParam, 0, len(msgs))
	for _, m := range msgs {
		var blocks []anthropic.ContentBlockParamUnion
		// tool_result blocks must lead a user message's content; any text
		// follows them. An assistant turn's text precedes its tool_use blocks.
		for _, tr := range m.ToolResults {
			blocks = append(blocks, anthropic.NewToolResultBlock(tr.CallID, tr.Content, tr.IsError))
		}
		if m.Text != "" {
			blocks = append(blocks, anthropic.NewTextBlock(m.Text))
		}
		for _, tc := range m.ToolCalls {
			input := tc.Input
			if len(input) == 0 {
				input = json.RawMessage(`{}`)
			}
			blocks = append(blocks, anthropic.NewToolUseBlock(tc.ID, input, tc.Name))
		}
		if m.Role == RoleAssistant {
			out = append(out, anthropic.NewAssistantMessage(blocks...))
		} else {
			out = append(out, anthropic.NewUserMessage(blocks...))
		}
	}
	return out
}

// toAnthropicSchema splits a JSON Schema object into the SDK's typed
// properties/required fields plus pass-through extras.
func toAnthropicSchema(schema map[string]any) anthropic.ToolInputSchemaParam {
	var p anthropic.ToolInputSchemaParam
	for k, v := range schema {
		switch k {
		case "type":
		case "properties":
			p.Properties = v
		case "required":
			p.Required = toStrings(v)
		default:
			if p.ExtraFields == nil {
				p.ExtraFields = map[string]any{}
			}
			p.ExtraFields[k] = v
		}
	}
	return p
}

func toStrings(v any) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, x := range vv {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// fromAnthropicMessage converts the SDK response. Only TextBlock content is
// collected into Text — a ThinkingBlock's reasoning never leaks into the reply.
func fromAnthropicMessage(msg *anthropic.Message, params anthropic.MessageNewParams) *Response {
	resp := &Response{Model: string(params.Model), MaxTokens: params.MaxTokens}
	var b strings.Builder
	// Switch on Type rather than AsAny(): AsAny decodes from the raw JSON, which
	// a hand-constructed (test) or Accumulate()d union may not carry.
	for _, block := range msg.Content {
		switch block.Type {
		case "text":
			b.WriteString(block.Text)
		case "tool_use":
			input := block.Input
			if len(input) == 0 {
				input = json.RawMessage(`{}`)
			}
			resp.ToolCalls = append(resp.ToolCalls, ToolCall{ID: block.ID, Name: block.Name, Input: input})
		}
	}
	resp.Text = b.String()
	resp.Usage = Usage{
		InputTokens:      msg.Usage.InputTokens,
		OutputTokens:     msg.Usage.OutputTokens,
		CacheReadTokens:  msg.Usage.CacheReadInputTokens,
		CacheWriteTokens: msg.Usage.CacheCreationInputTokens,
	}
	switch msg.StopReason {
	case anthropic.StopReasonMaxTokens:
		resp.StopReason = StopMaxTokens
	case anthropic.StopReasonRefusal:
		resp.StopReason = StopRefusal
		resp.Refusal = Refusal{Category: string(msg.StopDetails.Category), Explanation: msg.StopDetails.Explanation}
	case anthropic.StopReasonToolUse:
		resp.StopReason = StopToolUse
	default:
		resp.StopReason = StopEnd
	}
	return resp
}
