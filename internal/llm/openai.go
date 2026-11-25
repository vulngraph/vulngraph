package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// openAIClient speaks the OpenAI Chat Completions wire format, which most
// hosted and self-hosted model servers implement. Plain net/http rather than
// a vendor SDK: the surface used is small, and staying on the wire format
// keeps every compatible server equally first-class.
//
// The base URL is operator configuration, not user input, and a local model
// server is a legitimate target — so this uses safenet.NewInternalEgress (a
// hosted model server may sit behind HTTPS_PROXY), not the
// internal-address-blocking safenet.New.
type openAIClient struct {
	cfg  Config
	http *http.Client
}

func newOpenAI(c Config) *openAIClient {
	if c.ReasoningEffort == "" {
		// Without LLM_REASONING_EFFORT this backend has no way to turn
		// reasoning on, so Request.Reasoning is ignored. Said once here rather
		// than via Response.ReasoningSkipped: that flag is for a model that
		// can't take the config it was asked for, and setting it on every call
		// would repeat the reason package's per-call warning for a deliberate,
		// deploy-wide setting.
		log.FromContext(context.Background()).Info().
			Msg("llm: LLM_REASONING_EFFORT is unset — reasoning requests run without reasoning_effort on the openai backend")
	}
	// Timeout 0 (none): requests are bounded by ctx, and a streamed chat turn
	// — or a long non-streamed generation before its first header byte — can
	// legitimately run for minutes.
	return &openAIClient{cfg: c, http: safenet.NewInternalEgress(0)}
}

func (o *openAIClient) Provider() Provider { return ProviderOpenAI }

// --- wire types ---

type oaMessage struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
	Refusal    string       `json:"refusal,omitempty"`
}

type oaToolCall struct {
	Index    *int   `json:"index,omitempty"`
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string `json:"name,omitempty"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string         `json:"name"`
		Description string         `json:"description,omitempty"`
		Parameters  map[string]any `json:"parameters"`
	} `json:"function"`
}

type oaRequest struct {
	Model               string         `json:"model"`
	Messages            []oaMessage    `json:"messages"`
	Tools               []oaTool       `json:"tools,omitempty"`
	MaxTokens           int64          `json:"max_tokens,omitempty"`
	MaxCompletionTokens int64          `json:"max_completion_tokens,omitempty"`
	ResponseFormat      map[string]any `json:"response_format,omitempty"`
	ReasoningEffort     string         `json:"reasoning_effort,omitempty"`
	Stream              bool           `json:"stream,omitempty"`
	// StreamOptions asks for a final usage chunk on a streamed reply; without
	// it the wire format reports no usage for streams at all.
	StreamOptions *oaStreamOptions `json:"stream_options,omitempty"`
}

type oaStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// oaUsage is the wire usage block. prompt_tokens INCLUDES the cached part
// (prompt_tokens_details.cached_tokens), unlike Anthropic's input_tokens.
type oaUsage struct {
	PromptTokens        int64 `json:"prompt_tokens"`
	CompletionTokens    int64 `json:"completion_tokens"`
	PromptTokensDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

// toUsage normalises the wire block onto Usage's disjoint counts. Nil (the
// server sent none) is an unreported Usage, never a zero measurement.
func (u *oaUsage) toUsage() Usage {
	if u == nil {
		return Usage{}
	}
	var cached int64
	if u.PromptTokensDetails != nil {
		cached = min(u.PromptTokensDetails.CachedTokens, u.PromptTokens)
	}
	return Usage{
		InputTokens:     u.PromptTokens - cached,
		OutputTokens:    u.CompletionTokens,
		CacheReadTokens: cached,
		Reported:        true,
	}
}

type oaChoice struct {
	Message      oaMessage `json:"message"`
	Delta        oaMessage `json:"delta"`
	FinishReason string    `json:"finish_reason"`
}

type oaResponse struct {
	Choices []oaChoice `json:"choices"`
	// Error is set when a server reports a failure in-band: as a stream
	// chunk after the 200 headers went out, or (some proxies) as a 200 body.
	// OpenAI and most servers send an object with a message; Ollama sends a
	// bare string.
	Error json.RawMessage `json:"error"`
	// Usage is on a complete response, and on the final chunk of a stream
	// that asked for it (that chunk has no choices).
	Usage *oaUsage `json:"usage"`
}

// errorMessage returns the in-band error text, or "" when there is none.
func (r oaResponse) errorMessage() string {
	raw := bytes.TrimSpace(r.Error)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &obj) == nil && obj.Message != "" {
		return obj.Message
	}
	return string(raw)
}

// buildOpenAIRequest is a pure translation of a Request into the wire body,
// unit-testable without a server.
func (o *openAIClient) buildOpenAIRequest(req Request, stream bool) (oaRequest, int64) {
	model := o.cfg.modelFor(req)
	body := oaRequest{Model: model, Stream: stream}
	if stream {
		body.StreamOptions = &oaStreamOptions{IncludeUsage: true}
	}

	var sys []string
	for _, s := range req.System {
		sys = append(sys, s.Text)
	}
	if len(sys) > 0 {
		joined := strings.Join(sys, "\n\n")
		body.Messages = append(body.Messages, oaMessage{Role: "system", Content: &joined})
	}
	for _, m := range normalizeMessages(req.Messages) {
		body.Messages = append(body.Messages, toOpenAIMessages(m)...)
	}
	for _, t := range req.Tools {
		var tool oaTool
		tool.Type = "function"
		tool.Function.Name = t.Name
		tool.Function.Description = t.Description
		tool.Function.Parameters = t.InputSchema
		if tool.Function.Parameters == nil {
			tool.Function.Parameters = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		body.Tools = append(body.Tools, tool)
	}
	if req.JSONSchema != nil {
		// strict:false — strict mode rejects schema keywords some callers use
		// (minLength, …) and is unsupported by many compatible servers. Callers
		// validate the decoded reply regardless (see Request.JSONSchema).
		body.ResponseFormat = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "response",
				"schema": req.JSONSchema,
				"strict": false,
			},
		}
	}
	tokens := req.MaxTokens
	if req.Reasoning != nil && o.cfg.ReasoningEffort != "" {
		body.ReasoningEffort = o.cfg.ReasoningEffort
		if req.Reasoning.MaxTokens > 0 {
			tokens = req.Reasoning.MaxTokens
		}
	}
	// OpenAI's own API deprecated max_tokens (reasoning models reject it);
	// most compatible servers only understand max_tokens.
	if o.isOpenAIHosted() {
		body.MaxCompletionTokens = tokens
	} else {
		body.MaxTokens = tokens
	}
	return body, tokens
}

func (o *openAIClient) isOpenAIHosted() bool {
	u, err := url.Parse(o.cfg.BaseURL)
	return err == nil && strings.EqualFold(u.Hostname(), "api.openai.com")
}

func (o *openAIClient) isAzure() bool {
	u, err := url.Parse(o.cfg.BaseURL)
	return err == nil && strings.HasSuffix(strings.ToLower(u.Hostname()), ".openai.azure.com")
}

func toOpenAIMessages(m Message) []oaMessage {
	if m.Role == RoleAssistant {
		msg := oaMessage{Role: "assistant"}
		if m.Text != "" || len(m.ToolCalls) == 0 {
			text := m.Text
			msg.Content = &text
		}
		for _, tc := range m.ToolCalls {
			var call oaToolCall
			call.ID, call.Type = tc.ID, "function"
			call.Function.Name = tc.Name
			call.Function.Arguments = string(tc.Input)
			if call.Function.Arguments == "" {
				call.Function.Arguments = "{}"
			}
			msg.ToolCalls = append(msg.ToolCalls, call)
		}
		return []oaMessage{msg}
	}
	// A user turn answering tool calls becomes one role:"tool" message per
	// result (the wire format has no multi-result message), followed by any
	// user text.
	var out []oaMessage
	for _, tr := range m.ToolResults {
		content := tr.Content
		if tr.IsError {
			content = "ERROR: " + content
		}
		out = append(out, oaMessage{Role: "tool", ToolCallID: tr.CallID, Content: &content})
	}
	if m.Text != "" || len(m.ToolResults) == 0 {
		text := m.Text
		out = append(out, oaMessage{Role: "user", Content: &text})
	}
	return out
}

func (o *openAIClient) post(ctx context.Context, body oaRequest) (*http.Response, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("openai: encode request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.BaseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("openai: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if o.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.cfg.APIKey)
		if o.isAzure() {
			// Azure OpenAI key auth uses its own header.
			httpReq.Header.Set("api-key", o.cfg.APIKey)
		}
	}
	if body.Stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	}
	resp, err := o.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		defer func() { _ = resp.Body.Close() }()
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("openai: %s returned %d: %s", o.cfg.BaseURL, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return resp, nil
}

func (o *openAIClient) Complete(ctx context.Context, req Request) (*Response, error) {
	body, tokens := o.buildOpenAIRequest(req, false)
	httpResp, err := o.post(ctx, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()
	var wire oaResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&wire); err != nil {
		return nil, fmt.Errorf("openai: decode response: %w", err)
	}
	if msg := wire.errorMessage(); msg != "" {
		return nil, fmt.Errorf("openai: provider error: %s", msg)
	}
	if len(wire.Choices) == 0 {
		return nil, fmt.Errorf("openai: response had no choices")
	}
	ch := wire.Choices[0]
	resp := &Response{Model: body.Model, MaxTokens: tokens, Usage: wire.Usage.toUsage()}
	if ch.Message.Content != nil {
		resp.Text = *ch.Message.Content
	}
	for _, tc := range ch.Message.ToolCalls {
		resp.ToolCalls = append(resp.ToolCalls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Input: rawArgs(tc.Function.Arguments)})
	}
	resp.StopReason, resp.Refusal = openAIStop(ch.FinishReason, ch.Message.Refusal, len(resp.ToolCalls) > 0)
	return resp, nil
}

func (o *openAIClient) Stream(ctx context.Context, req Request, onText func(string)) (*Response, error) {
	body, tokens := o.buildOpenAIRequest(req, true)
	httpResp, err := o.post(ctx, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = httpResp.Body.Close() }()

	var (
		text    strings.Builder
		refusal strings.Builder
		finish  string
		calls   toolCallAccumulator
		usage   *oaUsage
		done    bool
	)
	partial := func() *Response {
		resp := &Response{Model: body.Model, MaxTokens: tokens, Text: text.String(), ToolCalls: calls.toolCalls(), Usage: usage.toUsage()}
		resp.StopReason, resp.Refusal = openAIStop(finish, refusal.String(), len(resp.ToolCalls) > 0)
		return resp
	}
	events := newSSEReader(httpResp.Body)
	for {
		data, ok := events.next()
		if !ok {
			break
		}
		if data == "[DONE]" {
			done = true
			break
		}
		var chunk oaResponse
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			return partial(), fmt.Errorf("openai stream: decode chunk: %w", err)
		}
		if msg := chunk.errorMessage(); msg != "" {
			return partial(), fmt.Errorf("openai stream: provider error: %s", msg)
		}
		if chunk.Usage != nil {
			usage = chunk.Usage
		}
		for _, ch := range chunk.Choices {
			if ch.Delta.Content != nil && *ch.Delta.Content != "" {
				text.WriteString(*ch.Delta.Content)
				if onText != nil {
					onText(*ch.Delta.Content)
				}
			}
			refusal.WriteString(ch.Delta.Refusal)
			for _, tc := range ch.Delta.ToolCalls {
				calls.add(tc)
			}
			if ch.FinishReason != "" {
				finish = ch.FinishReason
			}
		}
	}
	if err := events.err(); err != nil {
		return partial(), fmt.Errorf("openai stream: %w", err)
	}
	if !done && finish == "" {
		// Neither [DONE] nor a finish_reason: the connection was cut mid-reply
		// (proxy timeout, server crash), not a reply that ended.
		return partial(), fmt.Errorf("openai stream: ended without [DONE] or finish_reason: %w", io.ErrUnexpectedEOF)
	}
	return partial(), nil
}

// toolCallAccumulator reassembles streamed tool-call deltas. The OpenAI wire
// format keys every delta by index, but compatible servers vary: some send
// only an id on a call's first delta, some send neither on continuation
// deltas. A delta with an index joins that index's call; without one it
// joins the call with its id; with neither it continues the latest call.
type toolCallAccumulator struct {
	calls   []*oaToolCall
	byIndex map[int]*oaToolCall
	byID    map[string]*oaToolCall
}

func (a *toolCallAccumulator) add(tc oaToolCall) {
	if a.byIndex == nil {
		a.byIndex, a.byID = map[int]*oaToolCall{}, map[string]*oaToolCall{}
	}
	var acc *oaToolCall
	switch {
	case tc.Index != nil:
		acc = a.byIndex[*tc.Index]
	case tc.ID != "":
		acc = a.byID[tc.ID]
	case len(a.calls) > 0:
		acc = a.calls[len(a.calls)-1]
	}
	if acc == nil {
		acc = &oaToolCall{Index: tc.Index}
		a.calls = append(a.calls, acc)
		if tc.Index != nil {
			a.byIndex[*tc.Index] = acc
		}
	}
	if tc.ID != "" {
		acc.ID = tc.ID
		a.byID[tc.ID] = acc
	}
	if tc.Function.Name != "" {
		acc.Function.Name = tc.Function.Name
	}
	acc.Function.Arguments += tc.Function.Arguments
}

// toolCalls returns the assembled calls in index order, or in first-seen
// order when any call never carried an index.
func (a *toolCallAccumulator) toolCalls() []ToolCall {
	ordered := append([]*oaToolCall(nil), a.calls...)
	if len(a.byIndex) == len(ordered) {
		sort.Slice(ordered, func(i, j int) bool { return *ordered[i].Index < *ordered[j].Index })
	}
	var out []ToolCall
	for _, c := range ordered {
		out = append(out, ToolCall{ID: c.ID, Name: c.Function.Name, Input: rawArgs(c.Function.Arguments)})
	}
	return out
}

// sseReader yields the data payload of each Server-Sent Event. Per the SSE
// spec an event's data is every data: line up to the blank line that ends it,
// joined with "\n" — a server is free to split one JSON chunk across lines.
// Comment lines and other fields (event:, id:, retry:) are ignored.
type sseReader struct {
	sc *bufio.Scanner
}

func newSSEReader(r io.Reader) *sseReader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return &sseReader{sc: sc}
}

// next returns the next event's data, or false at the end of the stream.
func (s *sseReader) next() (string, bool) {
	var lines []string
	for s.sc.Scan() {
		line := s.sc.Text()
		if line == "" {
			if len(lines) > 0 {
				return strings.Join(lines, "\n"), true
			}
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		if field != "data" {
			continue
		}
		lines = append(lines, strings.TrimPrefix(value, " "))
	}
	// A final event the server didn't terminate with a blank line is still
	// delivered: [DONE] or an error is often the last thing written.
	if len(lines) > 0 {
		return strings.Join(lines, "\n"), true
	}
	return "", false
}

func (s *sseReader) err() error { return s.sc.Err() }

// openAIStop maps finish_reason (and a structured-output refusal) onto
// StopReason. Some servers report "stop" even when they emitted tool calls,
// so the presence of tool calls wins.
func openAIStop(finish, refusal string, hasToolCalls bool) (StopReason, Refusal) {
	if refusal != "" {
		return StopRefusal, Refusal{Category: "refusal", Explanation: refusal}
	}
	switch {
	case finish == "length":
		return StopMaxTokens, Refusal{}
	case finish == "content_filter":
		return StopRefusal, Refusal{Category: "content_filter", Explanation: "response blocked by the provider's content filter"}
	case finish == "tool_calls" || finish == "function_call" || hasToolCalls:
		return StopToolUse, Refusal{}
	default:
		return StopEnd, Refusal{}
	}
}

// rawArgs turns a tool call's arguments string into JSON, defaulting to an
// empty object when a server sends nothing.
func rawArgs(args string) json.RawMessage {
	if strings.TrimSpace(args) == "" {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(args)
}
