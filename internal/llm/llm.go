// Package llm is the provider-neutral seam every LLM-backed feature calls
// through (remediation reasoning, the adjudicator, NL→query translation,
// chat, plan refinement, CT triage, nuclei template generation). It is the
// ONLY package that imports a provider SDK — depguard enforces that — so
// swapping or adding a provider never touches feature code.
//
// Two backends ship:
//
//   - anthropic: the Anthropic Messages API via the official Go SDK. Keeps the
//     provider-specific features the platform was tuned on (adaptive thinking,
//     prompt caching, server-side structured outputs, refusal stop details).
//   - openai: any OpenAI-compatible Chat Completions endpoint — OpenAI, Azure
//     OpenAI, OpenRouter, Ollama, vLLM, LiteLLM, Groq, Gemini's OpenAI
//     endpoint, … — selected with LLM_BASE_URL.
//
// Features describe WHAT they need (a JSON-schema-shaped reply, room to
// reason, a cheap model) and each backend maps that onto what its API offers.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// Provider names a backend.
type Provider string

const (
	ProviderAnthropic Provider = "anthropic"
	ProviderOpenAI    Provider = "openai"
)

// Tier picks a model when Request.Model is empty. Default is the capable model
// used for reasoning, chat and translation; Fast is the cheap one used for
// high-volume classification (CT-log triage).
type Tier int

const (
	TierDefault Tier = iota
	TierFast
)

// Role is a conversation turn's author.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// SystemBlock is one piece of the system prompt. Cache marks a stable prefix
// worth caching (honoured by backends that support explicit prompt caching;
// ignored elsewhere). Put cached blocks first: caching is prefix-based.
type SystemBlock struct {
	Text  string
	Cache bool
}

// Message is one conversation turn. An assistant turn carries Text and/or
// ToolCalls; a user turn carries Text and/or ToolResults answering the
// previous assistant turn's ToolCalls.
type Message struct {
	Role        Role
	Text        string
	ToolCalls   []ToolCall
	ToolResults []ToolResult
}

// UserText is a convenience constructor for a plain user turn.
func UserText(text string) Message { return Message{Role: RoleUser, Text: text} }

// AssistantText is a convenience constructor for a plain assistant turn.
func AssistantText(text string) Message { return Message{Role: RoleAssistant, Text: text} }

// Tool is a function the model may call. InputSchema is a JSON Schema object
// ({"type":"object","properties":{…},"required":[…]}).
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// ToolCall is the model's request to invoke a Tool. Input is the raw JSON
// arguments object.
type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// ToolResult answers a ToolCall by ID.
type ToolResult struct {
	CallID  string
	Content string
	IsError bool
}

// Reasoning asks the backend to let the model think before answering, with
// MaxTokens as the (larger) total budget to use when it does. Backends that
// cannot honour it for the selected model fall back to Request.MaxTokens and
// set Response.ReasoningSkipped.
type Reasoning struct {
	MaxTokens int64
}

// Request is one model call.
type Request struct {
	// Model overrides Tier when non-empty.
	Model     string
	Tier      Tier
	System    []SystemBlock
	Messages  []Message
	MaxTokens int64
	Tools     []Tool
	// JSONSchema, when non-nil, constrains the reply to a JSON value matching
	// it (server-side where the backend supports it). Callers must still
	// validate the decoded reply — not every backend enforces every keyword.
	JSONSchema map[string]any
	Reasoning  *Reasoning
}

// StopReason is why the model stopped.
type StopReason string

const (
	StopEnd       StopReason = "end"
	StopMaxTokens StopReason = "max_tokens"
	StopToolUse   StopReason = "tool_use"
	StopRefusal   StopReason = "refusal"
)

// Refusal carries the backend's explanation when StopReason is StopRefusal.
type Refusal struct {
	Category    string
	Explanation string
}

// Response is a completed model call (also returned by Stream once the
// stream ends).
type Response struct {
	// Text is the concatenated visible text (never thinking/reasoning text).
	Text       string
	ToolCalls  []ToolCall
	StopReason StopReason
	Refusal    Refusal
	// Model is the model id the request was sent to.
	Model string
	// MaxTokens is the budget this request actually used, so a truncation
	// error can name it.
	MaxTokens int64
	// ReasoningSkipped reports that Request.Reasoning was set but the backend
	// could not enable it for this model.
	ReasoningSkipped bool
	// Usage is the provider's token accounting for this call.
	Usage Usage
}

// Usage is the token accounting a provider reported for one call. The four
// counts are disjoint: InputTokens excludes cached input on every backend, so
// a price table can charge each class once.
type Usage struct {
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	// Reported is false when the provider sent no final usage — a server that
	// omits it, or a stream that ended before its usage event. The counts are
	// then not a measurement, and a meter must charge the request's worst case
	// rather than read them as a small spend.
	Reported bool
}

// Total is every token the call was billed for.
func (u Usage) Total() int64 {
	return u.InputTokens + u.OutputTokens + u.CacheReadTokens + u.CacheWriteTokens
}

// Client is a configured backend.
type Client interface {
	// Complete runs one request to completion.
	Complete(ctx context.Context, req Request) (*Response, error)
	// Stream runs one request, calling onText with each visible text delta as
	// it arrives, and returns the assembled Response at the end. A stream that
	// fails after it started (a mid-stream provider error, a connection cut
	// before the provider signalled completion) returns the error AND a
	// non-nil Response holding the text received so far — never a partial
	// reply dressed up as a complete one.
	Stream(ctx context.Context, req Request, onText func(string)) (*Response, error)
	// Provider names the backend (for logs and diagnostics).
	Provider() Provider
}

// ErrNotConfigured is returned by New when no provider is configured.
var ErrNotConfigured = errors.New("llm: no provider configured")

// A metering Client (internal/app/llmusage) refuses a call before it is made
// with one of these: the budget that governs the call is spent, or the spend
// could not be read and the call is not one a person is waiting on.
var (
	ErrBudgetExceeded = errors.New("llm: monthly budget exhausted")
	ErrBudgetUnknown  = errors.New("llm: budget_unknown: LLM spend could not be read")
)

// normalizeMessages drops turns that carry nothing (no non-blank text, tool
// calls or tool results) and merges the same-role neighbours dropping can
// leave behind. A failed or user-stopped chat turn leaves an empty assistant
// message in client-held history; sent as-is, Anthropic rejects it (every
// message needs a non-blank content block) and every later turn of that
// conversation 400s. Both backends send the normalized list.
func normalizeMessages(msgs []Message) []Message {
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		if strings.TrimSpace(m.Text) == "" {
			m.Text = ""
		}
		if m.Text == "" && len(m.ToolCalls) == 0 && len(m.ToolResults) == 0 {
			continue
		}
		if n := len(out); n > 0 && out[n-1].Role == m.Role {
			prev := &out[n-1]
			switch {
			case prev.Text == "":
				prev.Text = m.Text
			case m.Text != "":
				prev.Text += "\n\n" + m.Text
			}
			prev.ToolCalls = append(prev.ToolCalls, m.ToolCalls...)
			prev.ToolResults = append(prev.ToolResults, m.ToolResults...)
			continue
		}
		// Copy the slices so a later merge never appends into the caller's.
		m.ToolCalls = append([]ToolCall(nil), m.ToolCalls...)
		m.ToolResults = append([]ToolResult(nil), m.ToolResults...)
		out = append(out, m)
	}
	return out
}
