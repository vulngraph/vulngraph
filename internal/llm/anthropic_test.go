package llm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/stretchr/testify/require"
)

// newTestAnthropic points the anthropic backend at an httptest server that
// writes the given SSE events (each a pair: event name, data JSON).
func newTestAnthropic(t *testing.T, events ...[2]string) *anthropicClient {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, ev := range events {
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev[0], ev[1])
		}
	}))
	t.Cleanup(srv.Close)
	return newAnthropic(Config{Provider: ProviderAnthropic, APIKey: "k", BaseURL: srv.URL, Model: DefaultAnthropicModel})
}

var (
	evMessageStart = [2]string{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}`}
	evBlockStart   = [2]string{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`}
	evDeltaHel     = [2]string{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hel"}}`}
	evBlockStop    = [2]string{"content_block_stop", `{"type":"content_block_stop","index":0}`}
	evMessageStop  = [2]string{"message_stop", `{"type":"message_stop"}`}
)

func TestAnthropicStream_Complete(t *testing.T) {
	c := newTestAnthropic(t, evMessageStart, evBlockStart, evDeltaHel, evBlockStop,
		[2]string{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}`},
		evMessageStop)
	var deltas []string
	resp, err := c.Stream(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 10}, func(s string) { deltas = append(deltas, s) })
	require.NoError(t, err)
	require.Equal(t, []string{"Hel"}, deltas)
	require.Equal(t, "Hel", resp.Text)
	require.Equal(t, StopEnd, resp.StopReason)
}

// A provider error after some text must come back as an error together with
// the partial text — not as nil, and not as a complete reply.
func TestAnthropicStream_ErrorAfterPartialText(t *testing.T) {
	c := newTestAnthropic(t, evMessageStart, evBlockStart, evDeltaHel,
		[2]string{"error", `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`})
	resp, err := c.Stream(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 10}, nil)
	require.ErrorContains(t, err, "Overloaded")
	require.NotNil(t, resp)
	require.Equal(t, "Hel", resp.Text)
}

func TestAnthropicStream_CutBeforeMessageStopIsAnError(t *testing.T) {
	c := newTestAnthropic(t, evMessageStart, evBlockStart, evDeltaHel)
	resp, err := c.Stream(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 10}, nil)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, "Hel", resp.Text)
}

// The empty assistant turn a failed chat turn leaves behind must not reach
// Anthropic as a zero-block message (400 on every later turn).
func TestToAnthropicMessages_DropsEmptyTurns(t *testing.T) {
	msgs := toAnthropicMessages([]Message{UserText("q1"), AssistantText(""), UserText("q2")})
	require.Len(t, msgs, 1)
	require.Equal(t, anthropic.MessageParamRoleUser, msgs[0].Role)
	require.Equal(t, "q1\n\nq2", msgs[0].Content[0].OfText.Text)
}

func TestToAnthropicMessages_ToolResultsLeadUserContent(t *testing.T) {
	msgs := toAnthropicMessages([]Message{{
		Role:        RoleUser,
		Text:        "and also",
		ToolResults: []ToolResult{{CallID: "tu_1", Content: "ok"}},
	}})
	require.Len(t, msgs[0].Content, 2)
	require.NotNil(t, msgs[0].Content[0].OfToolResult)
	require.NotNil(t, msgs[0].Content[1].OfText)
}

var testSchema = map[string]any{
	"type":                 "object",
	"properties":           map[string]any{"a": map[string]any{"type": "string"}},
	"required":             []string{"a"},
	"additionalProperties": false,
}

func reasoningReq(schema map[string]any) Request {
	return Request{
		System:     []SystemBlock{{Text: "sys", Cache: true}},
		Messages:   []Message{UserText("usr")},
		MaxTokens:  2048,
		JSONSchema: schema,
		Reasoning:  &Reasoning{MaxTokens: 8192},
	}
}

// claude-opus-4-8 runs without thinking when Thinking is left unset, so a
// Reasoning request on it must never be skippable by accident.
func TestBuildAnthropicParams_SchemaSetsOutputConfigFormat(t *testing.T) {
	params, skipped := buildAnthropicParams("claude-opus-4-8", reasoningReq(testSchema))
	require.Equal(t, testSchema, params.OutputConfig.Format.Schema)
	require.False(t, skipped, "claude-opus-4-8 accepts adaptive thinking")
}

func TestBuildAnthropicParams_NilSchemaLeavesOutputConfigUnset(t *testing.T) {
	params, _ := buildAnthropicParams("claude-opus-4-8", Request{Messages: []Message{UserText("u")}, MaxTokens: 2048})
	require.Nil(t, params.OutputConfig.Format.Schema)
}

// Forcing Thinking:{type:"adaptive"} unconditionally would 400 on tiers that
// don't accept it (Haiku 4.5, Sonnet 4.5, Opus 4.5 and earlier) — reachable
// because model env overrides accept any string.
func TestBuildAnthropicParams_SkipsThinkingForUnsupportedModel(t *testing.T) {
	params, skipped := buildAnthropicParams("claude-haiku-4-5-20251001", reasoningReq(testSchema))
	require.Nil(t, params.Thinking.OfAdaptive, "claude-haiku-4-5 rejects {type:\"adaptive\"} with a 400")
	require.True(t, skipped, "the skip must be reported so callers can log it")
	require.EqualValues(t, 2048, params.MaxTokens,
		"a model that isn't getting thinking has no reason to get the larger, thinking-sized budget")
}

func TestBuildAnthropicParams_EnablesThinkingForDefaultModel(t *testing.T) {
	params, skipped := buildAnthropicParams(DefaultAnthropicModel, reasoningReq(testSchema))
	require.NotNilf(t, params.Thinking.OfAdaptive,
		"DefaultAnthropicModel (%q) must accept adaptive thinking", DefaultAnthropicModel)
	require.EqualValues(t, 8192, params.MaxTokens, "thinking shares the budget, so the reasoning budget applies")
	require.False(t, skipped)
}

// A request without Reasoning (the NL translators) must be completely
// unaffected: no Thinking config and its own, smaller budget.
func TestBuildAnthropicParams_NoReasoningLeavesThinkingAndTokensUnchanged(t *testing.T) {
	params, skipped := buildAnthropicParams(DefaultAnthropicModel, Request{Messages: []Message{UserText("u")}, MaxTokens: 2048})
	require.Nil(t, params.Thinking.OfAdaptive)
	require.EqualValues(t, 2048, params.MaxTokens)
	require.False(t, skipped, "no reasoning requested means nothing to skip")
}

func TestBuildAnthropicParams_CacheFlagSetsCacheControl(t *testing.T) {
	params, _ := buildAnthropicParams(DefaultAnthropicModel, Request{
		System:    []SystemBlock{{Text: "stable", Cache: true}, {Text: "per-request"}},
		Messages:  []Message{UserText("u")},
		MaxTokens: 10,
	})
	require.Len(t, params.System, 2)
	require.Equal(t, anthropic.CacheControlEphemeralTTLTTL5m, params.System[0].CacheControl.TTL)
	require.Empty(t, params.System[1].CacheControl.TTL, "uncached blocks must not carry cache_control")
}

func TestBuildAnthropicParams_ToolsAndToolTurns(t *testing.T) {
	params, _ := buildAnthropicParams(DefaultAnthropicModel, Request{
		Messages: []Message{
			UserText("q"),
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "tu_1", Name: "get_asset", Input: []byte(`{"id":"x"}`)}}},
			{Role: RoleUser, ToolResults: []ToolResult{{CallID: "tu_1", Content: "ok"}}},
		},
		Tools: []Tool{{Name: "get_asset", Description: "d", InputSchema: map[string]any{
			"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}, "required": []any{"id"},
		}}},
		MaxTokens: 10,
	})
	require.Len(t, params.Tools, 1)
	require.Equal(t, []string{"id"}, params.Tools[0].OfTool.InputSchema.Required)
	require.Len(t, params.Messages, 3)
	require.Equal(t, anthropic.MessageParamRoleAssistant, params.Messages[1].Role)
	require.NotNil(t, params.Messages[1].Content[0].OfToolUse)
	require.Equal(t, "tu_1", params.Messages[2].Content[0].OfToolResult.ToolUseID)
}

func TestFromAnthropicMessage_StopReasons(t *testing.T) {
	p := anthropic.MessageNewParams{Model: "m", MaxTokens: 8192}

	r := fromAnthropicMessage(&anthropic.Message{StopReason: anthropic.StopReasonMaxTokens}, p)
	require.Equal(t, StopMaxTokens, r.StopReason)
	require.EqualValues(t, 8192, r.MaxTokens)

	r = fromAnthropicMessage(&anthropic.Message{
		StopReason:  anthropic.StopReasonRefusal,
		StopDetails: anthropic.RefusalStopDetails{Category: "cyber", Explanation: "policy"},
	}, p)
	require.Equal(t, StopRefusal, r.StopReason)
	require.Equal(t, "cyber", r.Refusal.Category)
}

// A ThinkingBlock ahead of the TextBlock must not pollute the extracted text.
func TestFromAnthropicMessage_SkipsThinkingBlockText(t *testing.T) {
	r := fromAnthropicMessage(&anthropic.Message{
		StopReason: anthropic.StopReasonEndTurn,
		Content: []anthropic.ContentBlockUnion{
			{Type: "thinking", Thinking: "reasoning about the finding..."},
			{Type: "text", Text: `{"ok":true}`},
		},
	}, anthropic.MessageNewParams{})
	require.Equal(t, `{"ok":true}`, r.Text)
	require.Equal(t, StopEnd, r.StopReason)
}

// The rule is family/version, not an exact list: a current model missing from
// a hand-kept list (claude-opus-5-5 once was) silently lost thinking, and a
// tier that rejects {type:"adaptive"} must never get it.
func TestSupportsAdaptiveThinking(t *testing.T) {
	for _, tt := range []struct {
		model string
		want  bool
	}{
		{"claude-opus-5-5", true},
		{"claude-sonnet-5-5", true},
		{"claude-fable-5-1", true},
		{"claude-fable-5", true},
		{"claude-mythos-5-1", true},
		{"claude-opus-5", true},
		{"claude-sonnet-5", true},
		{"claude-opus-4-8", true},
		{"claude-opus-4-7", true},
		{"claude-opus-4-6", true},
		{"claude-sonnet-4-6", true},
		{"claude-opus-6", true},                  // a future release, no edit needed
		{"claude-opus-4-6-20260101", true},       // dated snapshot
		{"anthropic.claude-opus-5-5", true},      // Bedrock prefix
		{"us.anthropic.claude-sonnet-5-5", true}, // Bedrock cross-region prefix
		{"claude-opus-4-6@20260101", true},       // Vertex snapshot separator
		{"claude-opus-4-8[1m]", true},
		{"anthropic/claude-opus-5-5", true}, // OpenRouter-style
		{"anthropic/claude-opus-4.8", true}, // OpenRouter dotted version
		{"anthropic/claude-haiku-4.5", false},
		{"claude-haiku-4-5", false},
		{"claude-haiku-4-5-20251001", false},
		{"claude-sonnet-4-5", false},
		{"claude-opus-4-5", false},
		{"claude-opus-4-1", false},
		{"claude-opus-4-20250514", false}, // the 8-digit part is a date, not minor 20250514
		{"claude-3-5-sonnet-20241022", false},
		{"claude", false},
		{"gpt-5", false},
		{"", false},
	} {
		require.Equal(t, tt.want, supportsAdaptiveThinking(tt.model), tt.model)
	}
}

func TestDefaultModels(t *testing.T) {
	require.Equal(t, "claude-opus-5-5", DefaultAnthropicModel)
	require.Equal(t, "claude-haiku-4-5", DefaultAnthropicFastModel)
	require.True(t, supportsAdaptiveThinking(DefaultAnthropicModel))
}
