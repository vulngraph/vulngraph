package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestOpenAI(t *testing.T, h http.HandlerFunc) (*openAIClient, *[]map[string]any) {
	t.Helper()
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/chat/completions", r.URL.Path)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		bodies = append(bodies, body)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c := newOpenAI(Config{Provider: ProviderOpenAI, BaseURL: srv.URL + "/v1", Model: "m-big", FastModel: "m-small", APIKey: "k"})
	return c, &bodies
}

func TestOpenAI_CompleteTextAndRequestShape(t *testing.T) {
	c, bodies := newTestOpenAI(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer k", r.Header.Get("Authorization"))
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"{\"a\":\"x\"}"},"finish_reason":"stop"}]}`)
	})
	resp, err := c.Complete(context.Background(), Request{
		System:     []SystemBlock{{Text: "one", Cache: true}, {Text: "two"}},
		Messages:   []Message{UserText("hi")},
		MaxTokens:  100,
		JSONSchema: testSchema,
	})
	require.NoError(t, err)
	require.Equal(t, `{"a":"x"}`, resp.Text)
	require.Equal(t, StopEnd, resp.StopReason)

	b := (*bodies)[0]
	require.Equal(t, "m-big", b["model"])
	require.EqualValues(t, 100, b["max_tokens"], "non-OpenAI-hosted servers get max_tokens")
	msgs := b["messages"].([]any)
	require.Equal(t, "one\n\ntwo", msgs[0].(map[string]any)["content"], "system blocks join into one system message")
	rf := b["response_format"].(map[string]any)
	require.Equal(t, "json_schema", rf["type"])
}

func TestOpenAI_FastTierAndReasoningEffort(t *testing.T) {
	c, bodies := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`)
	})
	_, err := c.Complete(context.Background(), Request{Tier: TierFast, Messages: []Message{UserText("x")}, MaxTokens: 5})
	require.NoError(t, err)
	require.Equal(t, "m-small", (*bodies)[0]["model"])
	require.NotContains(t, (*bodies)[0], "reasoning_effort")

	c.cfg.ReasoningEffort = "high"
	_, err = c.Complete(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 5, Reasoning: &Reasoning{MaxTokens: 50}})
	require.NoError(t, err)
	require.Equal(t, "high", (*bodies)[1]["reasoning_effort"])
	require.EqualValues(t, 50, (*bodies)[1]["max_tokens"])
}

func TestOpenAI_MaxCompletionTokensOnOpenAIHost(t *testing.T) {
	c := newOpenAI(Config{Provider: ProviderOpenAI, BaseURL: "https://api.openai.com/v1", Model: "m"})
	body, _ := c.buildOpenAIRequest(Request{Messages: []Message{UserText("x")}, MaxTokens: 7}, false)
	require.EqualValues(t, 7, body.MaxCompletionTokens)
	require.Zero(t, body.MaxTokens)
}

func TestOpenAI_ToolCallRoundTrip(t *testing.T) {
	c, bodies := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"get_asset","arguments":"{\"id\":\"i-1\"}"}}]},"finish_reason":"tool_calls"}]}`)
	})
	resp, err := c.Complete(context.Background(), Request{
		Messages: []Message{
			UserText("q"),
			{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "call_0", Name: "list_findings", Input: []byte(`{}`)}}},
			{Role: RoleUser, ToolResults: []ToolResult{{CallID: "call_0", Content: "[]"}, {CallID: "call_x", Content: "boom", IsError: true}}},
		},
		Tools:     []Tool{{Name: "get_asset", InputSchema: map[string]any{"type": "object"}}},
		MaxTokens: 10,
	})
	require.NoError(t, err)
	require.Equal(t, StopToolUse, resp.StopReason)
	require.Len(t, resp.ToolCalls, 1)
	require.Equal(t, "call_1", resp.ToolCalls[0].ID)
	require.JSONEq(t, `{"id":"i-1"}`, string(resp.ToolCalls[0].Input))

	msgs := (*bodies)[0]["messages"].([]any)
	require.Len(t, msgs, 4, "user, assistant(tool_calls), tool, tool")
	require.Equal(t, "tool", msgs[2].(map[string]any)["role"])
	require.Equal(t, "call_0", msgs[2].(map[string]any)["tool_call_id"])
	require.Equal(t, "ERROR: boom", msgs[3].(map[string]any)["content"])
	tools := (*bodies)[0]["tools"].([]any)
	require.Equal(t, "get_asset", tools[0].(map[string]any)["function"].(map[string]any)["name"])
}

func TestOpenAI_StreamTextAndToolCalls(t *testing.T) {
	c, _ := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, chunk := range []string{
			`{"choices":[{"delta":{"content":"Hel"}}]}`,
			`{"choices":[{"delta":{"content":"lo"}}]}`,
			`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"run_cypher","arguments":"{\"que"}}]}}]}`,
			`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ry\":\"MATCH\"}"}}]}}]}`,
			`{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`,
		} {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	})
	var deltas []string
	resp, err := c.Stream(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 10}, func(s string) { deltas = append(deltas, s) })
	require.NoError(t, err)
	require.Equal(t, []string{"Hel", "lo"}, deltas)
	require.Equal(t, "Hello", resp.Text)
	require.Equal(t, StopToolUse, resp.StopReason)
	require.Len(t, resp.ToolCalls, 1)
	require.JSONEq(t, `{"query":"MATCH"}`, string(resp.ToolCalls[0].Input))
}

func TestOpenAI_StopMapping(t *testing.T) {
	r, _ := openAIStop("length", "", false)
	require.Equal(t, StopMaxTokens, r)
	r, ref := openAIStop("stop", "I can't help with that", false)
	require.Equal(t, StopRefusal, r)
	require.Equal(t, "I can't help with that", ref.Explanation)
	r, _ = openAIStop("content_filter", "", false)
	require.Equal(t, StopRefusal, r)
	r, _ = openAIStop("stop", "", true)
	require.Equal(t, StopToolUse, r, "tool calls win over a server that reports stop")
}

func TestOpenAI_ErrorStatusIsSurfaced(t *testing.T) {
	c, _ := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":{"message":"bad key"}}`)
	})
	_, err := c.Complete(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 1})
	require.ErrorContains(t, err, "401")
	require.ErrorContains(t, err, "bad key")
}

func TestOpenAI_AzureHostAlsoSendsAPIKeyHeader(t *testing.T) {
	require.True(t, newOpenAI(Config{BaseURL: "https://res.openai.azure.com/openai/v1"}).isAzure())
	require.False(t, newOpenAI(Config{BaseURL: "https://api.openai.com/v1"}).isAzure())
}

// A hosted model server may sit behind an egress proxy, so the OpenAI-compatible
// client is the one internal client that honours HTTPS_PROXY/HTTP_PROXY.
func TestOpenAI_HonoursProxyEnvironment(t *testing.T) {
	tr, ok := newOpenAI(Config{BaseURL: "https://api.openai.com/v1"}).http.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.Proxy)
}

// sseServer returns a test client whose stream endpoint writes body verbatim.
func sseServer(t *testing.T, body string) *openAIClient {
	t.Helper()
	c, _ := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, body)
	})
	return c
}

func streamX(t *testing.T, c *openAIClient) (*Response, error) {
	t.Helper()
	return c.Stream(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 10}, nil)
}

func TestOpenAI_StreamMidStreamErrorChunk(t *testing.T) {
	for name, errJSON := range map[string]string{
		"object": `{"error":{"message":"upstream overloaded","type":"server_error"}}`,
		"string": `{"error":"model crashed"}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := sseServer(t, "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"+
				"data: "+errJSON+"\n\n")
			resp, err := streamX(t, c)
			require.ErrorContains(t, err, "provider error")
			require.NotNil(t, resp)
			require.Equal(t, "Hel", resp.Text, "the partial text comes back with the error")
		})
	}
}

func TestOpenAI_StreamCutWithoutDoneIsAnError(t *testing.T) {
	c := sseServer(t, "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n")
	resp, err := streamX(t, c)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, "Hel", resp.Text)
}

func TestOpenAI_StreamFinishReasonWithoutDoneIsComplete(t *testing.T) {
	c := sseServer(t, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n")
	resp, err := streamX(t, c)
	require.NoError(t, err)
	require.Equal(t, StopEnd, resp.StopReason)
}

func TestOpenAI_StreamToolCallsWithoutIndex(t *testing.T) {
	c := sseServer(t, strings.Join([]string{
		// id, no index: a new call keyed by id.
		`data: {"choices":[{"delta":{"tool_calls":[{"id":"a","function":{"name":"get_asset","arguments":"{\"id\""}}]}}]}`,
		// neither: continues the latest call.
		`data: {"choices":[{"delta":{"tool_calls":[{"function":{"arguments":":\"x\"}"}}]}}]}`,
		// a second call by id, then a continuation of the FIRST by id.
		`data: {"choices":[{"delta":{"tool_calls":[{"id":"b","function":{"name":"list_findings","arguments":"{}"}}]}}]}`,
		`data: {"choices":[{"delta":{"tool_calls":[{"id":"a","function":{"arguments":""}}]}}]}`,
		`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`,
		`data: [DONE]`,
	}, "\n\n")+"\n\n")
	resp, err := streamX(t, c)
	require.NoError(t, err)
	require.Len(t, resp.ToolCalls, 2)
	require.Equal(t, "a", resp.ToolCalls[0].ID)
	require.JSONEq(t, `{"id":"x"}`, string(resp.ToolCalls[0].Input))
	require.Equal(t, "b", resp.ToolCalls[1].ID)
	require.Equal(t, "list_findings", resp.ToolCalls[1].Name)
}

func TestOpenAI_StreamMultiLineDataEvent(t *testing.T) {
	c := sseServer(t, ": keep-alive comment\n"+
		"data: {\"choices\":[{\"delta\":\n"+
		"data: {\"content\":\"joined\"}}]}\n\n"+
		"event: done\ndata: [DONE]")
	resp, err := streamX(t, c)
	require.NoError(t, err)
	require.Equal(t, "joined", resp.Text)
}

func TestOpenAI_CompleteSurfacesInBandError(t *testing.T) {
	c, _ := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"error":{"message":"rate limited by upstream"}}`)
	})
	_, err := c.Complete(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 1})
	require.ErrorContains(t, err, "rate limited by upstream")
}

// Without LLM_REASONING_EFFORT the backend can't enable reasoning; that's a
// deploy-wide setting logged once at construction, not a per-call skip (which
// would make the reason package warn on every call).
func TestOpenAI_ReasoningWithoutEffortIsNotReportedSkipped(t *testing.T) {
	c, _ := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`)
	})
	resp, err := c.Complete(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 5, Reasoning: &Reasoning{MaxTokens: 50}})
	require.NoError(t, err)
	require.False(t, resp.ReasoningSkipped)
}

func TestOpenAI_EmptyAssistantTurnIsNotSent(t *testing.T) {
	c := newOpenAI(Config{Provider: ProviderOpenAI, BaseURL: "http://localhost:1/v1", Model: "m"})
	body, _ := c.buildOpenAIRequest(Request{Messages: []Message{UserText("q1"), AssistantText(""), UserText("q2")}}, false)
	require.Len(t, body.Messages, 1)
	require.Equal(t, "q1\n\nq2", *body.Messages[0].Content)
}
