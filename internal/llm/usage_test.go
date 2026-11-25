package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnthropicStream_ReportsFinalUsage(t *testing.T) {
	c := newTestAnthropic(t,
		[2]string{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":120,"output_tokens":1,"cache_read_input_tokens":900,"cache_creation_input_tokens":30}}}`},
		evBlockStart, evDeltaHel, evBlockStop,
		[2]string{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":42}}`},
		evMessageStop)
	resp, err := c.Stream(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 10}, nil)
	require.NoError(t, err)
	require.Equal(t, Usage{InputTokens: 120, OutputTokens: 42, CacheReadTokens: 900, CacheWriteTokens: 30, Reported: true}, resp.Usage)
	require.EqualValues(t, 1092, resp.Usage.Total())
}

// message_start's output count is a placeholder: a stream cut before
// message_delta has no final usage, and must say so.
func TestAnthropicStream_CutBeforeDeltaIsUnreported(t *testing.T) {
	c := newTestAnthropic(t, evMessageStart, evBlockStart, evDeltaHel)
	resp, err := c.Stream(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 10}, nil)
	require.Error(t, err)
	require.False(t, resp.Usage.Reported)
}

func TestAnthropicComplete_ReportsUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":7,"output_tokens":3,"cache_read_input_tokens":5,"cache_creation_input_tokens":0}}`)
	}))
	t.Cleanup(srv.Close)
	c := newAnthropic(Config{Provider: ProviderAnthropic, APIKey: "k", BaseURL: srv.URL, Model: DefaultAnthropicModel})
	resp, err := c.Complete(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 10})
	require.NoError(t, err)
	require.Equal(t, Usage{InputTokens: 7, OutputTokens: 3, CacheReadTokens: 5, Reported: true}, resp.Usage)
}

// prompt_tokens includes the cached part on the OpenAI wire; Usage keeps the
// classes disjoint so a price table charges each once.
func TestOpenAI_CompleteReportsDisjointUsage(t *testing.T) {
	c, _ := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":9,"prompt_tokens_details":{"cached_tokens":60}}}`)
	})
	resp, err := c.Complete(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 5})
	require.NoError(t, err)
	require.Equal(t, Usage{InputTokens: 40, OutputTokens: 9, CacheReadTokens: 60, Reported: true}, resp.Usage)
}

func TestOpenAI_CompleteWithoutUsageIsUnreported(t *testing.T) {
	c, _ := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}]}`)
	})
	resp, err := c.Complete(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 5})
	require.NoError(t, err)
	require.Equal(t, Usage{}, resp.Usage)
}

func TestOpenAI_StreamAsksForAndReadsFinalUsageChunk(t *testing.T) {
	c, bodies := newTestOpenAI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":2}}\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	})
	resp, err := c.Stream(context.Background(), Request{Messages: []Message{UserText("x")}, MaxTokens: 5}, nil)
	require.NoError(t, err)
	require.Equal(t, Usage{InputTokens: 11, OutputTokens: 2, Reported: true}, resp.Usage)
	require.Equal(t, map[string]any{"include_usage": true}, (*bodies)[0]["stream_options"])
}

func TestOpenAI_StreamWithoutUsageChunkIsUnreported(t *testing.T) {
	c := sseServer(t, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	resp, err := streamX(t, c)
	require.NoError(t, err)
	require.False(t, resp.Usage.Reported)
}

func TestChargeableUsage(t *testing.T) {
	req := Request{
		System:    []SystemBlock{{Text: "abcdef"}},
		Messages:  []Message{UserText("abc")},
		MaxTokens: 100,
	}
	reported := Usage{InputTokens: 1, OutputTokens: 2, Reported: true}
	for _, tc := range []struct {
		name string
		req  Request
		resp *Response
		want Usage
	}{
		{"reported usage is charged as reported", req, &Response{Usage: reported}, reported},
		{"unreported charges every byte and the whole output budget", req, &Response{}, Usage{InputTokens: 3, OutputTokens: 100}},
		{"a failed call is charged the worst case", req, nil, Usage{InputTokens: 3, OutputTokens: 100}},
		{"the larger budget the backend used wins", req, &Response{MaxTokens: 4000}, Usage{InputTokens: 3, OutputTokens: 4000}},
		{"a reasoning budget counts", Request{MaxTokens: 10, Reasoning: &Reasoning{MaxTokens: 50}}, nil, Usage{OutputTokens: 50}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ChargeableUsage(tc.req, tc.resp))
		})
	}
}

func TestOpenAI_CompleteSendsNoStreamOptions(t *testing.T) {
	c := newOpenAI(Config{Provider: ProviderOpenAI, BaseURL: "http://localhost:1/v1", Model: "m"})
	body, _ := c.buildOpenAIRequest(Request{Messages: []Message{UserText("x")}}, false)
	require.Nil(t, body.StreamOptions)
}
