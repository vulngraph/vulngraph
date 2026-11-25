package chat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/llm"
)

// fakeLLM streams each scripted turn in order: its text deltas, then its
// response or error.
type fakeLLM struct {
	turns []fakeTurn
	reqs  []llm.Request
}

type fakeTurn struct {
	deltas []string
	resp   *llm.Response
	err    error
}

func (f *fakeLLM) Complete(context.Context, llm.Request) (*llm.Response, error) {
	return nil, errors.New("not used")
}

func (f *fakeLLM) Stream(_ context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	f.reqs = append(f.reqs, req)
	turn := f.turns[len(f.reqs)-1]
	for _, d := range turn.deltas {
		onText(d)
	}
	return turn.resp, turn.err
}

func (f *fakeLLM) Provider() llm.Provider { return "fake" }

func serveChat(t *testing.T, client *fakeLLM, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewHandler(NewService(client, nil, nil, nil))
	rec := httptest.NewRecorder()
	h.Stream(rec, httptest.NewRequest(http.MethodPost, "/api/chat", strings.NewReader(body)))
	return rec
}

const oneQuestion = `{"messages":[{"role":"user","content":"hi"}]}`

func TestChatStream_Success(t *testing.T) {
	rec := serveChat(t, &fakeLLM{turns: []fakeTurn{{deltas: []string{"Hel", "lo"}, resp: &llm.Response{Text: "Hello", StopReason: llm.StopEnd}}}}, oneQuestion)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	require.Contains(t, rec.Body.String(), `"text":"Hel"`)
	require.True(t, strings.HasSuffix(rec.Body.String(), "data: {\"type\":\"done\"}\n\n"))
}

// A failure before any text must not look like an empty successful reply.
func TestChatStream_ErrorBeforeAnyTextIsAnErrorStatus(t *testing.T) {
	rec := serveChat(t, &fakeLLM{turns: []fakeTurn{{err: errors.New("anthropic: 400 secret provider detail")}}}, oneQuestion)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	require.NotContains(t, rec.Body.String(), "secret provider detail", "provider detail is logged, not sent")
}

// Tool-only first iteration streams nothing, so a failure on the second is
// still answerable with a status.
func TestChatStream_ErrorAfterToolOnlyIterationIsAnErrorStatus(t *testing.T) {
	rec := serveChat(t, &fakeLLM{turns: []fakeTurn{
		{resp: &llm.Response{StopReason: llm.StopToolUse, ToolCalls: []llm.ToolCall{{ID: "c1", Name: "nope", Input: []byte(`{}`)}}}},
		{err: errors.New("boom")},
	}}, oneQuestion)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestChatStream_ErrorMidStreamEndsWithErrorEventNotDone(t *testing.T) {
	rec := serveChat(t, &fakeLLM{turns: []fakeTurn{{deltas: []string{"Hel"}, resp: &llm.Response{Text: "Hel"}, err: errors.New("cut")}}}, oneQuestion)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	require.Contains(t, body, `"text":"Hel"`)
	require.Contains(t, body, `"type":"error"`)
	require.NotContains(t, body, `"type":"done"`)
}

func TestChatStream_RefusalIsVisible(t *testing.T) {
	rec := serveChat(t, &fakeLLM{turns: []fakeTurn{{resp: &llm.Response{
		StopReason: llm.StopRefusal,
		Refusal:    llm.Refusal{Category: "cyber", Explanation: "policy."},
	}}}}, oneQuestion)
	body := rec.Body.String()
	require.Contains(t, body, "declined to answer this request: policy._")
	require.Contains(t, body, `"type":"done"`)
}

func TestChatStream_EmptyReplyIsVisible(t *testing.T) {
	rec := serveChat(t, &fakeLLM{turns: []fakeTurn{{resp: &llm.Response{StopReason: llm.StopEnd}}}}, oneQuestion)
	require.Contains(t, rec.Body.String(), "empty reply")
}

func TestChatStream_DropsEmptyHistoryTurns(t *testing.T) {
	client := &fakeLLM{turns: []fakeTurn{{deltas: []string{"ok"}, resp: &llm.Response{Text: "ok"}}}}
	serveChat(t, client, `{"messages":[
		{"role":"user","content":"q1"},
		{"role":"assistant","content":""},
		{"role":"user","content":"q2"}]}`)
	require.Len(t, client.reqs, 1)
	require.Equal(t, []llm.Message{llm.UserText("q1"), llm.UserText("q2")}, client.reqs[0].Messages)
}

func TestChatStream_AllBlankHistoryIs400(t *testing.T) {
	rec := serveChat(t, &fakeLLM{}, `{"messages":[{"role":"assistant","content":" "}]}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
