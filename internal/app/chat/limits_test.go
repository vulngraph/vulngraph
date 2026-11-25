package chat

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/llm"
)

func TestTrimHistory(t *testing.T) {
	u, a := llm.UserText, llm.AssistantText
	l := Limits{MaxHistoryMessages: 3, MaxHistoryBytes: 10}

	got, trimmed, err := trimHistory([]llm.Message{u("q1"), a("a1"), u("q2")}, l)
	require.NoError(t, err)
	require.False(t, trimmed)
	require.Len(t, got, 3)

	got, trimmed, err = trimHistory([]llm.Message{u("q1"), a("a1"), u("q2"), a("a2"), u("q3")}, l)
	require.NoError(t, err)
	require.True(t, trimmed)
	require.Equal(t, []llm.Message{u("q2"), a("a2"), u("q3")}, got, "the newest turns, by count")

	got, _, err = trimHistory([]llm.Message{u("q1"), a("aaaaaa"), u("qqqq")}, l)
	require.NoError(t, err)
	require.Equal(t, []llm.Message{u("qqqq")}, got, "by bytes; never opening on an assistant turn")

	_, _, err = trimHistory([]llm.Message{u(strings.Repeat("x", 11))}, l)
	require.ErrorIs(t, err, ErrMessageTooLarge)
}

// A partial configuration keeps the other defaults: nothing is uncapped by
// leaving it unset, and the turn's budget stays inside the handler's hard cap.
func TestWithLimits_KeepsDefaultsAndTheHardCap(t *testing.T) {
	s := NewService(nil, nil, nil, nil).WithLimits(Limits{MaxTokens: 1000, Timeout: time.Hour})
	require.EqualValues(t, 1000, s.limits.MaxTokens)
	require.Equal(t, DefaultLimits.MaxToolCalls, s.limits.MaxToolCalls)
	require.Equal(t, DefaultLimits.MaxHistoryBytes, s.limits.MaxHistoryBytes)
	require.Less(t, s.limits.Timeout, streamTimeout)
}

// The token budget ends a turn with a note, before the next model call.
func TestStream_StopsAtTheTokenBudget(t *testing.T) {
	client := &fakeLLM{turns: []fakeTurn{
		{resp: &llm.Response{StopReason: llm.StopToolUse, Usage: llm.Usage{InputTokens: 900, Reported: true},
			ToolCalls: []llm.ToolCall{{ID: "c", Name: "get_compliance", Input: []byte(`{}`)}}}},
		{resp: &llm.Response{Text: "never", StopReason: llm.StopEnd}},
	}}
	svc := NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{}).WithLimits(Limits{MaxTokens: 500})
	out, err := streamTurns(t, svc, "")
	require.NoError(t, err)
	require.Len(t, client.reqs, 1)
	require.Contains(t, out, "token budget")
}

func TestStream_StopsAtTheToolCallCap(t *testing.T) {
	call := llm.ToolCall{ID: "c", Name: "get_compliance", Input: []byte(`{}`)}
	client := &fakeLLM{turns: []fakeTurn{toolTurn(call, call, call), {resp: &llm.Response{StopReason: llm.StopEnd}}}}
	svc := NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{}).WithLimits(Limits{MaxToolCalls: 2})
	out, err := streamTurns(t, svc, "")
	require.NoError(t, err)
	require.Contains(t, out, "tool-call limit")
}

// Old turns past the cap never reach the model.
func TestStream_SendsTrimmedHistory(t *testing.T) {
	client := &fakeLLM{turns: []fakeTurn{{resp: &llm.Response{Text: "ok", StopReason: llm.StopEnd}}}}
	svc := NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{}).WithLimits(Limits{MaxHistoryMessages: 1})
	msgs := []Message{{Role: "user", Content: "old"}, {Role: "assistant", Content: "old answer"}, {Role: "user", Content: "new"}}
	require.NoError(t, svc.Stream(context.Background(), msgs, "", func(string) {}))
	require.Equal(t, []llm.Message{llm.UserText("new")}, client.reqs[0].Messages)
}

// The page context rides outside the history, so it has its own cap.
func TestChatStream_OversizedPageContextIs400(t *testing.T) {
	big := strings.Repeat("x", DefaultLimits.MaxContextBytes+1)
	client := &fakeLLM{}
	rec := serveChat(t, client, `{"messages":[{"role":"user","content":"q"}],"context":"`+big+`"}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, client.reqs, "nothing was sent to the model")
}

func TestChatStream_OversizedMessageIs400(t *testing.T) {
	big := strings.Repeat("x", DefaultLimits.MaxHistoryBytes+1)
	rec := serveChat(t, &fakeLLM{}, `{"messages":[{"role":"user","content":"`+big+`"}]}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
