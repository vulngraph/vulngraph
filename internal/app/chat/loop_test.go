package chat

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/promptfence"
)

// These tests pin the observable behaviour of Stream's tool loop end to end
// (requests sent, history built, results fenced, caps and notes emitted), so
// the loop can move to internal/llm/toolloop without chat changing.

func streamTurns(t *testing.T, svc *Service, pageContext string) (string, error) {
	t.Helper()
	var out strings.Builder
	err := svc.Stream(context.Background(), []Message{{Role: "user", Content: "q"}}, pageContext, func(s string) { out.WriteString(s) })
	return out.String(), err
}

func toolTurn(calls ...llm.ToolCall) fakeTurn {
	return fakeTurn{resp: &llm.Response{StopReason: llm.StopToolUse, ToolCalls: calls}}
}

func TestStream_RequestShape(t *testing.T) {
	client := &fakeLLM{turns: []fakeTurn{{deltas: []string{"ok"}, resp: &llm.Response{Text: "ok", StopReason: llm.StopEnd}}}}
	svc := NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{})
	_, err := streamTurns(t, svc, "Viewing asset i-1")
	require.NoError(t, err)
	require.Len(t, client.reqs, 1)
	req := client.reqs[0]
	require.EqualValues(t, maxTokens, req.MaxTokens)
	require.Len(t, req.System, 2)
	require.Equal(t, llm.SystemBlock{Text: systemPrompt, Cache: true}, req.System[0])
	require.Equal(t, pageContextBlock("Viewing asset i-1"), req.System[1])
	require.Equal(t, svc.toolDefs(), req.Tools)
	require.Equal(t, []llm.Message{llm.UserText("q")}, req.Messages)
}

// Every tool result reaches the model fenced — successes and errors alike —
// answering the assistant turn that asked for it, in call order.
func TestStream_ToolResultsAreFencedIntoTheNextRequest(t *testing.T) {
	client := &fakeLLM{turns: []fakeTurn{
		toolTurn(
			llm.ToolCall{ID: "c1", Name: "get_compliance", Input: []byte(`{}`)},
			llm.ToolCall{ID: "c2", Name: "terminate_instance", Input: []byte(`{}`)},
		),
		{deltas: []string{"done"}, resp: &llm.Response{Text: "done", StopReason: llm.StopEnd}},
	}}
	svc := NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{})
	out, err := streamTurns(t, svc, "")
	require.NoError(t, err)
	require.Equal(t, "done", out)
	require.Len(t, client.reqs, 2)

	msgs := client.reqs[1].Messages
	require.Len(t, msgs, 3, "user, assistant(tool calls), user(tool results)")
	require.Equal(t, llm.RoleAssistant, msgs[1].Role)
	require.Len(t, msgs[1].ToolCalls, 2)

	results := msgs[2].ToolResults
	require.Len(t, results, 2)
	compliance, _ := svc.callTool(context.Background(), "get_compliance", `{}`)
	require.Equal(t, llm.ToolResult{CallID: "c1", Content: promptfence.Fence(compliance)}, results[0])
	require.Equal(t, "c2", results[1].CallID)
	require.True(t, results[1].IsError)
	require.True(t, strings.HasPrefix(results[1].Content, promptfence.Open))
	require.True(t, strings.HasSuffix(results[1].Content, promptfence.Close))
}

func TestStream_StopsAtTheIterationCeiling(t *testing.T) {
	turns := make([]fakeTurn, maxChatIterations)
	for i := range turns {
		turns[i] = toolTurn(llm.ToolCall{ID: "c", Name: "get_compliance", Input: []byte(`{}`)})
	}
	client := &fakeLLM{turns: turns}
	out, err := streamTurns(t, NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{}), "")
	require.NoError(t, err)
	require.Len(t, client.reqs, maxChatIterations)
	require.Equal(t, "\n\n_Stopped after reaching the tool-call limit for one turn. Ask a follow-up to continue._", out)
}

func TestStream_MaxTokensCutIsVisible(t *testing.T) {
	client := &fakeLLM{turns: []fakeTurn{{deltas: []string{"partial"}, resp: &llm.Response{Text: "partial", StopReason: llm.StopMaxTokens}}}}
	out, err := streamTurns(t, NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{}), "")
	require.NoError(t, err)
	require.Equal(t, "partial\n\n_The reply was cut off at the output token limit. Ask a follow-up to continue._", out)
}

// Text streamed during a tool-calling iteration counts as emitted: the final
// empty turn then gets no "empty reply" note.
func TestStream_TextFromAnEarlierIterationCountsAsEmitted(t *testing.T) {
	client := &fakeLLM{turns: []fakeTurn{
		{deltas: []string{"checking"}, resp: &llm.Response{Text: "checking", StopReason: llm.StopToolUse, ToolCalls: []llm.ToolCall{{ID: "c1", Name: "get_compliance", Input: []byte(`{}`)}}}},
		{resp: &llm.Response{StopReason: llm.StopEnd}},
	}}
	out, err := streamTurns(t, NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{}), "")
	require.NoError(t, err)
	require.Equal(t, "checking", out)
	require.Equal(t, llm.Message{Role: llm.RoleAssistant, Text: "checking", ToolCalls: []llm.ToolCall{{ID: "c1", Name: "get_compliance", Input: []byte(`{}`)}}}, client.reqs[1].Messages[1])
}

// A tool-use stop with no calls is a finished turn, not a loop.
func TestStream_ToolUseWithoutCallsEnds(t *testing.T) {
	client := &fakeLLM{turns: []fakeTurn{{deltas: []string{"x"}, resp: &llm.Response{Text: "x", StopReason: llm.StopToolUse}}}}
	_, err := streamTurns(t, NewService(client, fakeDeps{}, fakeDeps{}, fakeDeps{}), "")
	require.NoError(t, err)
	require.Len(t, client.reqs, 1)
}

// A budget refusal is named, not reported as a provider failure to retry.
func TestChatStream_BudgetRefusalIsNamed(t *testing.T) {
	rec := serveChat(t, &fakeLLM{turns: []fakeTurn{{err: fmt.Errorf("Allow chat: %w", llm.ErrBudgetExceeded)}}}, oneQuestion)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Contains(t, rec.Body.String(), "monthly AI budget")
}
