package toolloop

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/llm"
)

// slowTools records peak concurrency; "gate" is serial and "boom" panics.
type slowTools struct {
	inFlight, peak atomic.Int32
	serialShared   atomic.Bool
	mu             sync.Mutex
	order          []string
}

func (s *slowTools) Tools() []llm.Tool {
	return []llm.Tool{{Name: "read"}, {Name: "gate"}, {Name: "boom"}}
}

func (s *slowTools) Serial(name string) bool { return name == "gate" }

func (s *slowTools) Call(_ context.Context, name string, input json.RawMessage) (string, bool) {
	n := s.inFlight.Add(1)
	defer s.inFlight.Add(-1)
	for p := s.peak.Load(); n > p && !s.peak.CompareAndSwap(p, n); p = s.peak.Load() {
	}
	if name == "gate" && n != 1 {
		s.serialShared.Store(true)
	}
	if name == "boom" {
		panic("tool bug")
	}
	time.Sleep(30 * time.Millisecond)
	s.mu.Lock()
	s.order = append(s.order, string(input))
	s.mu.Unlock()
	return "ok " + string(input), false
}

func tc(id, name string) llm.ToolCall {
	return llm.ToolCall{ID: id, Name: name, Input: json.RawMessage(`"` + id + `"`)}
}

func TestParallelToolCallsKeepOrderAndRespectSerial(t *testing.T) {
	client := &scripted{t: t, turns: []*llm.Response{
		toolUse(used(1, 1), tc("a", "read"), tc("b", "read"), tc("c", "gate"), tc("d", "read"), tc("e", "boom")),
		{StopReason: llm.StopEnd, Text: "done"},
	}}
	tools := &slowTools{}
	var seen []string
	tr, err := Run(context.Background(), client, llm.Request{}, tools,
		Limits{MaxIterations: 4, MaxParallelTools: 4}, Observer{Tool: func(s Step) { seen = append(seen, s.Call.ID) }})
	require.NoError(t, err)
	require.Equal(t, StopDone, tr.Stop)
	require.Equal(t, 5, tr.ToolCalls)
	require.Equal(t, []string{"a", "b", "c", "d", "e"}, seen, "observer sees calls in requested order")
	require.Equal(t, int32(2), tools.peak.Load(), "a and b ran together; the serial gate split the turn")
	require.False(t, tools.serialShared.Load(), "a serial tool runs alone")

	results := tr.Messages[len(tr.Messages)-2].ToolResults
	require.Len(t, results, 5)
	for i, id := range []string{"a", "b", "c", "d", "e"} {
		require.Equal(t, id, results[i].CallID)
	}
	require.True(t, results[4].IsError, "a panicking tool answers its own call as an error")
}

func TestRunBatchPanickingToolFailsOnlyItsOwnCall(t *testing.T) {
	tools := &slowTools{}
	offered := map[string]bool{"read": true, "boom": true}
	steps := runBatch(context.Background(), tools, offered, []llm.ToolCall{tc("a", "read"), tc("b", "boom"), tc("c", "read")})

	require.Len(t, steps, 3)
	for i, want := range []struct {
		id      string
		result  string
		isError bool
	}{
		{"a", `ok "a"`, false},
		{"b", `tool "boom" failed: internal error`, true},
		{"c", `ok "c"`, false},
	} {
		require.Equal(t, want.id, steps[i].Call.ID)
		require.Equal(t, want.result, steps[i].Result)
		require.Equal(t, want.isError, steps[i].IsError, "call %s", want.id)
		require.Positive(t, steps[i].Duration, "call %s", want.id)
	}
}

func TestParallelBatchNeverOvershootsToolCap(t *testing.T) {
	client := &scripted{t: t, turns: []*llm.Response{
		toolUse(used(1, 1), tc("a", "read"), tc("b", "read"), tc("c", "read")),
	}}
	tr, err := Run(context.Background(), client, llm.Request{}, &slowTools{},
		Limits{MaxIterations: 4, MaxToolCalls: 2, MaxParallelTools: 8}, Observer{})
	require.NoError(t, err)
	require.Equal(t, StopToolCalls, tr.Stop)
	require.Equal(t, 2, tr.ToolCalls)
	require.Len(t, tr.Messages[len(tr.Messages)-1].ToolResults, 2, "the calls that ran are still answered")
}

func TestWrapUpNudgesAndRefusesFurtherTools(t *testing.T) {
	client := &scripted{t: t, turns: []*llm.Response{
		toolUse(used(1, 1), tc("a", "read")),
		toolUse(used(1, 1), tc("b", "read")),
		toolUse(used(1, 1), tc("c", "read")),
		{StopReason: llm.StopEnd, Text: "answer"},
	}}
	tools := &slowTools{}
	tr, err := Run(context.Background(), client, llm.Request{System: []llm.SystemBlock{{Text: "sys", Cache: true}}}, tools,
		Limits{MaxIterations: 4, WrapUp: 0.5}, Observer{})
	require.NoError(t, err)
	require.Equal(t, StopDone, tr.Stop)
	require.True(t, tr.WrappedUp)
	require.Equal(t, 2, tr.ToolCalls, "calls asked for after the wrap-up are not run")
	require.Equal(t, []string{`"a"`, `"b"`}, tools.order)

	for i, req := range client.reqs {
		require.Equal(t, "sys", req.System[0].Text, "the cached block is untouched")
		require.Len(t, req.Tools, 3, "the tool list never changes, so the prompt cache still hits")
		wrapped := len(req.System) == 2 && req.System[1].Text == WrapUpNote
		require.Equal(t, i >= 2, wrapped, "call %d", i)
	}
	refused := tr.Messages[len(tr.Messages)-2].ToolResults
	require.Len(t, refused, 1)
	require.True(t, refused[0].IsError)
}

func TestWrapUpOffByDefault(t *testing.T) {
	require.False(t, Limits{MaxIterations: 2}.wrapUpReached(&Transcript{Iterations: 2}, time.Now()))
	require.True(t, Limits{MaxIterations: 4, WrapUp: 0.75}.wrapUpReached(&Transcript{Iterations: 3}, time.Now()))
	require.False(t, Limits{MaxIterations: 4, WrapUp: 0.75}.wrapUpReached(&Transcript{Iterations: 2}, time.Now()))
}
