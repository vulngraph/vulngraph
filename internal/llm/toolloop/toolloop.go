// Package toolloop is the only multi-turn tool-calling loop (ADR 085 §4): any
// feature that lets the model call tools runs on it (today only chat;
// single-shot LLM calls do not). It calls the model, runs the tools it asks
// for, feeds the fenced results back, and repeats, under iteration, tool-call,
// token and wall-clock caps, stopping promptly on cancellation.
//
// It depends only on internal/llm and the shared prompt fence, never on a
// domain: callers bring their tools through a Dispatcher. Fencing happens
// here, inside the loop, so no caller can forget it.
package toolloop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/promptfence"
)

// Dispatcher supplies the tools offered for one run and executes them. Call
// returns the raw result and whether it is an error; the loop fences it.
type Dispatcher interface {
	Tools() []llm.Tool
	Call(ctx context.Context, name string, input json.RawMessage) (result string, isError bool)
}

// Serial is optionally implemented by a Dispatcher whose tools must not run
// concurrently with others (a tool that passes a live gate and writes an audit
// row in order). Tools it reports serial run alone, in their requested place.
type Serial interface {
	Serial(name string) bool
}

// Limits caps one run. MaxIterations is required: a loop with no iteration
// ceiling only ends when the model stops asking for tools, which an injected
// conversation can postpone indefinitely. The other caps are off at zero.
type Limits struct {
	// MaxIterations bounds model calls.
	MaxIterations int
	// MaxToolCalls bounds tool executions across the run.
	MaxToolCalls int
	// MaxTokens bounds the run's chargeable tokens (llm.ChargeableUsage, so a
	// call with no reported usage counts at its worst case).
	MaxTokens int64
	// Deadline bounds wall-clock time; reaching it ends the run as a budget
	// stop, not an error.
	Deadline time.Time
	// MaxParallelTools runs up to this many of one turn's tool calls at once
	// (0 or 1: one at a time). Results keep the requested order.
	MaxParallelTools int
	// WrapUp, in (0,1), starts the wrap-up once any cap is that fraction
	// spent: the model is told to answer from what it has, and tool calls it
	// still asks for are answered without running. The tool list is left
	// unchanged so the provider's prompt cache still hits. Zero disables it.
	WrapUp float64
}

// WrapUpNote is the system block added once the wrap-up starts, and
// wrapUpRefusal the result returned for a tool call made after it.
const (
	WrapUpNote    = "The budget for this turn is nearly spent. Do not call more tools: answer now from the results you already have, and say plainly what you could not check."
	wrapUpRefusal = "not run: the turn's budget is nearly spent. Answer from the results you already have."
)

// Step is one executed tool call. Result is the raw, unfenced result (what an
// audit row hashes); the model saw it fenced.
type Step struct {
	Call     llm.ToolCall
	Result   string
	IsError  bool
	Duration time.Duration
}

// Observer receives the run as it happens. Every field is optional.
type Observer struct {
	// Text gets each visible text delta as it streams.
	Text func(string)
	// Turn gets each completed model turn.
	Turn func(*llm.Response)
	// Tool gets each executed tool call.
	Tool func(Step)
}

// Stop is why a run ended without error.
type Stop string

const (
	// StopDone: the model finished (no tool calls requested).
	StopDone       Stop = "done"
	StopIterations Stop = "max_iterations"
	StopToolCalls  Stop = "max_tool_calls"
	StopTokens     Stop = "max_tokens"
	StopDeadline   Stop = "deadline"
)

// Transcript is what a run produced.
type Transcript struct {
	// Messages is the full conversation: the request's messages plus every
	// assistant turn and fenced tool-result turn the run added.
	Messages []llm.Message
	// Last is the final model response (nil if no call completed).
	Last       *llm.Response
	Iterations int
	ToolCalls  int
	// Usage sums llm.ChargeableUsage over every model call, failed ones
	// included. Reported is true only if every call reported its usage.
	Usage llm.Usage
	Stop  Stop
	// WrappedUp is true once the wrap-up started (Limits.WrapUp).
	WrappedUp bool
}

// ErrNoIterationLimit rejects a run with no iteration ceiling.
var ErrNoIterationLimit = errors.New("toolloop: Limits.MaxIterations must be positive")

// FenceResult wraps a tool result in the untrusted-content fence. Every tool
// result reaches live data an attacker may have chosen (a finding title, a
// resource tag, a CloudTrail user-agent string); JSON structure blocks a
// syntactic breakout but not a field value read as an instruction.
func FenceResult(callID, result string, isErr bool) llm.ToolResult {
	return llm.ToolResult{CallID: callID, Content: promptfence.Fence(result), IsError: isErr}
}

// Run executes the loop. req carries the system prompt, the conversation so
// far and the per-call MaxTokens; its Tools are replaced by d.Tools(). On
// error the Transcript still holds everything up to the failure, including a
// partial final response when the provider returned one.
func Run(ctx context.Context, client llm.Client, req llm.Request, d Dispatcher, lim Limits, obs Observer) (Transcript, error) {
	if lim.MaxIterations <= 0 {
		return Transcript{}, ErrNoIterationLimit
	}
	runCtx := ctx
	if !lim.Deadline.IsZero() {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithDeadline(ctx, lim.Deadline)
		defer cancel()
	}
	tools := d.Tools()
	offered := make(map[string]bool, len(tools))
	for _, t := range tools {
		offered[t.Name] = true
	}
	tr := Transcript{Messages: append([]llm.Message(nil), req.Messages...), Usage: llm.Usage{Reported: true}}
	serial, _ := d.(Serial)
	start := time.Now()

	for {
		if stop, err := tr.budgetStop(ctx, runCtx, lim); stop != "" || err != nil {
			tr.Stop = stop
			return tr, err
		}
		call := req
		call.Messages = tr.Messages
		call.Tools = tools
		if !tr.WrappedUp && lim.wrapUpReached(&tr, start) {
			tr.WrappedUp = true
		}
		if tr.WrappedUp {
			call.System = append(append([]llm.SystemBlock(nil), req.System...), llm.SystemBlock{Text: WrapUpNote})
		}
		resp, err := client.Stream(runCtx, call, obs.Text)
		tr.Iterations++
		tr.charge(llm.ChargeableUsage(call, resp))
		if resp != nil {
			tr.Last = resp
		}
		if err != nil {
			if deadlineHit(ctx, runCtx) {
				tr.Stop = StopDeadline
				return tr, nil
			}
			return tr, fmt.Errorf("toolloop: model call: %w", err)
		}
		if obs.Turn != nil {
			obs.Turn(resp)
		}
		tr.Messages = append(tr.Messages, llm.Message{Role: llm.RoleAssistant, Text: resp.Text, ToolCalls: resp.ToolCalls})
		if resp.StopReason != llm.StopToolUse || len(resp.ToolCalls) == 0 {
			tr.Stop = StopDone
			return tr, nil
		}
		if tr.WrappedUp {
			// Answer every call so the conversation stays well formed, run none.
			refused := make([]llm.ToolResult, 0, len(resp.ToolCalls))
			for _, tc := range resp.ToolCalls {
				refused = append(refused, FenceResult(tc.ID, wrapUpRefusal, true))
			}
			tr.appendResults(refused)
			continue
		}

		results := make([]llm.ToolResult, 0, len(resp.ToolCalls))
		for pending := resp.ToolCalls; len(pending) > 0; {
			if stop, err := tr.toolStop(ctx, runCtx, lim); stop != "" || err != nil {
				// The results gathered so far still answer their calls, so the
				// transcript stays a well-formed conversation for review.
				tr.appendResults(results)
				tr.Stop = stop
				return tr, err
			}
			batch := nextBatch(pending, serial, lim.batchSize(tr.ToolCalls))
			pending = pending[len(batch):]
			for _, step := range runBatch(runCtx, d, offered, batch) {
				tr.ToolCalls++
				if obs.Tool != nil {
					obs.Tool(step)
				}
				results = append(results, FenceResult(step.Call.ID, step.Result, step.IsError))
			}
		}
		tr.appendResults(results)
	}
}

// batchSize is how many calls may run together now: MaxParallelTools, cut to
// what MaxToolCalls still allows so a batch never overshoots the cap.
func (lim Limits) batchSize(done int) int {
	n := max(lim.MaxParallelTools, 1)
	if lim.MaxToolCalls > 0 {
		n = min(n, lim.MaxToolCalls-done)
	}
	return max(n, 1)
}

// wrapUpReached reports whether any cap is WrapUp spent.
func (lim Limits) wrapUpReached(tr *Transcript, start time.Time) bool {
	if lim.WrapUp <= 0 || lim.WrapUp >= 1 {
		return false
	}
	spent := func(used, limit float64) bool { return limit > 0 && used >= lim.WrapUp*limit }
	switch {
	case spent(float64(tr.Iterations), float64(lim.MaxIterations)):
		return true
	case spent(float64(tr.ToolCalls), float64(lim.MaxToolCalls)):
		return true
	case spent(float64(tr.Usage.Total()), float64(lim.MaxTokens)):
		return true
	case !lim.Deadline.IsZero() && spent(float64(time.Since(start)), float64(lim.Deadline.Sub(start))):
		return true
	}
	return false
}

// nextBatch takes the next run of calls that may execute together: a serial
// tool alone, otherwise up to size consecutive non-serial calls.
func nextBatch(pending []llm.ToolCall, serial Serial, size int) []llm.ToolCall {
	isSerial := func(tc llm.ToolCall) bool { return serial != nil && serial.Serial(tc.Name) }
	if isSerial(pending[0]) || size <= 1 {
		return pending[:1]
	}
	n := 1
	for n < len(pending) && n < size && !isSerial(pending[n]) {
		n++
	}
	return pending[:n]
}

// runBatch executes calls concurrently and returns their steps in order.
func runBatch(ctx context.Context, d Dispatcher, offered map[string]bool, batch []llm.ToolCall) []Step {
	steps := make([]Step, len(batch))
	if len(batch) == 1 {
		steps[0] = runOne(ctx, d, offered, batch[0])
		return steps
	}
	var wg sync.WaitGroup
	for i, tc := range batch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverStep(ctx, tc, &steps[i])
			steps[i] = runOne(ctx, d, offered, tc)
		}()
	}
	wg.Wait()
	return steps
}

func runOne(ctx context.Context, d Dispatcher, offered map[string]bool, tc llm.ToolCall) (step Step) {
	start := time.Now()
	step = Step{Call: tc}
	defer func() { step.Duration = time.Since(start) }()
	defer recoverStep(ctx, tc, &step)
	if offered[tc.Name] {
		step.Result, step.IsError = d.Call(ctx, tc.Name, tc.Input)
	} else {
		// A name the run never offered is refused before dispatch: the model
		// cannot widen its own tool set by guessing names.
		step.Result, step.IsError = fmt.Sprintf("tool %q is not available in this conversation", tc.Name), true
	}
	return step
}

// recoverStep turns a panicking tool into an error answer for its own call; it
// never takes down the turn, the calls running beside it, or the pod.
func recoverStep(ctx context.Context, tc llm.ToolCall, step *Step) {
	if r := recover(); r != nil {
		log.FromContext(ctx).Error().Interface("panic", r).Str("tool", tc.Name).Msg("toolloop: tool panicked")
		step.Call = tc
		step.Result, step.IsError = fmt.Sprintf("tool %q failed: internal error", tc.Name), true
	}
}

func (tr *Transcript) appendResults(results []llm.ToolResult) {
	if len(results) > 0 {
		tr.Messages = append(tr.Messages, llm.Message{Role: llm.RoleUser, ToolResults: results})
	}
}

func (tr *Transcript) charge(u llm.Usage) {
	tr.Usage.InputTokens += u.InputTokens
	tr.Usage.OutputTokens += u.OutputTokens
	tr.Usage.CacheReadTokens += u.CacheReadTokens
	tr.Usage.CacheWriteTokens += u.CacheWriteTokens
	tr.Usage.Reported = tr.Usage.Reported && u.Reported
}

// budgetStop is checked before every model call.
func (tr *Transcript) budgetStop(ctx, runCtx context.Context, lim Limits) (Stop, error) {
	if stop, err := checkContext(ctx, runCtx); stop != "" || err != nil {
		return stop, err
	}
	switch {
	case tr.Iterations >= lim.MaxIterations:
		return StopIterations, nil
	case lim.MaxTokens > 0 && tr.Usage.Total() >= lim.MaxTokens:
		return StopTokens, nil
	}
	return "", nil
}

// toolStop is checked before every tool call.
func (tr *Transcript) toolStop(ctx, runCtx context.Context, lim Limits) (Stop, error) {
	if stop, err := checkContext(ctx, runCtx); stop != "" || err != nil {
		return stop, err
	}
	if lim.MaxToolCalls > 0 && tr.ToolCalls >= lim.MaxToolCalls {
		return StopToolCalls, nil
	}
	return "", nil
}

// checkContext separates the caller's cancellation (an error) from the run's
// own deadline (a budget stop).
func checkContext(ctx, runCtx context.Context) (Stop, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("toolloop: %w", err)
	}
	if deadlineHit(ctx, runCtx) {
		return StopDeadline, nil
	}
	return "", nil
}

func deadlineHit(ctx, runCtx context.Context) bool {
	return ctx.Err() == nil && errors.Is(runCtx.Err(), context.DeadlineExceeded)
}
