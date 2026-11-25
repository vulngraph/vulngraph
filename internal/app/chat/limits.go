package chat

import (
	"errors"
	"time"

	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/internal/llm/toolloop"
	"github.com/vulngraph/vulngraph/pkg/querybudget"
)

// Limits caps one chat turn beyond the iteration ceiling. The client holds
// the conversation and resends all of it every turn, and every iteration of
// the tool loop resends it again, so a long history multiplies cost; these
// caps keep one turn's spend bounded however the conversation grew.
type Limits struct {
	// MaxTokens bounds the turn's chargeable tokens across every iteration
	// (toolloop.Limits.MaxTokens).
	MaxTokens int64
	// MaxToolCalls bounds tool executions in the turn.
	MaxToolCalls int
	// Timeout is the turn's wall-clock budget. Reaching it ends the turn with
	// a note, inside the handler's hard streamTimeout.
	Timeout time.Duration
	// MaxHistoryMessages and MaxHistoryBytes bound the conversation sent to
	// the model; older turns are dropped first.
	MaxHistoryMessages int
	MaxHistoryBytes    int
	// MaxContextBytes bounds the page context, which is sent outside the
	// history and so is not covered by MaxHistoryBytes.
	MaxContextBytes int
}

// DefaultLimits is used unless configured otherwise (CHAT_* in cmd/graph).
var DefaultLimits = Limits{
	MaxTokens:          500_000,
	MaxToolCalls:       24,
	Timeout:            5 * time.Minute,
	MaxHistoryMessages: 40,
	MaxHistoryBytes:    200_000,
	MaxContextBytes:    8_000,
}

// ErrMessageTooLarge rejects a turn whose latest user message alone exceeds
// MaxHistoryBytes: it cannot be trimmed without changing the question.
var ErrMessageTooLarge = errors.New("chat: the message is too long")

// ErrContextTooLarge rejects a page context over MaxContextBytes. It is a
// compact description of what is on screen; anything larger is not one.
var ErrContextTooLarge = errors.New("chat: the page context is too long")

// WithLimits replaces DefaultLimits. A zero field keeps its default, so a
// partial configuration never silently uncaps the rest.
func (s *Service) WithLimits(l Limits) *Service {
	d := DefaultLimits
	if l.MaxTokens > 0 {
		d.MaxTokens = l.MaxTokens
	}
	if l.MaxToolCalls > 0 {
		d.MaxToolCalls = l.MaxToolCalls
	}
	if l.Timeout > 0 {
		// The handler's streamTimeout is the hard stop; the budget ends the
		// turn first, so it can still say why.
		d.Timeout = min(l.Timeout, streamTimeout-time.Minute)
	}
	if l.MaxHistoryMessages > 0 {
		d.MaxHistoryMessages = l.MaxHistoryMessages
	}
	if l.MaxHistoryBytes > 0 {
		d.MaxHistoryBytes = l.MaxHistoryBytes
	}
	if l.MaxContextBytes > 0 {
		d.MaxContextBytes = l.MaxContextBytes
	}
	s.limits = d
	return s
}

// loopLimits is the toolloop form of the turn's caps.
func (l Limits) loopLimits(now time.Time) toolloop.Limits {
	return toolloop.Limits{
		MaxIterations: maxChatIterations,
		MaxToolCalls:  l.MaxToolCalls,
		MaxTokens:     l.MaxTokens,
		Deadline:      now.Add(l.Timeout),
		// Independent read tools in one turn run together; live tools stay
		// serial (chatTools.Serial) so their gate and audit keep their order.
		MaxParallelTools: chatParallelTools,
		// At 80% of any cap the model is told to answer from what it has,
		// instead of being cut off mid-investigation at the hard cap.
		WrapUp: chatWrapUp,
	}
}

const (
	chatParallelTools = 4
	chatWrapUp        = 0.8
)

// toolQueryBudget bounds every database query one chat tool call runs. An
// LLM picks the arguments, so a question can resolve to an expensive scan;
// this keeps it from holding a ClickHouse slot (or the server) for minutes.
// The server-side max_execution_time sits under the client timeout so the
// server reports the overrun as an error the model can read.
var toolQueryBudget = querybudget.Budget{Timeout: 30 * time.Second, MaxExecutionTime: 25}

// trimHistory keeps the newest turns within both history caps. The result
// starts with a user turn (providers reject a conversation that opens with
// the assistant) and always ends with the latest one. trimmed reports
// whether anything was dropped.
func trimHistory(history []llm.Message, l Limits) (out []llm.Message, trimmed bool, err error) {
	if len(history) == 0 {
		return history, false, nil
	}
	last := history[len(history)-1]
	if len(last.Text) > l.MaxHistoryBytes {
		return nil, false, ErrMessageTooLarge
	}
	start, size := len(history)-1, len(last.Text)
	for start > 0 && len(history)-start < l.MaxHistoryMessages && size+len(history[start-1].Text) <= l.MaxHistoryBytes {
		start--
		size += len(history[start].Text)
	}
	for start < len(history)-1 && history[start].Role != llm.RoleUser {
		start++
	}
	return history[start:], start > 0, nil
}

// limitNote is the visible explanation for a turn a cap ended.
func limitNote(stop toolloop.Stop) string {
	switch stop {
	case toolloop.StopIterations, toolloop.StopToolCalls:
		return "\n\n_Stopped after reaching the tool-call limit for one turn. Ask a follow-up to continue._"
	case toolloop.StopTokens:
		return "\n\n_Stopped after reaching the token budget for one turn. Ask a follow-up to continue._"
	case toolloop.StopDeadline:
		return "\n\n_Stopped after reaching the time limit for one turn. Ask a follow-up to continue._"
	}
	return ""
}
