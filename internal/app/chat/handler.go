package chat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/sse"
)

// streamTimeout bounds one chat turn — the whole agentic tool loop. /api/chat
// is exempt from the server's per-request deadline, so this is its only cap.
const streamTimeout = 10 * time.Minute

// streamFailedMsg is all a client is told about a failed turn; the cause is
// logged (it can carry provider error bodies).
const streamFailedMsg = "the AI provider request failed — try again"

// budgetExhaustedMsg names a budget refusal (llmusage), which retrying cannot fix.
const budgetExhaustedMsg = "the monthly AI budget for chat is spent — an admin can raise LLM_INTERACTIVE_MONTHLY_BUDGET_USD"

// Handler is the HTTP transport for the chat domain.
type Handler struct {
	svc *Service
}

// NewHandler constructs a Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Stream handles POST /api/chat. It accepts a ChatRequest JSON body and
// responds with a text/event-stream in the pkg/sse protocol. A turn that
// fails before anything was streamed gets an RFC 9457 error status instead;
// one that fails mid-stream ends with an error event and no done.
func (h *Handler) Stream(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), streamTimeout)
	defer cancel()
	logger := log.FromContext(ctx)

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be valid JSON"))
		return
	}

	if len(req.Messages) == 0 {
		errs.WriteHTTPError(w, errs.InvalidInput(ErrEmptyMessages.Error()))
		return
	}

	// Margin past streamTimeout so a turn that hits it can still send its
	// error event before the connection's write deadline.
	sse.ExtendWriteDeadline(ctx, w, streamTimeout+15*time.Second)

	out := sse.NewWriter(w)
	err := h.svc.Stream(ctx, req.Messages, req.Context, out.Text)
	switch {
	case err == nil:
		out.Done()
	case errors.Is(err, ErrEmptyMessages):
		errs.WriteHTTPError(w, errs.InvalidInput(ErrEmptyMessages.Error()))
	case errors.Is(err, ErrMessageTooLarge), errors.Is(err, ErrContextTooLarge):
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
	case errors.Is(err, context.Canceled):
		// The client went away; there is no one to tell.
	case errors.Is(err, llm.ErrBudgetExceeded):
		logger.Warn().Err(err).Msg("chat: refused by the LLM budget")
		if !out.Started() {
			errs.WriteHTTPError(w, errs.Unavailable(budgetExhaustedMsg))
			return
		}
		out.Error(budgetExhaustedMsg)
	default:
		logger.Error().Err(err).Bool("mid_stream", out.Started()).Msg("chat: stream failed")
		if !out.Started() {
			errs.WriteHTTPError(w, errs.Unavailable(streamFailedMsg))
			return
		}
		out.Error(streamFailedMsg)
	}
}
