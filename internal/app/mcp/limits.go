package mcp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/llm"
)

// Limiter is a per-key token bucket. *auth.KeyedLimiter implements it.
type Limiter interface {
	Allow(key string) (bool, time.Duration)
}

// limitClass names the per-user budget a tool spends from. /api/mcp is one
// route serving cheap and expensive tools alike, so the limit is per tool,
// not per route: graph_query makes up to two LLM calls, and
// get_alert_context runs an unindexed attribute scan.
type limitClass int

const (
	limitNone limitClass = iota
	// limitLLM shares the /api/chat per-user LLM limiter: one budget per
	// user across every LLM-backed surface.
	limitLLM
	// limitAlertContext shares the POST /api/context/alert limiter.
	limitAlertContext
	// limitScanStart is its own budget: each call queues a real scan run.
	limitScanStart
	// limitCypher shares the REST Cypher-pool routes' per-user limiter: caller
	// Cypher runs on a two-connection pool that scheduled detections also use.
	limitCypher
)

// codeRateLimited is server-defined: the caller's per-user budget for this
// tool is spent (or the LLM spend budget is).
const codeRateLimited = -32029

// WithLimits wires the per-user limiters the costly tools spend from. A tool
// whose limiter is not wired is refused, never run unlimited.
func (h *Handler) WithLimits(llmLimiter, alertContext Limiter) *Handler {
	h.setLimiter(limitLLM, llmLimiter)
	h.setLimiter(limitAlertContext, alertContext)
	return h
}

// WithScanLimit wires the per-user limiter start_profile_scan spends from.
func (h *Handler) WithScanLimit(l Limiter) *Handler {
	h.setLimiter(limitScanStart, l)
	return h
}

// WithCypherLimit wires the per-user limiter run_cypher spends from.
func (h *Handler) WithCypherLimit(l Limiter) *Handler {
	h.setLimiter(limitCypher, l)
	return h
}

func (h *Handler) setLimiter(c limitClass, l Limiter) {
	if h.limiters == nil {
		h.limiters = map[limitClass]Limiter{}
	}
	h.limiters[c] = l
}

// checkLimit takes one token for the caller from the tool's limiter.
func (h *Handler) checkLimit(ctx context.Context, t tool) *rpcError {
	if t.limit == limitNone {
		return nil
	}
	l := h.limiters[t.limit]
	if l == nil {
		return &rpcError{Code: codeRateLimited, Message: "this tool's rate limit is not configured, so it is disabled"}
	}
	user, ok := auth.UserFromContext(ctx)
	if !ok || user.ID == "" {
		return &rpcError{Code: codeForbidden, Message: "an authenticated user is required"}
	}
	if allowed, wait := l.Allow(user.ID); !allowed {
		return &rpcError{Code: codeRateLimited,
			Message: fmt.Sprintf("rate limited: retry in %ds", max(1, int(math.Ceil(wait.Seconds()))))}
	}
	return nil
}

// budgetError maps an LLM budget refusal to an explicit error, rather than
// the generic "tool execution failed".
func budgetError(err error) *rpcError {
	switch {
	case errors.Is(err, llm.ErrBudgetExceeded):
		return &rpcError{Code: codeRateLimited, Message: "the LLM spend budget is exhausted"}
	case errors.Is(err, llm.ErrBudgetUnknown):
		return &rpcError{Code: codeRateLimited, Message: "the LLM spend budget cannot be checked right now"}
	}
	return nil
}
