package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/app/chat"
	"github.com/vulngraph/vulngraph/internal/app/llmusage"
	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// newLLMClient builds the configured LLM client (see llm.FromEnv for the env
// contract). No configuration at all returns (nil, nil): every LLM feature is
// optional and degrades to a 503 or a heuristic. A configuration that names a
// provider but is unusable fails startup loudly rather than at first use.
func newLLMClient(ctx context.Context, getenv func(string) string) (llm.Client, error) {
	cfg := llm.FromEnv(getenv)
	client, err := llm.New(cfg)
	if errors.Is(err, llm.ErrNotConfigured) {
		log.FromContext(ctx).Info().Msg("llm: no provider configured — reasoning, chat, NL query and AI template features are disabled")
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	log.FromContext(ctx).Info().
		Str("provider", string(cfg.Provider)).
		Str("model", cfg.Model).
		Str("fast_model", cfg.FastModel).
		Str("base_url", cfg.BaseURL).
		Msg("llm: provider configured")
	return client, nil
}

// newLLMUsage builds the spend ledger and monthly budget (ADR 085 §7):
//
//	LLM_MONTHLY_BUDGET_USD              cap on ALL LLM spend per calendar month (UTC);
//	                                    gates background work (reasoning, adjudication,
//	                                    CT triage, agents). 0 or unset = unlimited.
//	LLM_INTERACTIVE_MONTHLY_BUDGET_USD  cap on interactive spend only (chat, NL query,
//	                                    refine, template generation). 0 or unset = unlimited.
//	LLM_USER_DAILY_BUDGET_USD           cap on one user's interactive spend per UTC day.
//	LLM_USER_MONTHLY_BUDGET_USD         cap on one user's interactive spend per month.
//	                                    0 or unset = unlimited (both).
//	LLM_PRICES                          JSON price table, USD per million tokens.
//
// A malformed value fails startup: silently reading a typo'd budget as
// "unlimited" would fail open.
func newLLMUsage(ctx context.Context, pool *pgxpool.Pool, getenv func(string) string) (*llmusage.Service, error) {
	prices, err := llmusage.ParsePriceTable(getenv("LLM_PRICES"))
	if err != nil {
		return nil, err
	}
	monthly, err := budgetUSD(getenv, "LLM_MONTHLY_BUDGET_USD")
	if err != nil {
		return nil, err
	}
	interactive, err := budgetUSD(getenv, "LLM_INTERACTIVE_MONTHLY_BUDGET_USD")
	if err != nil {
		return nil, err
	}
	userDaily, err := budgetUSD(getenv, "LLM_USER_DAILY_BUDGET_USD")
	if err != nil {
		return nil, err
	}
	userMonthly, err := budgetUSD(getenv, "LLM_USER_MONTHLY_BUDGET_USD")
	if err != nil {
		return nil, err
	}
	budget := llmusage.Budget{MonthlyMicroUSD: monthly, InteractiveMicroUSD: interactive,
		UserDailyMicroUSD: userDaily, UserMonthlyMicroUSD: userMonthly}
	log.FromContext(ctx).Info().
		Float64("monthly_budget_usd", float64(monthly)/1e6).
		Float64("interactive_budget_usd", float64(interactive)/1e6).
		Float64("user_daily_budget_usd", float64(userDaily)/1e6).
		Float64("user_monthly_budget_usd", float64(userMonthly)/1e6).
		Int("priced_models", len(prices)).
		Msg("llm: usage ledger configured (0 = unlimited)")
	return llmusage.NewService(llmusage.NewPGRepo(pool), prices, budget), nil
}

// budgetUSD parses a non-negative dollar amount into micro-USD; unset is 0.
func budgetUSD(getenv func(string) string, key string) (int64, error) {
	raw := strings.TrimSpace(getenv(key))
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("budgetUSD: %s=%q is not a non-negative dollar amount", key, raw)
	}
	return llmusage.USDToMicro(v), nil
}

// chatLimitsFromEnv reads the per-turn chat caps; unset keeps
// chat.DefaultLimits. A malformed value fails startup rather than reading as
// "uncapped":
//
//	CHAT_MAX_TOKENS_PER_TURN      chargeable tokens across one turn's tool loop
//	CHAT_MAX_TOOL_CALLS_PER_TURN  tool executions in one turn
//	CHAT_TURN_TIMEOUT             wall-clock budget for one turn (Go duration)
//	CHAT_MAX_HISTORY_MESSAGES     newest conversation turns sent to the model
//	CHAT_MAX_HISTORY_BYTES        newest conversation text sent to the model
//	CHAT_MAX_CONTEXT_BYTES        page context (what the user has open)
func chatLimitsFromEnv(getenv func(string) string) (chat.Limits, error) {
	var l chat.Limits
	ints := []struct {
		key string
		set func(int64)
	}{
		{"CHAT_MAX_TOKENS_PER_TURN", func(v int64) { l.MaxTokens = v }},
		{"CHAT_MAX_TOOL_CALLS_PER_TURN", func(v int64) { l.MaxToolCalls = int(v) }},
		{"CHAT_MAX_HISTORY_MESSAGES", func(v int64) { l.MaxHistoryMessages = int(v) }},
		{"CHAT_MAX_HISTORY_BYTES", func(v int64) { l.MaxHistoryBytes = int(v) }},
		{"CHAT_MAX_CONTEXT_BYTES", func(v int64) { l.MaxContextBytes = int(v) }},
	}
	for _, e := range ints {
		raw := strings.TrimSpace(getenv(e.key))
		if raw == "" {
			continue
		}
		v, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || v <= 0 {
			return chat.Limits{}, fmt.Errorf("chatLimitsFromEnv: %s=%q is not a positive integer", e.key, raw)
		}
		e.set(v)
	}
	if raw := strings.TrimSpace(getenv("CHAT_TURN_TIMEOUT")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return chat.Limits{}, fmt.Errorf("chatLimitsFromEnv: CHAT_TURN_TIMEOUT=%q is not a positive duration", raw)
		}
		l.Timeout = d
	}
	return l, nil
}
