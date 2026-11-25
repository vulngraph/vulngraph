package llmusage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Handler serves the LLM usage summary.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// SummaryResponse is the wire shape of GET /api/llm/usage. Money is in USD;
// a budget of 0 means unlimited.
type SummaryResponse struct {
	Month                     string         `json:"month"`
	Since                     time.Time      `json:"since"`
	Until                     time.Time      `json:"until"`
	MonthlyBudgetUSD          float64        `json:"monthly_budget_usd"`
	InteractiveBudgetUSD      float64        `json:"interactive_budget_usd"`
	UserDailyBudgetUSD        float64        `json:"user_daily_budget_usd"`
	UserMonthlyBudgetUSD      float64        `json:"user_monthly_budget_usd"`
	SpentUSD                  float64        `json:"spent_usd"`
	InteractiveSpentUSD       float64        `json:"interactive_spent_usd"`
	BackgroundSpentUSD        float64        `json:"background_spent_usd"`
	UnrecordedUSD             float64        `json:"unrecorded_usd"`
	DefaultPriceUsedForModels []string       `json:"default_price_used_for_models"`
	Lines                     []LineResponse `json:"lines"`
}

// LineResponse is one purpose × model row.
type LineResponse struct {
	Purpose          string  `json:"purpose"`
	Model            string  `json:"model"`
	Interactive      bool    `json:"interactive"`
	Calls            int64   `json:"calls"`
	UnreportedCalls  int64   `json:"unreported_calls"`
	FailedCalls      int64   `json:"failed_calls"`
	InputTokens      int64   `json:"input_tokens"`
	OutputTokens     int64   `json:"output_tokens"`
	CacheReadTokens  int64   `json:"cache_read_tokens"`
	CacheWriteTokens int64   `json:"cache_write_tokens"`
	CostUSD          float64 `json:"cost_usd"`
}

// Summary handles GET /api/llm/usage?month=YYYY-MM (default: this month).
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	sum, err := h.svc.Summary(r.Context(), r.URL.Query().Get("month"))
	switch {
	case err == nil:
	case errors.Is(err, ErrInvalidMonth):
		errs.WriteHTTPError(w, errs.InvalidInput("month must be YYYY-MM"))
		return
	default:
		log.FromContext(r.Context()).Error().Err(err).Msg("llm usage summary failed")
		errs.WriteHTTPError(w, errs.Internal("failed to summarize LLM usage"))
		return
	}
	resp := SummaryResponse{
		Month:                     sum.Month,
		Since:                     sum.Since,
		Until:                     sum.Until,
		MonthlyBudgetUSD:          usd(sum.Budget.MonthlyMicroUSD),
		InteractiveBudgetUSD:      usd(sum.Budget.InteractiveMicroUSD),
		UserDailyBudgetUSD:        usd(sum.Budget.UserDailyMicroUSD),
		UserMonthlyBudgetUSD:      usd(sum.Budget.UserMonthlyMicroUSD),
		SpentUSD:                  usd(sum.TotalMicroUSD),
		InteractiveSpentUSD:       usd(sum.InteractiveMicroUSD),
		BackgroundSpentUSD:        usd(sum.TotalMicroUSD - sum.InteractiveMicroUSD),
		UnrecordedUSD:             usd(sum.UnrecordedMicroUSD),
		DefaultPriceUsedForModels: append([]string{}, sum.DefaultPriceUsedForModels...),
		Lines:                     make([]LineResponse, len(sum.Lines)),
	}
	for i, l := range sum.Lines {
		resp.Lines[i] = LineResponse{
			Purpose:          string(l.Purpose),
			Model:            l.Model,
			Interactive:      l.Interactive,
			Calls:            l.Calls,
			UnreportedCalls:  l.UnreportedCalls,
			FailedCalls:      l.FailedCalls,
			InputTokens:      l.InputTokens,
			OutputTokens:     l.OutputTokens,
			CacheReadTokens:  l.CacheReadTokens,
			CacheWriteTokens: l.CacheWriteTokens,
			CostUSD:          usd(l.CostMicroUSD),
		}
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

func usd(micro int64) float64 { return float64(micro) / 1e6 }

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
