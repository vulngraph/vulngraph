// Package llmusage is the LLM spend ledger and monthly budget (ADR 085 §7).
// Every model call from any feature is recorded with its tokens and an
// estimated cost, and a call is refused before it is made when the budget
// that governs its purpose is spent — or, for unattended work, when the
// spend cannot be read at all.
package llmusage

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/llm"
)

// Purpose names the feature a model call serves. It decides which budget
// applies: interactive purposes (a person is waiting on the reply) are capped
// only by the interactive budget, so unattended spend can never cut a user off
// (ADR 085); every other purpose is background work, capped by the global monthly budget over ALL
// spend and refused when that spend is unknown.
type Purpose string

const (
	PurposeChat        Purpose = "chat"
	PurposeNLQuery     Purpose = "nl_query"
	PurposeRefine      Purpose = "refine"
	PurposeTemplateGen Purpose = "template_gen" // Historical usage only; template generation is retired.
	PurposeReason      Purpose = "reason"
	PurposeAdjudicate  Purpose = "adjudicate"
	PurposeCTTriage    Purpose = "ct_triage"
	// PurposeDriftAnalysis is background: an unattended sweep, never in
	// interactivePurposes.
	PurposeDriftAnalysis Purpose = "drift_analysis"
)

// interactivePurposes is the positive list; anything not on it — including a
// purpose added later and forgotten here — is background and fails closed.
var interactivePurposes = map[Purpose]bool{
	PurposeChat:        true,
	PurposeNLQuery:     true,
	PurposeRefine:      true,
	PurposeTemplateGen: true,
}

// Interactive reports whether a person is waiting on calls of this purpose.
func (p Purpose) Interactive() bool { return interactivePurposes[p] }

// ErrBudgetExceeded and ErrBudgetUnknown wrap the llm package's sentinels, so
// any caller of an llm.Client can recognise a budget refusal without
// importing this package.
var (
	ErrBudgetExceeded = fmt.Errorf("llmusage: %w", llm.ErrBudgetExceeded)
	ErrBudgetUnknown  = fmt.Errorf("llmusage: %w", llm.ErrBudgetUnknown)
	ErrInvalidMonth   = errors.New("llmusage: month must be YYYY-MM")
)

// Record is one model call in the ledger. When Usage.Reported is false the
// token counts are the worst-case charge (llm.ChargeableUsage), not a report.
type Record struct {
	Purpose Purpose
	// UserID is the user whose request made the call; "" for unattended work.
	UserID       string
	Provider     string
	Model        string
	Usage        llm.Usage
	Failed       bool
	CostMicroUSD int64
}

// Spend is the ledger total since a point in time.
type Spend struct {
	TotalMicroUSD       int64
	InteractiveMicroUSD int64
}

// Line is one purpose × model row of a usage summary.
type Line struct {
	Purpose          Purpose
	Model            string
	Interactive      bool
	Calls            int64
	UnreportedCalls  int64
	FailedCalls      int64
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
	CostMicroUSD     int64
}

// Summary is a calendar month of usage against the configured budgets.
type Summary struct {
	Month                     string
	Since, Until              time.Time
	Budget                    Budget
	TotalMicroUSD             int64
	InteractiveMicroUSD       int64
	Lines                     []Line
	UnrecordedMicroUSD        int64
	DefaultPriceUsedForModels []string
}

// Budget is the spend policy. Zero means unlimited for any cap.
type Budget struct {
	// MonthlyMicroUSD caps ALL spend this month; it gates background purposes.
	MonthlyMicroUSD int64
	// InteractiveMicroUSD caps interactive spend this month; it gates
	// interactive purposes, which background spend never counts against.
	InteractiveMicroUSD int64
	// UserDailyMicroUSD and UserMonthlyMicroUSD cap one user's interactive
	// spend per UTC day and calendar month. Interactive spend counts toward
	// the total that halts background work, so without them one viewer could
	// drain both budgets for everyone.
	UserDailyMicroUSD   int64
	UserMonthlyMicroUSD int64
}

// UserSpend is one user's ledger total this month and today.
type UserSpend struct {
	MonthMicroUSD int64
	DayMicroUSD   int64
}

// DayStart is the first instant of t's UTC day.
func DayStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// Price is USD per million tokens for each token class.
type Price struct {
	Input      float64  `json:"input"`
	Output     float64  `json:"output"`
	CacheRead  *float64 `json:"cache_read,omitempty"`
	CacheWrite *float64 `json:"cache_write,omitempty"`
}

// DefaultPrice is charged for any model the price table does not name. It is
// a deliberate over-estimate, not any vendor's list price: an unpriced model
// should hit the budget early rather than late. Set LLM_PRICES for accurate
// figures, including {"*":{"input":0,"output":0}} for a free local model.
var DefaultPrice = Price{Input: 15, Output: 75}

// PriceTable maps model ids (or id prefixes) to prices. The key "*" replaces
// DefaultPrice.
type PriceTable map[string]Price

// ParsePriceTable reads LLM_PRICES: a JSON object of model → Price. Empty is a
// valid, empty table (every model at DefaultPrice).
func ParsePriceTable(raw string) (PriceTable, error) {
	if strings.TrimSpace(raw) == "" {
		return PriceTable{}, nil
	}
	var t PriceTable
	if err := json.Unmarshal([]byte(raw), &t); err != nil {
		return nil, fmt.Errorf("ParsePriceTable: LLM_PRICES is not a JSON object of model prices: %w", err)
	}
	for model, p := range t {
		for _, v := range []*float64{&p.Input, &p.Output, p.CacheRead, p.CacheWrite} {
			if v != nil && (*v < 0 || math.IsNaN(*v) || math.IsInf(*v, 0)) {
				return nil, fmt.Errorf("ParsePriceTable: LLM_PRICES[%q] has a negative or non-finite price", model)
			}
		}
	}
	return t, nil
}

// Lookup returns the price for model: an exact key, else the longest key that
// prefixes it (so "claude-opus-4" prices dated variants), else "*", else
// DefaultPrice. known is false when the default was used.
func (t PriceTable) Lookup(model string) (p Price, known bool) {
	if p, ok := t[model]; ok && model != "*" {
		return p, true
	}
	best := ""
	for k := range t {
		if k != "*" && strings.HasPrefix(model, k) && len(k) > len(best) {
			best = k
		}
	}
	if best != "" {
		return t[best], true
	}
	if p, ok := t["*"]; ok {
		return p, true
	}
	return DefaultPrice, false
}

// CostMicroUSD prices u. A cache class without its own price is charged
// conservatively: cache reads at the input price, cache writes at twice it.
func (p Price) CostMicroUSD(u llm.Usage) int64 {
	cacheRead, cacheWrite := p.Input, 2*p.Input
	if p.CacheRead != nil {
		cacheRead = *p.CacheRead
	}
	if p.CacheWrite != nil {
		cacheWrite = *p.CacheWrite
	}
	// USD per million tokens × tokens = micro-USD.
	micro := p.Input*float64(u.InputTokens) +
		p.Output*float64(u.OutputTokens) +
		cacheRead*float64(u.CacheReadTokens) +
		cacheWrite*float64(u.CacheWriteTokens)
	return int64(math.Ceil(micro))
}

// MonthStart is the first instant of t's calendar month in UTC.
func MonthStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// ParseMonth reads "YYYY-MM" into its [start, end) range.
func ParseMonth(s string) (time.Time, time.Time, error) {
	start, err := time.Parse("2006-01", s)
	if err != nil {
		return time.Time{}, time.Time{}, ErrInvalidMonth
	}
	return start, start.AddDate(0, 1, 0), nil
}

// USDToMicro converts a configured dollar amount to micro-USD.
func USDToMicro(usd float64) int64 { return int64(math.Round(usd * 1e6)) }
