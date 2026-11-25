package llmusage

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// recordTimeout bounds one ledger write. The write outlives the caller's
// cancellation (a user closing the chat tab does not un-spend the tokens).
const recordTimeout = 5 * time.Second

// Repo is the ledger store.
type Repo interface {
	Insert(ctx context.Context, rec Record) error
	SpendSince(ctx context.Context, since time.Time) (Spend, error)
	UserSpendSince(ctx context.Context, userID string, monthStart, dayStart time.Time) (UserSpend, error)
	Summarize(ctx context.Context, since, until time.Time) ([]Line, error)
}

// Service records model calls and enforces the monthly budget.
type Service struct {
	repo   Repo
	prices PriceTable
	budget Budget
	now    func() time.Time

	// gate serialises budget checks with the reservations they make
	// (reserve.go), so concurrent calls cannot all pass on one reading.
	gate sync.Mutex
	// readTimeout bounds each ledger read made under gate (spendReadTimeout).
	readTimeout time.Duration

	// mu guards the two in-memory additions to the ledger total.
	mu sync.Mutex
	// unrecorded is spend whose ledger write failed, for the month starting
	// at unrecordedMonth. It is added to every budget check, so a failing
	// ledger write can never make spend look smaller than it was.
	unrecordedMonth time.Time
	unrecorded      Spend
	// inflight is reserved spend of calls not yet recorded.
	inflight inflight
}

// NewService builds the ledger service. A zero Budget is unlimited.
func NewService(repo Repo, prices PriceTable, budget Budget) *Service {
	return &Service{repo: repo, prices: prices, budget: budget, now: time.Now, readTimeout: spendReadTimeout}
}

// record writes one call to the ledger, charging llm.ChargeableUsage (the
// worst case when the provider reported nothing). resp is nil when the call
// failed before a response existed.
func (s *Service) record(ctx context.Context, p Purpose, userID string, provider llm.Provider, req llm.Request, resp *llm.Response, callErr error) {
	usage := llm.ChargeableUsage(req, resp)
	model := req.Model
	if resp != nil && resp.Model != "" {
		model = resp.Model
	}
	model = orUnknown(model)
	price, _ := s.prices.Lookup(model)
	rec := Record{
		Purpose:      p,
		UserID:       userID,
		Provider:     string(provider),
		Model:        model,
		Usage:        usage,
		Failed:       callErr != nil,
		CostMicroUSD: price.CostMicroUSD(usage),
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTimeout)
	defer cancel()
	if err := s.repo.Insert(wctx, rec); err != nil {
		s.addUnrecorded(rec)
		log.FromContext(ctx).Error().Err(err).Str("purpose", string(p)).Int64("cost_micro_usd", rec.CostMicroUSD).
			Msg("llmusage: ledger write failed — spend held in memory against the budget")
	}
}

// Summary reports a calendar month ("YYYY-MM"; empty = the current month).
func (s *Service) Summary(ctx context.Context, month string) (Summary, error) {
	since := MonthStart(s.now())
	until := since.AddDate(0, 1, 0)
	if month != "" {
		var err error
		if since, until, err = ParseMonth(month); err != nil {
			return Summary{}, fmt.Errorf("Summary: %w", err)
		}
	}
	lines, err := s.repo.Summarize(ctx, since, until)
	if err != nil {
		return Summary{}, fmt.Errorf("Summary: %w", err)
	}
	sum := Summary{Month: since.Format("2006-01"), Since: since, Until: until, Budget: s.budget, Lines: lines}
	defaulted := map[string]bool{}
	for _, l := range lines {
		sum.TotalMicroUSD += l.CostMicroUSD
		if l.Interactive {
			sum.InteractiveMicroUSD += l.CostMicroUSD
		}
		if _, known := s.prices.Lookup(l.Model); !known {
			defaulted[l.Model] = true
		}
	}
	for m := range defaulted {
		sum.DefaultPriceUsedForModels = append(sum.DefaultPriceUsedForModels, m)
	}
	sort.Strings(sum.DefaultPriceUsedForModels)
	if u := s.plusUnrecorded(since, Spend{}); u.TotalMicroUSD > 0 {
		sum.UnrecordedMicroUSD = u.TotalMicroUSD
	}
	return sum, nil
}

func orUnknown(model string) string {
	if model == "" {
		return "unknown"
	}
	return model
}

func (s *Service) addUnrecorded(rec Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	month := MonthStart(s.now())
	if !s.unrecordedMonth.Equal(month) {
		s.unrecordedMonth, s.unrecorded = month, Spend{}
	}
	s.unrecorded.TotalMicroUSD += rec.CostMicroUSD
	if rec.Purpose.Interactive() {
		s.unrecorded.InteractiveMicroUSD += rec.CostMicroUSD
	}
}

func (s *Service) plusUnrecorded(month time.Time, spend Spend) Spend {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unrecordedMonth.Equal(month) {
		spend.TotalMicroUSD += s.unrecorded.TotalMicroUSD
		spend.InteractiveMicroUSD += s.unrecorded.InteractiveMicroUSD
	}
	return spend
}

// Client wraps next so every call reserves its worst case against the budget
// before it is made and is recorded under p after (reserve.go). A nil next stays nil: LLM features test
// for a nil client to degrade (503 or heuristics).
func (s *Service) Client(next llm.Client, p Purpose) llm.Client {
	if next == nil {
		return nil
	}
	return &meteredClient{next: next, svc: s, purpose: p}
}

type meteredClient struct {
	next    llm.Client
	svc     *Service
	purpose Purpose
}

func (m *meteredClient) Provider() llm.Provider { return m.next.Provider() }

func (m *meteredClient) Complete(ctx context.Context, req llm.Request) (resp *llm.Response, err error) {
	r, err := m.svc.Reserve(ctx, m.purpose, req)
	if err != nil {
		return nil, err
	}
	defer func() { m.settle(ctx, r, req, resp, err, recover()) }()
	return m.next.Complete(ctx, req)
}

func (m *meteredClient) Stream(ctx context.Context, req llm.Request, onText func(string)) (resp *llm.Response, err error) {
	r, err := m.svc.Reserve(ctx, m.purpose, req)
	if err != nil {
		return nil, err
	}
	defer func() { m.settle(ctx, r, req, resp, err, recover()) }()
	return m.next.Stream(ctx, req, onText)
}

// settle runs deferred, so a panic in the provider client or in a caller's
// onText still records the call (as failed, at its worst case) and releases
// its reservation — a leaked reservation would hold budget until restart.
// The panic is re-raised for the caller's own recovery.
func (m *meteredClient) settle(ctx context.Context, r *Reservation, req llm.Request, resp *llm.Response, err error, panicked any) {
	if panicked != nil {
		err = fmt.Errorf("llm call panicked: %v", panicked)
	}
	m.svc.Settle(ctx, r, m.next.Provider(), req, resp, err)
	if panicked != nil {
		panic(panicked)
	}
}
