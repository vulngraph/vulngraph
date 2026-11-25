package llmusage

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// A budget check that reads the ledger and lets the call through, with the
// call recorded only once it returns, lets N concurrent calls all read the
// same "under budget" total and all go ahead. So the check RESERVES the
// call's worst-case cost (llm.ChargeableUsage with no response: the request
// size plus the whole output budget) before the call, and the reservation is
// released only once the real cost is in the ledger. Reads and reservations
// are serialised by Service.gate, so every check sees every call in flight
// in this process. (Serve replicas each hold their own reservations, like
// the per-user rate limiter.)

// spendReadTimeout bounds each ledger read made under Service.gate. The gate
// serialises every LLM call in the process, and worker contexts often carry
// no deadline, so one hung read would otherwise stall them all; a timed-out
// read takes the same degraded path as any unreadable ledger (background
// refused, interactive allowed).
const spendReadTimeout = 3 * time.Second

// Reservation is one call's held budget, released by Settle.
type Reservation struct {
	purpose Purpose
	userID  string
	cost    int64
}

// inflight is the reserved, not yet settled spend in this process.
type inflight struct {
	total, interactive int64
	byUser             map[string]int64
}

// Reserve admits a call for p with request req, holding its worst-case cost
// against every budget that applies until Settle. It refuses (ErrBudgetExceeded)
// when spend plus what is in flight has reached a cap, or when this call's
// worst case would take it over. Background purposes are refused when the
// ledger cannot be read (ErrBudgetUnknown); interactive ones proceed — a
// person is waiting, the per-user rate limit still bounds them, and every
// call is still recorded.
func (s *Service) Reserve(ctx context.Context, p Purpose, req llm.Request) (*Reservation, error) {
	r := &Reservation{purpose: p, cost: s.estimate(req)}
	if p.Interactive() {
		if u, ok := auth.UserFromContext(ctx); ok {
			r.userID = u.ID
		}
	}
	s.gate.Lock()
	defer s.gate.Unlock()
	if err := s.checkGlobal(ctx, r); err != nil {
		return nil, err
	}
	if err := s.checkUser(ctx, r); err != nil {
		return nil, err
	}
	s.hold(r, 1)
	return r, nil
}

// Settle records the call and only then releases its reservation, so at no
// point is its cost in neither the ledger nor the in-flight total.
func (s *Service) Settle(ctx context.Context, r *Reservation, provider llm.Provider, req llm.Request, resp *llm.Response, callErr error) {
	s.record(ctx, r.purpose, r.userID, provider, req, resp, callErr)
	s.hold(r, -1)
}

func (s *Service) estimate(req llm.Request) int64 {
	price, _ := s.prices.Lookup(orUnknown(req.Model))
	return price.CostMicroUSD(llm.ChargeableUsage(req, nil))
}

// checkGlobal applies the monthly cap that governs r's purpose. Called with
// gate held.
func (s *Service) checkGlobal(ctx context.Context, r *Reservation) error {
	limit := s.budget.MonthlyMicroUSD
	if r.purpose.Interactive() {
		limit = s.budget.InteractiveMicroUSD
	}
	if limit <= 0 {
		return nil
	}
	month := MonthStart(s.now())
	readCtx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	spend, err := s.repo.SpendSince(readCtx, month)
	if err != nil {
		if r.purpose.Interactive() {
			log.FromContext(ctx).Warn().Err(err).Str("purpose", string(r.purpose)).
				Msg("llmusage: ledger unreadable — allowing the interactive call")
			return nil
		}
		return fmt.Errorf("Reserve %s: %w: %w", r.purpose, ErrBudgetUnknown, err)
	}
	spend = s.plusUnrecorded(month, spend)
	held := s.held()
	used := spend.TotalMicroUSD + held.total
	if r.purpose.Interactive() {
		used = spend.InteractiveMicroUSD + held.interactive
	}
	if over(used, r.cost, limit) {
		return fmt.Errorf("Reserve %s: %w", r.purpose, ErrBudgetExceeded)
	}
	return nil
}

// checkUser applies the per-user caps to an interactive call made for a
// user. Called with gate held.
func (s *Service) checkUser(ctx context.Context, r *Reservation) error {
	if r.userID == "" || (s.budget.UserDailyMicroUSD <= 0 && s.budget.UserMonthlyMicroUSD <= 0) {
		return nil
	}
	now := s.now()
	readCtx, cancel := context.WithTimeout(ctx, s.readTimeout)
	defer cancel()
	spend, err := s.repo.UserSpendSince(readCtx, r.userID, MonthStart(now), DayStart(now))
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("purpose", string(r.purpose)).
			Msg("llmusage: per-user spend unreadable — allowing the interactive call")
		return nil
	}
	held := s.heldBy(r.userID)
	if limit := s.budget.UserDailyMicroUSD; limit > 0 && over(spend.DayMicroUSD+held, r.cost, limit) {
		return fmt.Errorf("Reserve %s: %w: your daily LLM budget is spent", r.purpose, ErrBudgetExceeded)
	}
	if limit := s.budget.UserMonthlyMicroUSD; limit > 0 && over(spend.MonthMicroUSD+held, r.cost, limit) {
		return fmt.Errorf("Reserve %s: %w: your monthly LLM budget is spent", r.purpose, ErrBudgetExceeded)
	}
	return nil
}

// over reports whether a cap is reached, or would be passed by this call's
// worst case.
func over(used, cost, limit int64) bool { return used >= limit || used+cost > limit }

// hold adds (sign 1) or removes (sign -1) r from the in-flight totals.
func (s *Service) hold(r *Reservation, sign int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := sign * r.cost
	s.inflight.total += c
	if r.purpose.Interactive() {
		s.inflight.interactive += c
	}
	if r.userID != "" {
		if s.inflight.byUser == nil {
			s.inflight.byUser = map[string]int64{}
		}
		s.inflight.byUser[r.userID] += c
		if s.inflight.byUser[r.userID] == 0 {
			delete(s.inflight.byUser, r.userID)
		}
	}
}

// held returns the in-flight totals (without the per-user map).
func (s *Service) held() inflight {
	s.mu.Lock()
	defer s.mu.Unlock()
	return inflight{total: s.inflight.total, interactive: s.inflight.interactive}
}

// heldBy returns one user's in-flight spend.
func (s *Service) heldBy(userID string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight.byUser[userID]
}
