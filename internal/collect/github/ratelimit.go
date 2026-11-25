package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// rateLimitThreshold is how many remaining API calls trigger proactive
// throttling. GitHub's core limit is 5000/hour for authenticated requests;
// we start waiting when we're within 100 of the reset floor.
const rateLimitThreshold = 100

// errRateLimitWait means the rate-limit window resets after the job's context
// deadline: waiting is pointless (the 30-minute sync job would die mid-wait,
// as the reset can be up to an hour out), so callers get the error immediately
// and classify the work as rate-limit-skipped instead of blocking to death.
var errRateLimitWait = errors.New("github: rate limit window resets after deadline")

// tokenRateState tracks the current rate-limit window for one installation token.
type tokenRateState struct {
	mu        sync.Mutex
	known     bool // false until the first X-RateLimit-Remaining header is seen
	remaining int
	resetAt   time.Time
}

// update reads X-RateLimit-* headers from a response and records the new state.
// Call this after every GitHub API response regardless of status.
func (s *tokenRateState) update(resp *http.Response) {
	if resp == nil {
		return
	}
	remaining := resp.Header.Get("X-RateLimit-Remaining")
	reset := resp.Header.Get("X-RateLimit-Reset")
	if remaining == "" && reset == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, err := strconv.Atoi(remaining); err == nil {
		s.remaining = n
		s.known = true
	}
	if ts, err := strconv.ParseInt(reset, 10, 64); err == nil {
		s.resetAt = time.Unix(ts, 0)
	}
}

// waitIfNeeded blocks until the rate-limit window resets when the remaining
// budget is below the threshold; non-blocking while the limit is healthy or no
// response has been seen yet. remaining==0 is a genuinely exhausted budget —
// "no data yet" is tracked by known, not a zero sentinel (reading ==0 as "no
// data" would let exhausted syncs sail straight into 403s). When the reset lies beyond the
// context deadline it returns errRateLimitWait immediately instead of blocking
// until the deadline kills the job.
func (s *tokenRateState) waitIfNeeded(ctx context.Context) error {
	s.mu.Lock()
	known, remaining, resetAt := s.known, s.remaining, s.resetAt
	s.mu.Unlock()

	if !known || remaining >= rateLimitThreshold {
		return nil
	}
	// Below threshold — wait until the window resets, then add 1s of buffer.
	wait := time.Until(resetAt) + time.Second
	if wait <= 0 {
		return nil
	}
	if deadline, ok := ctx.Deadline(); ok && time.Now().Add(wait).After(deadline) {
		return fmt.Errorf("reset in %s: %w", wait.Round(time.Second), errRateLimitWait)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

// rateLimitStates is a global registry keyed by installation token so concurrent
// syncs for different connectors don't interfere with each other's tracking.
var rateLimitStates sync.Map // map[string]*tokenRateState

func getRateState(token string) *tokenRateState {
	if v, ok := rateLimitStates.Load(token); ok {
		return v.(*tokenRateState)
	}
	s := &tokenRateState{} // known=false until the first response headers arrive
	actual, _ := rateLimitStates.LoadOrStore(token, s)
	return actual.(*tokenRateState)
}
