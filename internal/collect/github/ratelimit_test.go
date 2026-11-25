package github

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func rateResp(remaining, reset string) *http.Response {
	h := http.Header{}
	if remaining != "" {
		h.Set("X-RateLimit-Remaining", remaining)
	}
	if reset != "" {
		h.Set("X-RateLimit-Reset", reset)
	}
	return &http.Response{Header: h}
}

func TestWaitIfNeeded_NoDataYetAllows(t *testing.T) {
	s := &tokenRateState{}
	require.NoError(t, s.waitIfNeeded(context.Background()))
}

func TestWaitIfNeeded_HealthyBudgetAllows(t *testing.T) {
	s := &tokenRateState{}
	s.update(rateResp("4900", ""))
	require.NoError(t, s.waitIfNeeded(context.Background()))
}

// remaining==0 is a genuinely exhausted budget, not the "no data yet"
// sentinel it used to be — with the reset already past, the request proceeds;
// with a future reset it must throttle (covered below via the deadline path).
func TestWaitIfNeeded_ExhaustedWithPastResetAllows(t *testing.T) {
	s := &tokenRateState{}
	s.update(rateResp("0", "1"))
	require.NoError(t, s.waitIfNeeded(context.Background()))
}

func TestWaitIfNeeded_ResetPastDeadlineFailsFast(t *testing.T) {
	s := &tokenRateState{}
	reset := time.Now().Add(45 * time.Minute)
	s.update(rateResp("0", ""))
	s.mu.Lock()
	s.resetAt = reset
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	err := s.waitIfNeeded(ctx)
	require.ErrorIs(t, err, errRateLimitWait)
	require.Less(t, time.Since(start), time.Second, "must fail immediately, not block until the deadline")
}

func TestWaitIfNeeded_WaitsUntilShortReset(t *testing.T) {
	s := &tokenRateState{}
	s.update(rateResp("50", ""))
	s.mu.Lock()
	s.resetAt = time.Now().Add(50 * time.Millisecond)
	s.mu.Unlock()

	start := time.Now()
	require.NoError(t, s.waitIfNeeded(context.Background()))
	require.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
}

func TestUpdate_ParsesHeaders(t *testing.T) {
	s := &tokenRateState{}
	require.False(t, s.known)
	s.update(rateResp("42", "1767225600"))
	require.True(t, s.known)
	require.Equal(t, 42, s.remaining)
	require.Equal(t, time.Unix(1767225600, 0), s.resetAt)
}
