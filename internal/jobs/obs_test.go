package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/vulngraph/vulngraph/internal/obs"
)

func TestFeedForJobKind(t *testing.T) {
	cases := map[string]string{
		"refresh_kev":    "kev",
		"refresh_osv":    "osv",
		"refresh_epss":   "epss",
		"refresh_scc":    "scc",
		"domain_monitor": "domain_monitor",
		"enrich":         "", // not a feed
		"correlate":      "",
	}
	for kind, want := range cases {
		if got := feedForJobKind(kind); got != want {
			t.Errorf("feedForJobKind(%q) = %q, want %q", kind, got, want)
		}
	}
}

func TestObsMiddleware_StampsFeedOnSuccess(t *testing.T) {
	m := obs.New()
	mw := &obsMiddleware{m: m}

	// A successful KEV refresh stamps the kev feed gauge.
	err := mw.Work(context.Background(), &rivertype.JobRow{Kind: "refresh_kev", Queue: "feeds"},
		func(context.Context) error { return nil })
	require.NoError(t, err)
	if got := testutil.CollectAndCount(m.Registry(), "graph_feed_last_success_timestamp_seconds"); got != 1 {
		t.Fatalf("expected 1 feed gauge sample after success, got %d", got)
	}

	// A FAILED refresh must not stamp (a stale feed must look stale).
	m2 := obs.New()
	mw2 := &obsMiddleware{m: m2}
	_ = mw2.Work(context.Background(), &rivertype.JobRow{Kind: "refresh_osv", Queue: "sync"},
		func(context.Context) error { return errors.New("osv down") })
	if got := testutil.CollectAndCount(m2.Registry(), "graph_feed_last_success_timestamp_seconds"); got != 0 {
		t.Fatalf("failed refresh must not stamp feed gauge, got %d", got)
	}
}

// Regression guard: obsMiddleware records a failure as a
// metric but never logs it, and never even runs on a panic (which unwinds
// past its err := doInner(ctx) line) — jobErrorLogger (River's ErrorHandler)
// is the fix, invoked for both shapes above all middleware. Behavior-only,
// matching this file's own convention (see TestObsMiddleware_StampsFeedOnSuccess
// above) rather than asserting captured log text, which pkg/log has no
// existing capture helper for.
func TestJobErrorLogger_HandleError_KeepsDefaultRetrySchedule(t *testing.T) {
	var h jobErrorLogger
	result := h.HandleError(context.Background(), &rivertype.JobRow{Kind: "refresh_kev", Queue: "feeds", Attempt: 3}, errors.New("cisa: 503"))
	if result != nil {
		t.Fatalf("HandleError must return nil to preserve River's default retry schedule, got %+v", result)
	}
}

func TestJobErrorLogger_HandlePanic_KeepsDefaultRetrySchedule(t *testing.T) {
	var h jobErrorLogger
	result := h.HandlePanic(context.Background(), &rivertype.JobRow{Kind: "refresh_scc", Queue: "feeds", Attempt: 1}, "boom", "goroutine 1 [running]:...")
	if result != nil {
		t.Fatalf("HandlePanic must return nil to preserve River's default retry schedule, got %+v", result)
	}
}
