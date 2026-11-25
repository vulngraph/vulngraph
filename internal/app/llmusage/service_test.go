package llmusage

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/llm"
)

// fakeRepo is a ledger whose spend is what was configured plus what was
// inserted, like the real one.
type fakeRepo struct {
	mu        sync.Mutex
	spend     Spend
	user      map[string]UserSpend
	spendErr  error
	insertErr error
	inserted  []Record
	since     time.Time
	lines     []Line
}

func (r *fakeRepo) Insert(_ context.Context, rec Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.insertErr != nil {
		return r.insertErr
	}
	r.inserted = append(r.inserted, rec)
	return nil
}

func (r *fakeRepo) SpendSince(_ context.Context, since time.Time) (Spend, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.since = since
	s := r.spend
	for _, rec := range r.inserted {
		s.TotalMicroUSD += rec.CostMicroUSD
		if rec.Purpose.Interactive() {
			s.InteractiveMicroUSD += rec.CostMicroUSD
		}
	}
	return s, r.spendErr
}

func (r *fakeRepo) UserSpendSince(_ context.Context, userID string, _, _ time.Time) (UserSpend, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.spendErr != nil {
		return UserSpend{}, r.spendErr
	}
	s := r.user[userID]
	for _, rec := range r.inserted {
		if rec.UserID == userID {
			s.MonthMicroUSD += rec.CostMicroUSD
			s.DayMicroUSD += rec.CostMicroUSD
		}
	}
	return s, nil
}

func (r *fakeRepo) Summarize(context.Context, time.Time, time.Time) ([]Line, error) {
	return r.lines, nil
}

var now = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func newSvc(repo *fakeRepo, b Budget) *Service {
	s := NewService(repo, PriceTable{"m": {Input: 1, Output: 1}}, b)
	s.now = func() time.Time { return now }
	return s
}

// tiny is a request whose worst case costs 2 micro-USD at model m's price.
var tiny = llm.Request{Model: "m", MaxTokens: 2}

func userCtx(id string) context.Context {
	return auth.ContextWithUser(context.Background(), auth.User{ID: id, Email: id + "@example.com", Role: auth.RoleViewer})
}

func TestReserve(t *testing.T) {
	readErr := errors.New("pg down")
	budget := Budget{MonthlyMicroUSD: 100, InteractiveMicroUSD: 50}
	for _, tc := range []struct {
		name    string
		budget  Budget
		spend   Spend
		readErr error
		purpose Purpose
		want    error
	}{
		{"unlimited background never reads the ledger", Budget{}, Spend{}, readErr, PurposeReason, nil},
		{"background under the cap", budget, Spend{TotalMicroUSD: 98}, nil, PurposeReason, nil},
		{"background at the cap", budget, Spend{TotalMicroUSD: 100}, nil, PurposeAdjudicate, llm.ErrBudgetExceeded},
		{"background whose worst case would pass the cap", budget, Spend{TotalMicroUSD: 99}, nil, PurposeAdjudicate, llm.ErrBudgetExceeded},
		{"background counts interactive spend too", budget, Spend{TotalMicroUSD: 100, InteractiveMicroUSD: 100}, nil, PurposeReason, llm.ErrBudgetExceeded},
		{"background with an unreadable ledger is budget_unknown", budget, Spend{}, readErr, PurposeReason, llm.ErrBudgetUnknown},
		{"an unknown purpose is background", budget, Spend{}, readErr, "new_feature", llm.ErrBudgetUnknown},
		{"interactive is not cut off by background spend", budget, Spend{TotalMicroUSD: 10_000, InteractiveMicroUSD: 48}, nil, PurposeChat, nil},
		{"interactive at its own cap", budget, Spend{TotalMicroUSD: 50, InteractiveMicroUSD: 50}, nil, PurposeChat, llm.ErrBudgetExceeded},
		{"interactive with no interactive cap", Budget{MonthlyMicroUSD: 1}, Spend{TotalMicroUSD: 10_000, InteractiveMicroUSD: 10_000}, nil, PurposeNLQuery, nil},
		{"interactive keeps working with an unreadable ledger", budget, Spend{}, readErr, PurposeChat, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeRepo{spend: tc.spend, spendErr: tc.readErr}
			_, err := newSvc(repo, tc.budget).Reserve(context.Background(), tc.purpose, tiny)
			if tc.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.want)
			if tc.readErr == nil {
				require.Equal(t, MonthStart(now), repo.since)
			}
		})
	}
}

// The race the reservation closes: concurrent calls that each read "under
// budget" must not all go ahead. With room for exactly five worst cases,
// exactly five of fifty concurrent calls reach the provider.
func TestClient_ConcurrentCallsCannotOvershootTheBudget(t *testing.T) {
	repo := &fakeRepo{}
	release := make(chan struct{})
	next := &blockingClient{release: release, resp: &llm.Response{Model: "m"}}
	svc := newSvc(repo, Budget{MonthlyMicroUSD: 10})
	c := svc.Client(next, PurposeReason)

	var wg sync.WaitGroup
	var refused atomic.Int64
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Complete(context.Background(), tiny); errors.Is(err, llm.ErrBudgetExceeded) {
				refused.Add(1)
			}
		}()
	}
	require.Eventually(t, func() bool { return refused.Load() == 45 }, 5*time.Second, time.Millisecond,
		"every call past the fifth is refused while the first five are still in flight")
	close(release)
	wg.Wait()
	require.EqualValues(t, 5, next.calls.Load())

	spend, err := repo.SpendSince(context.Background(), MonthStart(now))
	require.NoError(t, err)
	require.LessOrEqual(t, spend.TotalMicroUSD, int64(10), "the ledger never passes the budget")
	require.Zero(t, svc.held().total, "every reservation is released once settled")
}

// A per-user cap stops one user without touching another.
func TestReserve_PerUserCaps(t *testing.T) {
	repo := &fakeRepo{user: map[string]UserSpend{
		"heavy":   {MonthMicroUSD: 40, DayMicroUSD: 10},
		"monthly": {MonthMicroUSD: 100, DayMicroUSD: 0},
	}}
	svc := newSvc(repo, Budget{UserDailyMicroUSD: 10, UserMonthlyMicroUSD: 100})

	_, err := svc.Reserve(userCtx("heavy"), PurposeChat, tiny)
	require.ErrorIs(t, err, llm.ErrBudgetExceeded)
	require.ErrorContains(t, err, "daily")
	_, err = svc.Reserve(userCtx("monthly"), PurposeNLQuery, tiny)
	require.ErrorIs(t, err, llm.ErrBudgetExceeded)
	require.ErrorContains(t, err, "monthly")

	r, err := svc.Reserve(userCtx("light"), PurposeChat, tiny)
	require.NoError(t, err)
	svc.Settle(userCtx("light"), r, "fake", tiny, &llm.Response{Model: "m"}, nil)
	require.Equal(t, "light", repo.inserted[0].UserID, "the ledger row names the user")

	_, err = svc.Reserve(userCtx("heavy"), PurposeReason, tiny)
	require.NoError(t, err, "background work is not charged to a user")
}

// The per-user cap counts the user's own calls in flight.
func TestReserve_PerUserCapCountsInFlightCalls(t *testing.T) {
	svc := newSvc(&fakeRepo{}, Budget{UserDailyMicroUSD: 4})
	_, err := svc.Reserve(userCtx("u"), PurposeChat, tiny)
	require.NoError(t, err)
	_, err = svc.Reserve(userCtx("u"), PurposeChat, tiny)
	require.NoError(t, err)
	_, err = svc.Reserve(userCtx("u"), PurposeChat, tiny)
	require.ErrorIs(t, err, llm.ErrBudgetExceeded)
	_, err = svc.Reserve(userCtx("other"), PurposeChat, tiny)
	require.NoError(t, err)
}

func TestRecord_ChargesReportedUsage(t *testing.T) {
	repo := &fakeRepo{}
	req := llm.Request{MaxTokens: 1000, Messages: []llm.Message{llm.UserText("hi")}}
	resp := &llm.Response{Model: "m", Usage: llm.Usage{InputTokens: 10, OutputTokens: 5, Reported: true}}
	newSvc(repo, Budget{}).record(context.Background(), PurposeChat, "", "anthropic", req, resp, nil)
	require.Equal(t, []Record{{
		Purpose: PurposeChat, Provider: "anthropic", Model: "m",
		Usage: resp.Usage, CostMicroUSD: 15,
	}}, repo.inserted)
}

// No usage reported (or a failed call) is charged the worst case — never as
// a free call.
func TestRecord_UnreportedAndFailedCallsAreChargedTheWorstCase(t *testing.T) {
	repo := &fakeRepo{}
	svc := newSvc(repo, Budget{})
	req := llm.Request{Model: "m", MaxTokens: 1000, Messages: []llm.Message{llm.UserText("abcdef")}}
	svc.record(context.Background(), PurposeReason, "", "openai", req, &llm.Response{Model: "m"}, nil)
	svc.record(context.Background(), PurposeReason, "", "openai", req, nil, errors.New("timeout"))
	require.Len(t, repo.inserted, 2)
	for _, rec := range repo.inserted {
		require.False(t, rec.Usage.Reported)
		require.EqualValues(t, 1000, rec.Usage.OutputTokens)
		require.EqualValues(t, 1002, rec.CostMicroUSD)
		require.Equal(t, "m", rec.Model)
	}
	require.True(t, repo.inserted[1].Failed)
}

// A ledger write that fails still counts against the budget.
func TestRecord_FailedWriteStillCountsAgainstTheBudget(t *testing.T) {
	repo := &fakeRepo{insertErr: errors.New("pg down")}
	svc := newSvc(repo, Budget{MonthlyMicroUSD: 100, InteractiveMicroUSD: 100})
	resp := &llm.Response{Model: "m", Usage: llm.Usage{InputTokens: 100, Reported: true}}
	svc.record(context.Background(), PurposeChat, "", "anthropic", llm.Request{}, resp, nil)

	_, err := svc.Reserve(context.Background(), PurposeReason, tiny)
	require.ErrorIs(t, err, llm.ErrBudgetExceeded)
	_, err = svc.Reserve(context.Background(), PurposeChat, tiny)
	require.ErrorIs(t, err, llm.ErrBudgetExceeded)

	sum, err := svc.Summary(context.Background(), "")
	require.NoError(t, err)
	require.EqualValues(t, 100, sum.UnrecordedMicroUSD)

	// A new month starts clean.
	now2 := now.AddDate(0, 1, 0)
	svc.now = func() time.Time { return now2 }
	_, err = svc.Reserve(context.Background(), PurposeReason, tiny)
	require.NoError(t, err)
}

func TestSummary(t *testing.T) {
	repo := &fakeRepo{lines: []Line{
		{Purpose: PurposeChat, Model: "m", Interactive: true, CostMicroUSD: 30},
		{Purpose: PurposeReason, Model: "unpriced", CostMicroUSD: 70},
	}}
	sum, err := newSvc(repo, Budget{MonthlyMicroUSD: 500}).Summary(context.Background(), "")
	require.NoError(t, err)
	require.Equal(t, "2026-10", sum.Month)
	require.EqualValues(t, 100, sum.TotalMicroUSD)
	require.EqualValues(t, 30, sum.InteractiveMicroUSD)
	require.Equal(t, []string{"unpriced"}, sum.DefaultPriceUsedForModels)

	_, err = newSvc(repo, Budget{}).Summary(context.Background(), "October")
	require.ErrorIs(t, err, ErrInvalidMonth)
}

type countingClient struct {
	calls int
	resp  *llm.Response
}

func (c *countingClient) Complete(context.Context, llm.Request) (*llm.Response, error) {
	c.calls++
	return c.resp, nil
}

func (c *countingClient) Stream(_ context.Context, _ llm.Request, onText func(string)) (*llm.Response, error) {
	c.calls++
	onText("x")
	return c.resp, nil
}

func (c *countingClient) Provider() llm.Provider { return "fake" }

// blockingClient holds every call until release is closed.
type blockingClient struct {
	release chan struct{}
	resp    *llm.Response
	calls   atomic.Int64
}

func (c *blockingClient) Complete(context.Context, llm.Request) (*llm.Response, error) {
	c.calls.Add(1)
	<-c.release
	return c.resp, nil
}

func (c *blockingClient) Stream(ctx context.Context, req llm.Request, _ func(string)) (*llm.Response, error) {
	return c.Complete(ctx, req)
}

func (c *blockingClient) Provider() llm.Provider { return "fake" }

func TestClient(t *testing.T) {
	require.Nil(t, newSvc(&fakeRepo{}, Budget{}).Client(nil, PurposeChat), "a nil client stays nil so features still degrade")

	repo := &fakeRepo{}
	next := &countingClient{resp: &llm.Response{Model: "m", Usage: llm.Usage{OutputTokens: 2, Reported: true}}}
	c := newSvc(repo, Budget{}).Client(next, PurposeTemplateGen)
	require.Equal(t, llm.Provider("fake"), c.Provider())
	_, err := c.Complete(context.Background(), llm.Request{})
	require.NoError(t, err)
	var streamed string
	_, err = c.Stream(context.Background(), llm.Request{}, func(s string) { streamed += s })
	require.NoError(t, err)
	require.Equal(t, "x", streamed)
	require.Len(t, repo.inserted, 2)
	require.Equal(t, PurposeTemplateGen, repo.inserted[0].Purpose)

	// Refused before the provider is called.
	over := &fakeRepo{spend: Spend{TotalMicroUSD: 1}}
	next = &countingClient{}
	c = newSvc(over, Budget{MonthlyMicroUSD: 1}).Client(next, PurposeAdjudicate)
	_, err = c.Complete(context.Background(), llm.Request{})
	require.ErrorIs(t, err, llm.ErrBudgetExceeded)
	_, err = c.Stream(context.Background(), llm.Request{}, nil)
	require.ErrorIs(t, err, llm.ErrBudgetExceeded)
	require.Zero(t, next.calls)
	require.Empty(t, over.inserted)
}
