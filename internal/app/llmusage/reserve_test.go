package llmusage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/llm"
)

// hungRepo's spend reads block until their context ends, like a stuck
// Postgres connection.
type hungRepo struct{ fakeRepo }

func (r *hungRepo) SpendSince(ctx context.Context, _ time.Time) (Spend, error) {
	<-ctx.Done()
	return Spend{}, ctx.Err()
}

func (r *hungRepo) UserSpendSince(ctx context.Context, _ string, _, _ time.Time) (UserSpend, error) {
	<-ctx.Done()
	return UserSpend{}, ctx.Err()
}

// A hung ledger read is held under the gate every LLM call in the process
// waits on; with a caller context that has no deadline it must still end,
// and take the unreadable-ledger path.
func TestReserve_HungLedgerReadTimesOut(t *testing.T) {
	repo := &hungRepo{}
	svc := NewService(repo, PriceTable{"m": {Input: 1, Output: 1}},
		Budget{MonthlyMicroUSD: 100, InteractiveMicroUSD: 100, UserDailyMicroUSD: 100})
	svc.readTimeout = 20 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		_, err := svc.Reserve(context.Background(), PurposeReason, tiny)
		done <- err
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, llm.ErrBudgetUnknown, "background work is refused when spend cannot be read")
	case <-time.After(5 * time.Second):
		t.Fatal("a hung ledger read blocked Reserve indefinitely")
	}

	_, err := svc.Reserve(userCtx("u"), PurposeChat, tiny)
	require.NoError(t, err, "interactive calls proceed past an unreadable ledger, per-user read included")
}

type panickyClient struct{}

func (panickyClient) Complete(context.Context, llm.Request) (*llm.Response, error) {
	panic("provider bug")
}
func (panickyClient) Stream(_ context.Context, _ llm.Request, onText func(string)) (*llm.Response, error) {
	onText("x")
	return &llm.Response{Model: "m"}, nil
}
func (panickyClient) Provider() llm.Provider { return "fake" }

// A panic in the provider or in the caller's onText still records the call
// as failed and releases its reservation, then re-panics.
func TestClient_PanicSettlesTheReservation(t *testing.T) {
	repo := &fakeRepo{}
	svc := newSvc(repo, Budget{MonthlyMicroUSD: 1_000})
	c := svc.Client(panickyClient{}, PurposeReason)

	require.PanicsWithValue(t, "provider bug", func() { _, _ = c.Complete(context.Background(), tiny) })
	require.PanicsWithValue(t, "caller bug", func() {
		_, _ = c.Stream(context.Background(), tiny, func(string) { panic("caller bug") })
	})

	require.Zero(t, svc.held().total, "no reservation leaks")
	require.Len(t, repo.inserted, 2, "both calls reach the ledger")
	for _, rec := range repo.inserted {
		require.True(t, rec.Failed)
		require.EqualValues(t, 2, rec.CostMicroUSD, "charged at the worst case")
	}
}
