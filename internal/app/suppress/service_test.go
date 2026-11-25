package suppress

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeRepo is an in-memory Repo for service tests. Per-method err fields force a
// store failure so the service/handler error branches are exercised.
type fakeRepo struct {
	rows       map[string]Suppression
	getErr     error
	upsertErr  error
	deleteErr  error
	listErr    error
	listIDsErr error
	reviewErr  error
	markErr    error
	// notified mirrors expiry_notified_at: set by MarkExpiryNotified, cleared
	// whenever the expiry moves.
	notified map[string]bool
}

func newFakeRepo() *fakeRepo { return &fakeRepo{rows: map[string]Suppression{}} }

func (f *fakeRepo) Upsert(_ context.Context, s Suppression) (Suppression, error) {
	if f.upsertErr != nil {
		return Suppression{}, f.upsertErr
	}
	f.rows[s.FindingID] = s
	delete(f.notified, s.FindingID)
	return s, nil
}

func (f *fakeRepo) Delete(_ context.Context, findingID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if _, ok := f.rows[findingID]; !ok {
		return ErrNotFound
	}
	delete(f.rows, findingID)
	return nil
}

func (f *fakeRepo) Get(_ context.Context, findingID string) (Suppression, error) {
	if f.getErr != nil {
		return Suppression{}, f.getErr
	}
	s, ok := f.rows[findingID]
	if !ok {
		return Suppression{}, ErrNotFound
	}
	return s, nil
}

func (f *fakeRepo) List(_ context.Context) ([]Suppression, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]Suppression, 0, len(f.rows))
	for _, s := range f.rows {
		out = append(out, s)
	}
	return out, nil
}

func (f *fakeRepo) Review(_ context.Context, findingID, by string, expiresAt time.Time) (Suppression, error) {
	if f.reviewErr != nil {
		return Suppression{}, f.reviewErr
	}
	s, ok := f.rows[findingID]
	if !ok {
		return Suppression{}, ErrNotFound
	}
	s.ExpiresAt, s.ReviewedBy, s.LastReviewedAt = expiresAt, by, testNow
	f.rows[findingID] = s
	delete(f.notified, findingID)
	return s, nil
}

func (f *fakeRepo) Expiries(_ context.Context) (map[string]time.Time, error) {
	if f.listIDsErr != nil {
		return nil, f.listIDsErr
	}
	out := make(map[string]time.Time, len(f.rows))
	for id, s := range f.rows {
		out[id] = s.ExpiresAt
	}
	return out, nil
}

func (f *fakeRepo) DueExpiryNotice(_ context.Context, after, until time.Time) ([]Suppression, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []Suppression
	for _, s := range f.rows {
		if s.ExpiresAt.After(after) && !s.ExpiresAt.After(until) && !f.notified[s.FindingID] {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out, nil
}

func (f *fakeRepo) MarkExpiryNotified(_ context.Context, findingIDs []string) error {
	if f.markErr != nil {
		return f.markErr
	}
	if f.notified == nil {
		f.notified = map[string]bool{}
	}
	for _, id := range findingIDs {
		f.notified[id] = true
	}
	return nil
}

// testNow is the fixed clock every service test runs on.
var testNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// clockedService is a service over repo whose clock is testNow.
func clockedService(repo Repo) *Service {
	svc := NewService(repo)
	svc.now = func() time.Time { return testNow }
	return svc
}

func TestSuppress_RequiresReason(t *testing.T) {
	svc := NewService(newFakeRepo())
	_, err := svc.SuppressUntil(context.Background(), "f1", "", "admin@b.example", time.Now().Add(24*time.Hour))
	require.ErrorIs(t, err, ErrMissingReason)
}

func TestSuppress_PersistsAndIsIdempotent(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)

	sup, err := svc.SuppressUntil(context.Background(), "f1", "false positive", "admin@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, "f1", sup.FindingID)
	require.Equal(t, "false positive", sup.Reason)
	require.Equal(t, "admin@b.example", sup.SuppressedBy)

	// Re-suppressing updates the reason (upsert), not a second row.
	_, err = svc.SuppressUntil(context.Background(), "f1", "accepted risk", "other@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.Len(t, repo.rows, 1)
	require.Equal(t, "accepted risk", repo.rows["f1"].Reason)
}

func TestIsSuppressed(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.SuppressUntil(context.Background(), "f1", "reason", "admin@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	got, err := svc.IsSuppressed(context.Background(), "f1")
	require.NoError(t, err)
	require.True(t, got)

	got, err = svc.IsSuppressed(context.Background(), "missing")
	require.NoError(t, err) // ErrNotFound → not suppressed, not an error
	require.False(t, got)
}

func TestIsSuppressed_StoreError(t *testing.T) {
	repo := newFakeRepo()
	repo.getErr = errors.New("connection refused")
	svc := NewService(repo)

	_, err := svc.IsSuppressed(context.Background(), "f1")
	require.Error(t, err) // a real store failure surfaces, not masked as "not suppressed"
}

func TestUnsuppress(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.SuppressUntil(context.Background(), "f1", "reason", "admin@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	require.NoError(t, svc.Unsuppress(context.Background(), "f1", "test@example.com"))
	require.Empty(t, repo.rows)

	// Lifting an absent suppression surfaces ErrNotFound (wrapped).
	require.ErrorIs(t, svc.Unsuppress(context.Background(), "f1", "test@example.com"), ErrNotFound)
}

func TestSuppressionStates(t *testing.T) {
	repo := newFakeRepo()
	svc := clockedService(repo)
	for _, id := range []string{"f1", "f2", "f3"} {
		_, err := svc.SuppressUntil(context.Background(), id, "reason", "admin@b.example", time.Now().Add(24*time.Hour))
		require.NoError(t, err)
	}
	// f3's exception lapsed; f4's lapses exactly now (expiry is exclusive).
	repo.rows["f3"] = Suppression{FindingID: "f3", ExpiresAt: testNow.Add(-time.Hour)}
	repo.rows["f4"] = Suppression{FindingID: "f4", ExpiresAt: testNow}

	active, expired, err := svc.SuppressionStates(context.Background())
	require.NoError(t, err)
	require.Len(t, active, 2)
	require.Contains(t, active, "f1")
	require.Contains(t, active, "f2")
	require.NotContains(t, active, "nope")
	require.Len(t, expired, 2)
	require.Contains(t, expired, "f3")
	require.Contains(t, expired, "f4")
}

func TestList(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.SuppressUntil(context.Background(), "f1", "reason", "admin@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	out, err := svc.List(context.Background())
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "f1", out[0].FindingID)
}

func TestSuppressMany(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)

	exp := time.Now().Add(30 * day)
	n, err := svc.SuppressMany(context.Background(), []string{"f1", "f2", "", "f3"}, "accepted risk", "admin@b.example", exp)
	require.NoError(t, err)
	require.Equal(t, 3, n) // empty id skipped
	require.Len(t, repo.rows, 3)
	require.Equal(t, "accepted risk", repo.rows["f2"].Reason)
	require.Equal(t, exp, repo.rows["f2"].ExpiresAt)

	// Reason and a valid expiry are still required, and nothing is written without them.
	_, err = svc.SuppressMany(context.Background(), []string{"f4"}, "", "admin@b.example", exp)
	require.ErrorIs(t, err, ErrMissingReason)
	_, err = svc.SuppressMany(context.Background(), []string{"f4"}, "r", "admin@b.example", time.Time{})
	require.ErrorIs(t, err, ErrMissingExpiry)
	require.NotContains(t, repo.rows, "f4")
}

func TestUnsuppressMany_Idempotent(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	_, err := svc.SuppressMany(context.Background(), []string{"f1", "f2"}, "r", "admin@b.example", time.Now().Add(day))
	require.NoError(t, err)

	// Unsuppress a mix of suppressed + never-suppressed ids — no error, count = real removals.
	n, err := svc.UnsuppressMany(context.Background(), []string{"f1", "f2", "ghost"}, "test@example.com")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Empty(t, repo.rows)
}

func TestSuppressMany_PartialFailureSurfaced(t *testing.T) {
	// A store error on upsert is reported (with the count that applied), not swallowed.
	svc := NewService(&fakeRepo{rows: map[string]Suppression{}, upsertErr: errors.New("pg down")})
	n, err := svc.SuppressMany(context.Background(), []string{"f1", "f2"}, "r", "by", time.Now().Add(day))
	require.Error(t, err)
	require.ErrorContains(t, err, "SuppressMany")
	require.Zero(t, n)
}

// Store failures are wrapped with the method name, never swallowed.
func TestService_StoreErrorsWrapped(t *testing.T) {
	boom := errors.New("pg down")

	_, err := NewService(&fakeRepo{upsertErr: boom}).SuppressUntil(context.Background(), "f1", "r", "by", time.Now().Add(24*time.Hour))
	require.ErrorContains(t, err, "Suppress")

	err = NewService(&fakeRepo{deleteErr: boom}).Unsuppress(context.Background(), "f1", "test@example.com")
	require.ErrorContains(t, err, "Unsuppress")

	_, err = NewService(&fakeRepo{listErr: boom}).List(context.Background())
	require.ErrorContains(t, err, "List")

	_, _, err = NewService(&fakeRepo{listIDsErr: boom}).SuppressionStates(context.Background())
	require.ErrorContains(t, err, "SuppressionStates")

	_, err = clockedService(&fakeRepo{listErr: boom}).ExpiryNoticesDue(context.Background())
	require.ErrorContains(t, err, "ExpiryNoticesDue")

	err = clockedService(&fakeRepo{markErr: boom}).MarkExpiryNoticesSent(context.Background(), []string{"f1"})
	require.ErrorContains(t, err, "MarkExpiryNoticesSent")

	repo := newFakeRepo()
	repo.rows["f1"] = Suppression{FindingID: "f1", ExpiresAt: testNow.Add(day)}
	repo.reviewErr = boom
	_, err = clockedService(repo).Review(context.Background(), "f1", "by", testNow.Add(30*day))
	require.ErrorIs(t, err, boom)
	require.ErrorContains(t, err, "Review")
}
