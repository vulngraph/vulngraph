package suppress

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSuppressUntil_ValidatesExpiryBeforeWriting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expires time.Time
		want    error
	}{
		{"missing", time.Time{}, ErrMissingExpiry},
		{"past", testNow.Add(-day), ErrExpiryInPast},
		{"too far", testNow.Add(2 * MaxExpiry), ErrExpiryTooFar},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			_, err := clockedService(repo).SuppressUntil(context.Background(), "f1", "r", "by", tc.expires)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, repo.rows)
		})
	}

	repo := newFakeRepo()
	sup, err := clockedService(repo).SuppressUntil(context.Background(), "f1", "r", "by", testNow.Add(30*day))
	require.NoError(t, err)
	require.Equal(t, testNow.Add(30*day), sup.ExpiresAt)
	require.Equal(t, testNow.Add(30*day), repo.rows["f1"].ExpiresAt)
}

// An expired suppression stops matching: the finding re-enters the pipeline.
func TestIsSuppressed_ExpiredDoesNotMatch(t *testing.T) {
	repo := newFakeRepo()
	svc := clockedService(repo)
	repo.rows["live"] = Suppression{FindingID: "live", ExpiresAt: testNow.Add(time.Minute)}
	repo.rows["lapsed"] = Suppression{FindingID: "lapsed", ExpiresAt: testNow.Add(-time.Minute)}

	got, err := svc.IsSuppressed(context.Background(), "live")
	require.NoError(t, err)
	require.True(t, got)

	got, err = svc.IsSuppressed(context.Background(), "lapsed")
	require.NoError(t, err)
	require.False(t, got)
}

func TestReview_RenewsAndReinstates(t *testing.T) {
	repo := newFakeRepo()
	svc := clockedService(repo)
	repo.rows["f1"] = Suppression{FindingID: "f1", Reason: "accepted risk", ExpiresAt: testNow.Add(-day)}

	sup, err := svc.Review(context.Background(), "f1", "carol@b.example", testNow.Add(90*day))
	require.NoError(t, err)
	require.Equal(t, testNow.Add(90*day), sup.ExpiresAt)
	require.Equal(t, "carol@b.example", sup.ReviewedBy)
	require.Equal(t, testNow, sup.LastReviewedAt)
	require.Equal(t, "accepted risk", sup.Reason, "a review keeps the original reason")

	got, err := svc.IsSuppressed(context.Background(), "f1")
	require.NoError(t, err)
	require.True(t, got, "renewing an expired suppression re-instates it")
}

func TestReview_Errors(t *testing.T) {
	repo := newFakeRepo()
	svc := clockedService(repo)

	_, err := svc.Review(context.Background(), "ghost", "by", testNow.Add(day))
	require.ErrorIs(t, err, ErrNotFound)

	repo.rows["f1"] = Suppression{FindingID: "f1", ExpiresAt: testNow.Add(day)}
	_, err = svc.Review(context.Background(), "f1", "by", time.Time{})
	require.ErrorIs(t, err, ErrMissingExpiry)
	require.Equal(t, testNow.Add(day), repo.rows["f1"].ExpiresAt, "a rejected review changes nothing")
}

func TestExpiryNoticesDue_WindowAndOrder(t *testing.T) {
	repo := newFakeRepo()
	svc := clockedService(repo)
	for id, at := range map[string]time.Time{
		"lapsed":     testNow.Add(-time.Hour),
		"in-13d":     testNow.Add(13 * day),
		"in-1d":      testNow.Add(day),
		"edge-14d":   testNow.Add(ExpiryNoticeWindow),
		"beyond-14d": testNow.Add(ExpiryNoticeWindow + time.Second),
		"far-future": testNow.Add(200 * day),
	} {
		repo.rows[id] = Suppression{FindingID: id, ExpiresAt: at}
	}

	got, err := svc.ExpiryNoticesDue(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"in-1d", "in-13d", "edge-14d"}, findingIDs(got),
		"already-lapsed and beyond-window suppressions are excluded; soonest first")
}

// Each expiry is announced once: a sent notice is not due again, however often
// the job runs — until the expiry moves, which makes the new expiry due.
func TestExpiryNotices_AnnouncedOncePerExpiry(t *testing.T) {
	repo := newFakeRepo()
	svc := clockedService(repo)
	ctx := context.Background()
	repo.rows["f1"] = Suppression{FindingID: "f1", ExpiresAt: testNow.Add(3 * day)}

	due, err := svc.ExpiryNoticesDue(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"f1"}, findingIDs(due))
	require.NoError(t, svc.MarkExpiryNoticesSent(ctx, findingIDs(due)))

	due, err = svc.ExpiryNoticesDue(ctx)
	require.NoError(t, err)
	require.Empty(t, due, "already announced")

	_, err = svc.Review(ctx, "f1", "carol@b.example", testNow.Add(10*day))
	require.NoError(t, err)
	due, err = svc.ExpiryNoticesDue(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"f1"}, findingIDs(due), "a renewed expiry is announced afresh")

	require.NoError(t, svc.MarkExpiryNoticesSent(ctx, nil), "nothing to mark is a no-op")
}

func findingIDs(sups []Suppression) []string {
	ids := make([]string, len(sups))
	for i, s := range sups {
		ids[i] = s.FindingID
	}
	return ids
}

func TestExpiredNow_UsesServiceClock(t *testing.T) {
	svc := clockedService(newFakeRepo())
	require.True(t, svc.ExpiredNow(Suppression{ExpiresAt: testNow}))
	require.False(t, svc.ExpiredNow(Suppression{ExpiresAt: testNow.Add(time.Second)}))
}
