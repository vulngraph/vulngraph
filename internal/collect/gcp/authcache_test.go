package gcp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/stretchr/testify/require"
)

// testAuthCache is a cache with the spacing gate stubbed out — real tests must
// not sleep 7 seconds between calls. Time still advances only when a test says
// so, via advance().
func testAuthCache() *authCache {
	c, _ := testAuthCacheWithClock()
	return c
}

// testAuthCacheWithClock also returns the handle a test uses to move time.
func testAuthCacheWithClock() (*authCache, func(time.Duration)) {
	c := newAuthCache()
	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	offset := time.Duration(0)
	c.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return base.Add(offset)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c, func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		offset += d
	}
}

// authFake counts LastAuthentications calls and can fail a chosen number of
// them.
type authFake struct {
	mu       sync.Mutex
	calls    int
	failFor  int   // fail the first N calls
	failWith error // nil means a 429 quota error
	values   map[string]time.Time
}

func (f *authFake) LastAuthentications(context.Context, string, string) (map[string]time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.failFor {
		if f.failWith != nil {
			return nil, f.failWith
		}
		return nil, fmt.Errorf("LastAuthentications: %w", &googleapi.Error{Code: 429, Message: "Quota exceeded"})
	}
	return f.values, nil
}

// The rest of iamAPI is unused by the cache.
func (f *authFake) ServiceAccounts(context.Context, string) ([]gcpServiceAccount, error) {
	return nil, nil
}
func (f *authFake) Policy(context.Context, string) (iamPolicy, error)           { return iamPolicy{}, nil }
func (f *authFake) Ancestry(context.Context, string) ([]string, error)          { return nil, nil }
func (f *authFake) OrganizationDomain(context.Context, string) (string, error)  { return "", nil }
func (f *authFake) RolePermissions(context.Context, string) ([]string, error)   { return nil, nil }
func (f *authFake) UserManagedKeys(context.Context, string) ([]gcpSAKey, error) { return nil, nil }

func (f *authFake) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// TestAuthCacheServesSnapshotWithinRefreshInterval is the quota fix: Policy
// Analyzer allows 10 requests/minute across the whole estate, far fewer than one
// request per project per sweep. Repeated sweeps inside the refresh window must
// cost ZERO extra requests.
func TestAuthCacheServesSnapshotWithinRefreshInterval(t *testing.T) {
	f := &authFake{values: map[string]time.Time{"sa-1": time.Now()}}
	c, advance := testAuthCacheWithClock()

	first := c.lastAuth(context.Background(), f, "proj", activitySALastAuth)
	require.True(t, first.ok)
	require.Equal(t, 0, first.observedDays)
	require.Equal(t, 1, f.callCount())

	for range 5 {
		advance(time.Hour)
		got := c.lastAuth(context.Background(), f, "proj", activitySALastAuth)
		require.True(t, got.ok)
		require.Equal(t, f.values, got.values)
	}
	require.Equal(t, 1, f.callCount(), "sweeps inside the refresh window must not re-query")

	advance(authRefreshInterval)
	require.True(t, c.lastAuth(context.Background(), f, "proj", activitySALastAuth).ok)
	require.Equal(t, 2, f.callCount(), "a sweep past the refresh interval must re-query")
}

// TestAuthCacheCarriesForwardOnFailure is the flap fix: a failed refresh used to
// strip sa_last_auth_days from every service account in the project, which flipped
// SAs between having and lacking the key and inflated asset_change_log's write
// volume. A failure must serve the last good
// read instead.
func TestAuthCacheCarriesForwardOnFailure(t *testing.T) {
	f := &authFake{values: map[string]time.Time{"sa-1": time.Now()}}
	c, advance := testAuthCacheWithClock()

	require.True(t, c.lastAuth(context.Background(), f, "proj", activitySALastAuth).ok)

	// Every subsequent refresh fails.
	f.mu.Lock()
	f.failFor = 1000
	f.mu.Unlock()

	advance(authRefreshInterval + 2*time.Hour)
	got := c.lastAuth(context.Background(), f, "proj", activitySALastAuth)
	require.True(t, got.ok, "a failed refresh must not erase a good observation")
	require.Equal(t, f.values, got.values)
	require.Equal(t, 0, got.observedDays, "still the same day")

	advance(3 * 24 * time.Hour)
	got = c.lastAuth(context.Background(), f, "proj", activitySALastAuth)
	require.True(t, got.ok)
	require.Equal(t, 3, got.observedDays, "a consumer must be able to tell carried from fresh")
}

// …but carried-forward data that silently ages is its own bug. Past authMaxAge
// the snapshot is dropped and the metadata goes back to unknown.
func TestAuthCacheDropsSnapshotPastMaxAge(t *testing.T) {
	f := &authFake{values: map[string]time.Time{"sa-1": time.Now()}}
	c, advance := testAuthCacheWithClock()
	require.True(t, c.lastAuth(context.Background(), f, "proj", activitySALastAuth).ok)

	f.mu.Lock()
	f.failFor = 1000
	f.mu.Unlock()

	advance(authMaxAge + time.Hour)
	got := c.lastAuth(context.Background(), f, "proj", activitySALastAuth)
	require.False(t, got.ok, "past the staleness ceiling the answer is unknown, not stale")
	require.Nil(t, got.values)
}

// A quota 429 is worth another attempt; a 403 is not — retrying a permission or
// API-not-enabled error just spends the shared 10/min budget faster.
func TestAuthCacheRetriesOnlyRetryableErrors(t *testing.T) {
	quota := &authFake{failFor: 2, values: map[string]time.Time{"sa-1": time.Now()}}
	c := testAuthCache()
	got := c.lastAuth(context.Background(), quota, "proj", activitySALastAuth)
	require.True(t, got.ok, "a 429 must be retried within the attempt budget")
	require.Equal(t, 3, quota.callCount())

	forbidden := &authFake{
		failFor:  1000,
		failWith: fmt.Errorf("LastAuthentications: %w", &googleapi.Error{Code: 403, Message: "API not enabled"}),
	}
	c2, _ := testAuthCacheWithClock()
	got = c2.lastAuth(context.Background(), forbidden, "proj", activitySALastAuth)
	require.False(t, got.ok)
	require.Equal(t, 1, forbidden.callCount(), "a 403 must not be retried")
}

func TestRetryableAuthErr(t *testing.T) {
	require.True(t, retryableAuthErr(fmt.Errorf("x: %w", &googleapi.Error{Code: 429})))
	require.True(t, retryableAuthErr(fmt.Errorf("x: %w", &googleapi.Error{Code: 503})))
	require.False(t, retryableAuthErr(fmt.Errorf("x: %w", &googleapi.Error{Code: 403})))
	require.False(t, retryableAuthErr(fmt.Errorf("x: %w", &googleapi.Error{Code: 404})))
	require.False(t, retryableAuthErr(errors.New("dial tcp: i/o timeout")))
}

// TestAuthCacheSpacesRequests pins the gate that keeps refreshes inside the
// 10 requests/minute ceiling: consecutive Policy Analyzer calls must be spaced
// by authMinInterval.
func TestAuthCacheSpacesRequests(t *testing.T) {
	c := newAuthCache()
	var waits []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	base := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return base } // frozen: every call is "immediately after" the last

	f := &authFake{values: map[string]time.Time{}}
	for i := range 3 {
		c.lastAuth(context.Background(), f, fmt.Sprintf("proj-%d", i), activitySALastAuth)
	}
	require.Len(t, waits, 2, "the first request goes out immediately; each next one waits")
	for _, w := range waits {
		require.Equal(t, authMinInterval, w)
	}
}
