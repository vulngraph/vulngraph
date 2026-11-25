package gcp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/api/googleapi"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Policy Analyzer quota is charged to the CONSUMER project — the one
// credential project every GCP connector authenticates through, not the
// project being queried — and is far too small for one request per project
// per sweep across the whole estate. A plain retry only spends that shared,
// starved budget faster.
//
// So this cache asks far less and never throws away a good answer: a
// snapshot per (project, activity type) is reused for authRefreshInterval
// (the underlying datum has day granularity, so re-reading it every sweep
// tells us nothing new), requests are spaced authMinInterval apart
// process-wide to fit inside the quota, and a failed refresh falls back to
// the last good snapshot instead of erasing the metadata.
const (
	// authRefreshInterval is how long a snapshot is served before a refresh is
	// attempted.
	authRefreshInterval = 12 * time.Hour
	// authMaxAge is the hard staleness ceiling. Past it the snapshot is dropped
	// and the metadata goes back to UNKNOWN (key omitted) rather than silently
	// asserting an ever-staler fact nobody can vouch for.
	authMaxAge = 7 * 24 * time.Hour
	// authMinInterval spaces Policy Analyzer requests across the whole process.
	// The quota is 10/min for the consumer project; 7s leaves headroom.
	authMinInterval = 7 * time.Second
	// authAttempts is the number of tries per refresh. Each retry still waits
	// out authMinInterval, so this is a backoff, not a burst.
	authAttempts = 3
)

// authSnapshot is one Policy Analyzer answer and when it was read.
type authSnapshot struct {
	values     map[string]time.Time
	observedAt time.Time
}

// authCache holds the last good Policy Analyzer answer per (project, activity
// type). It lives on the long-lived *Collector, so it survives across sweeps and
// is shared by every connector — which is what makes the request spacing
// meaningful, since they all spend the same consumer-project quota.
type authCache struct {
	mu       sync.Mutex
	entries  map[string]authSnapshot
	lastCall time.Time // when a Policy Analyzer request last went out

	// now and sleep are seams for tests; nil means time.Now and a real wait.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

func newAuthCache() *authCache {
	return &authCache{entries: map[string]authSnapshot{}}
}

func (c *authCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// wait blocks until the process-wide spacing gate allows another Policy
// Analyzer request, then records that one is going out.
func (c *authCache) wait(ctx context.Context) error {
	c.mu.Lock()
	elapsed := c.clock().Sub(c.lastCall)
	c.lastCall = c.clock()
	c.mu.Unlock()

	if elapsed >= authMinInterval {
		return nil
	}
	delay := authMinInterval - elapsed
	if c.sleep != nil {
		return c.sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// authResult is what the collector learned about one activity type this sweep.
type authResult struct {
	// values is lastAuthenticatedTime keyed by SA unique id / email / key id.
	values map[string]time.Time
	// ok is false when nothing usable is known — no fresh read and no snapshot
	// young enough to stand behind. The caller must then OMIT the metadata.
	ok bool
	// observedDays is the whole-day age of the read `values` came from: 0 for a
	// read taken now, N for one carried forward N days. It is written to the
	// asset so a consumer can tell a fresh observation from a carried one
	// without guessing.
	observedDays int
}

// lastAuth returns the Policy Analyzer answer for one project and activity type,
// refreshing at most every authRefreshInterval and falling back to the last good
// snapshot when a refresh fails.
func (c *authCache) lastAuth(ctx context.Context, client iamAPI, projectID, activityType string) authResult {
	key := projectID + "|" + activityType
	now := c.clock()

	c.mu.Lock()
	cached, hasCached := c.entries[key]
	c.mu.Unlock()

	if hasCached && now.Sub(cached.observedAt) < authRefreshInterval {
		return authResult{values: cached.values, ok: true, observedDays: ageDays(now, cached.observedAt)}
	}

	values, err := c.refresh(ctx, client, projectID, activityType)
	if err == nil {
		c.mu.Lock()
		c.entries[key] = authSnapshot{values: values, observedAt: c.clock()}
		c.mu.Unlock()
		return authResult{values: values, ok: true, observedDays: 0}
	}

	if hasCached && now.Sub(cached.observedAt) < authMaxAge {
		log.FromContext(ctx).Warn().Err(err).
			Str("project", projectID).Str("activity_type", activityType).
			Int("observed_days", ageDays(now, cached.observedAt)).
			Msg("gcp policy analyzer refresh failed — serving the last good read")
		return authResult{values: cached.values, ok: true, observedDays: ageDays(now, cached.observedAt)}
	}

	// Nothing fresh and nothing young enough to stand behind: unknown. Never a
	// fabricated value — the checks that read this metadata all fire on a
	// positive value, so an omitted key is silence.
	log.FromContext(ctx).Warn().Err(err).
		Str("project", projectID).Str("activity_type", activityType).
		Msg("gcp policy analyzer lookup skipped — usage metadata omitted this sweep")
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
	return authResult{}
}

// refresh performs the query, spacing each attempt behind the shared gate and
// retrying only errors that another attempt could plausibly fix.
func (c *authCache) refresh(ctx context.Context, client iamAPI, projectID, activityType string) (map[string]time.Time, error) {
	var err error
	for attempt := range authAttempts {
		if waitErr := c.wait(ctx); waitErr != nil {
			return nil, fmt.Errorf("refresh: %w", waitErr)
		}
		var values map[string]time.Time
		values, err = client.LastAuthentications(ctx, projectID, activityType)
		if err == nil {
			return values, nil
		}
		if !retryableAuthErr(err) || attempt == authAttempts-1 {
			return nil, fmt.Errorf("refresh: %w", err)
		}
	}
	return nil, fmt.Errorf("refresh: %w", err)
}

// retryableAuthErr reports whether another attempt could succeed. A quota 429
// or a 5xx can; a 403 (API not enabled, permission missing) or a 404 cannot,
// and retrying those just burns the shared per-minute budget.
func retryableAuthErr(err error) bool {
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) {
		return false // transport/unknown: do not spend more quota guessing
	}
	return apiErr.Code == 429 || apiErr.Code >= 500
}

func ageDays(now, observedAt time.Time) int {
	d := int(now.Sub(observedAt).Hours() / 24)
	if d < 0 {
		return 0
	}
	return d
}
