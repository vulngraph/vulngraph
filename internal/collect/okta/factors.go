package okta

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// factorConcurrency bounds the per-user factor fan-out. Okta's /api/v1/users
// bucket is rate-limited per org (600 req/min on most tenants); eight in flight
// keeps a 10 000-user sweep inside that budget while finishing in minutes rather
// than hours.
const factorConcurrency = 8

// factorState is one user's MFA factor enrollment AS OBSERVED. A user appears in
// the factors map ONLY when their factor listing actually succeeded — a failed
// lookup leaves the user absent, so the caller emits no mfa_enabled key at all
// rather than emitting "false". enrich.IdentityHygiene and classifyRoleTrust
// both score mfa_enabled=="false" as a positive control gap, so an unobserved
// state must read as neither true nor false.
type factorState struct {
	// ActiveTypes are the deduplicated, sorted factorType values whose status is
	// ACTIVE. Enrolled-but-PENDING_ACTIVATION factors are not a usable second
	// factor yet, so they do not count.
	ActiveTypes []string
}

// enrolled reports whether the user holds at least one usable second factor.
func (f factorState) enrolled() bool { return len(f.ActiveTypes) > 0 }

// oktaFactor is one row of GET /api/v1/users/{id}/factors.
type oktaFactor struct {
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
	Status     string `json:"status"`
}

// userFactors fetches enrolled MFA factors for every user, bounded to
// factorConcurrency in flight. It returns the observed states keyed by user ID
// and the number of users whose lookup did not succeed.
//
// Failures are counted, never guessed: a user missing from the returned map has
// an UNKNOWN factor state and the caller must leave the key absent for them. A
// permanent failure (403 — the API token lacks the users-read scope for this
// endpoint) aborts the remaining fan-out instead of repeating it once per user;
// every unfetched user simply stays unknown.
func (c *Collector) userFactors(ctx context.Context, domain, token string, userIDs []string) (map[string]factorState, int) {
	out := make(map[string]factorState, len(userIDs))
	if len(userIDs) == 0 {
		return out, 0
	}

	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		permanent atomic.Bool
		sem       = make(chan struct{}, factorConcurrency)
	)

	for _, uid := range userIDs {
		if permanent.Load() {
			break
		}
		select {
		case <-ctx.Done():
			// Everything not yet dispatched stays unknown, which is the safe reading.
			wg.Wait()
			mu.Lock()
			defer mu.Unlock()
			return out, len(userIDs) - len(out)
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(uid string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.FromContext(ctx).Error().Interface("panic", r).
						Msg("okta: panic fetching user factors")
				}
			}()

			st, err := c.factorsForUser(ctx, domain, token, uid)
			if err != nil {
				if errors.Is(err, collect.ErrPermanent) {
					permanent.Store(true)
					log.FromContext(ctx).Warn().Err(err).
						Msg("okta: factor read rejected — MFA state stays unknown for every user")
				}
				return
			}
			mu.Lock()
			out[uid] = st
			mu.Unlock()
		}(uid)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	return out, len(userIDs) - len(out)
}

// factorsForUser reads one user's enrolled factors.
func (c *Collector) factorsForUser(ctx context.Context, domain, token, userID string) (factorState, error) {
	url := fmt.Sprintf("%s/api/v1/users/%s/factors", domain, userID)
	var factors []oktaFactor
	if _, err := c.doJSON(ctx, url, token, &factors); err != nil {
		return factorState{}, fmt.Errorf("factorsForUser %s: %w", userID, err)
	}

	seen := map[string]bool{}
	for _, f := range factors {
		if !strings.EqualFold(f.Status, "ACTIVE") {
			continue
		}
		t := strings.ToLower(strings.TrimSpace(f.FactorType))
		if t == "" {
			continue
		}
		seen[t] = true
	}
	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	sort.Strings(types)
	return factorState{ActiveTypes: types}, nil
}
