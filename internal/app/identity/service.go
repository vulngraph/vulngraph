package identity

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// cacheTTL is how long a census is reused. The census is a whole-population
// scan and the underlying data only moves when a collector sweep lands, so
// serving every dashboard load from ClickHouse would burn a FINAL scan per page
// view for a number that changes a few times an hour.
const cacheTTL = 5 * time.Minute

// Service computes the identity census.
type Service struct {
	repo Repo
	// now is injectable so tests get a fixed staleness clock.
	now func() time.Time

	mu     sync.Mutex
	cached *Census
	at     time.Time
}

func NewService(repo Repo) *Service {
	return &Service{repo: repo, now: time.Now}
}

// Census returns the identity census, recomputing it when the cached one is
// older than cacheTTL.
func (s *Service) Census(ctx context.Context) (Census, error) {
	now := s.now()

	s.mu.Lock()
	if s.cached != nil && now.Sub(s.at) < cacheTTL {
		c := *s.cached
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()

	in, err := s.repo.censusInput(ctx, now)
	if err != nil {
		return Census{}, fmt.Errorf("Census: %w", err)
	}
	c := buildCensus(in, now)

	s.mu.Lock()
	s.cached, s.at = &c, now
	s.mu.Unlock()
	return c, nil
}
