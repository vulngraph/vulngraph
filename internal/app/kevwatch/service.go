package kevwatch

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Repo is the catalog and additions store.
type Repo interface {
	KnownCVEs(ctx context.Context) (map[string]bool, error)
	Commit(ctx context.Context, entries []Entry, additions []Addition) ([]Addition, error)
	ListAdditions(ctx context.Context, limit int) ([]Addition, error)
}

// Service diffs each fetched catalog against the last one seen.
type Service struct {
	repo Repo
	now  func() time.Time
}

func NewService(repo Repo) *Service { return &Service{repo: repo, now: time.Now} }

// Reconcile records the catalog and returns the additions it newly recorded:
// every fetched CVE the stored catalog does not hold yet (on the first run,
// only those CISA added within BootstrapWindow). openFindings maps an
// upper-cased CVE id to its open finding count right now.
//
// The catalog upsert and the addition inserts commit together, so a failed
// run leaves nothing half-recorded and the next refresh diffs again; an
// addition already recorded is never returned twice.
func (s *Service) Reconcile(ctx context.Context, entries []Entry, openFindings map[string]int) ([]Addition, error) {
	known, err := s.repo.KnownCVEs(ctx)
	if err != nil {
		return nil, fmt.Errorf("Reconcile: %w", err)
	}
	bootstrap := len(known) == 0
	cutoff := s.now().Add(-BootstrapWindow)

	norm := make([]Entry, 0, len(entries))
	var additions []Addition
	for _, e := range entries {
		e.CVEID = strings.ToUpper(strings.TrimSpace(e.CVEID))
		if e.CVEID == "" {
			continue
		}
		norm = append(norm, e)
		if known[e.CVEID] {
			continue
		}
		// An unknown dateAdded on the first run is not evidence of recency.
		if bootstrap && (e.DateAdded.IsZero() || e.DateAdded.Before(cutoff)) {
			continue
		}
		additions = append(additions, Addition{
			CVEID: e.CVEID, DateAdded: e.DateAdded, Name: e.Name, OpenFindings: openFindings[e.CVEID],
		})
	}
	recorded, err := s.repo.Commit(ctx, norm, additions)
	if err != nil {
		return nil, fmt.Errorf("Reconcile: %w", err)
	}
	return recorded, nil
}

// Recent lists the most recently detected additions; limit is clamped to
// [1, MaxListLimit], defaulting to DefaultListLimit.
func (s *Service) Recent(ctx context.Context, limit int) ([]Addition, error) {
	if limit <= 0 {
		limit = DefaultListLimit
	}
	out, err := s.repo.ListAdditions(ctx, min(limit, MaxListLimit))
	if err != nil {
		return nil, fmt.Errorf("Recent: %w", err)
	}
	return out, nil
}
