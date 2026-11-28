package enrichcache

import (
	"context"
	"fmt"
	"time"
)

func (s *Service) GetSweepProgress(ctx context.Context) (SweepProgress, error) {
	p, err := s.repo.GetSweepProgress(ctx)
	if err != nil {
		return SweepProgress{}, fmt.Errorf("GetSweepProgress: %w", err)
	}
	return p, nil
}

func (s *Service) AdvanceSweepProgress(ctx context.Context, revision int64, next SweepProgress) (bool, error) {
	if revision < 0 || (next.Cursor != "" && next.Before.IsZero()) || !next.Before.Equal(next.Before.Truncate(time.Millisecond)) {
		return false, fmt.Errorf("AdvanceSweepProgress: invalid checkpoint")
	}
	ok, err := s.repo.AdvanceSweepProgress(ctx, revision, next)
	if err != nil {
		return false, fmt.Errorf("AdvanceSweepProgress: %w", err)
	}
	return ok, nil
}
