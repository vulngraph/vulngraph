package connector

import (
	"context"
	"fmt"
	"time"
)

func (s *Service) PendingAssetRetirements(ctx context.Context, limit int) (map[string]time.Time, error) {
	out, err := s.repo.PendingAssetRetirements(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("PendingAssetRetirements: %w", err)
	}
	return out, nil
}
func (s *Service) CompleteAssetRetirements(ctx context.Context, deletions map[string]time.Time) error {
	if err := s.repo.CompleteAssetRetirements(ctx, deletions); err != nil {
		return fmt.Errorf("CompleteAssetRetirements: %w", err)
	}
	return nil
}
