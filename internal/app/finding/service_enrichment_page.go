package finding

import (
	"context"
	"fmt"
)

func (s *Service) EnrichmentCandidates(ctx context.Context, f Filter) (EnrichmentPage, error) {
	page, err := s.repo.EnrichmentCandidates(ctx, f)
	if err != nil {
		return EnrichmentPage{}, fmt.Errorf("EnrichmentCandidates: %w", err)
	}
	return page, nil
}
