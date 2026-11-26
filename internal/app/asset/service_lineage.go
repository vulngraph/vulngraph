package asset

import "context"

// LineageSources and LineageTargets return distinct typed endpoints within the
// requested cap. A truncated read cannot prove the absence of another path.
// Edge properties and the opposite endpoint are deliberately not loaded.
func (s *Service) LineageSources(ctx context.Context, ids []string, edgeType string, limit int) ([]Edge, bool, error) {
	return s.repo.LineageSources(ctx, ids, edgeType, limit)
}

func (s *Service) LineageTargets(ctx context.Context, ids []string, edgeType string, limit int) ([]Edge, bool, error) {
	return s.repo.LineageTargets(ctx, ids, edgeType, limit)
}

func (s *Service) AnyConfirmedExposure(ctx context.Context, ids []string) (bool, error) {
	return s.repo.AnyConfirmedExposure(ctx, ids)
}
