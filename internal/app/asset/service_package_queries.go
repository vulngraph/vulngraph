package asset

import (
	"context"
	"fmt"
)

func (s *Service) FindPackageVersions(ctx context.Context, name string, limit int) ([]Asset, error) {
	rows, err := s.repo.FindPackageVersions(ctx, name, limit)
	if err != nil {
		return nil, fmt.Errorf("FindPackageVersions: %w", err)
	}
	return rows, nil
}

func (s *Service) PackageRiskByRunner(ctx context.Context) (map[string]uint8, error) {
	scores, err := s.repo.PackageRiskByRunner(ctx)
	if err != nil {
		return nil, fmt.Errorf("PackageRiskByRunner: %w", err)
	}
	return scores, nil
}
