package asset

import (
	"context"
	"fmt"
	"time"
)

type derivationRepo interface {
	BeginDerivedUpdate(context.Context) (time.Time, error)
	PublishFindingRisk(context.Context, time.Time, map[string]uint8) error
	WriteAnnotations(context.Context, time.Time, []Annotation) error
}

func (s *Service) BeginDerivedUpdate(ctx context.Context) (time.Time, error) {
	r, ok := s.repo.(derivationRepo)
	if !ok {
		return time.Time{}, fmt.Errorf("BeginDerivedUpdate: repository does not support derived state")
	}
	return r.BeginDerivedUpdate(ctx)
}
func (s *Service) PublishFindingRisk(ctx context.Context, version time.Time, scores map[string]uint8) error {
	r, ok := s.repo.(derivationRepo)
	if !ok {
		return fmt.Errorf("PublishFindingRisk: repository does not support derived state")
	}
	return r.PublishFindingRisk(ctx, version, scores)
}
func (s *Service) WriteAnnotations(ctx context.Context, version time.Time, annotations []Annotation) error {
	r, ok := s.repo.(derivationRepo)
	if !ok {
		return fmt.Errorf("WriteAnnotations: repository does not support derived state")
	}
	return r.WriteAnnotations(ctx, version, annotations)
}
