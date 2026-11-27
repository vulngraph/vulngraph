package finding

import (
	"context"
	"fmt"
)

func (s *Service) BaseRiskByResource(ctx context.Context) (map[string]uint8, error) {
	r, ok := s.repo.(interface {
		BaseRiskByResource(context.Context) (map[string]uint8, error)
	})
	if !ok {
		return nil, fmt.Errorf("BaseRiskByResource: repository does not support raw severity rollup")
	}
	return r.BaseRiskByResource(ctx)
}
