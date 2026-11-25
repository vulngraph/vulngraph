package nuclei

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/llm"
)

// TemplateService implements scan.TemplateValidator and scan.TemplateTester
// so serve.go can wire them without importing nuclei directly in scan.
type TemplateService struct {
	allowInternal bool
}

// NewTemplateService honours scan.AllowInternalTargetsEnv for template tests.
func NewTemplateService() *TemplateService {
	return &TemplateService{allowInternal: scan.AllowInternalTargets()}
}

func (s *TemplateService) Validate(ctx context.Context, yamlContent string) scan.TemplateValidation {
	return Validate(ctx, yamlContent)
}

func (s *TemplateService) Test(ctx context.Context, yamlContent, targetURL string) ([]scan.Result, error) {
	return TestTemplate(ctx, yamlContent, targetURL, s.allowInternal)
}

// TemplateGeneratorAdapter adapts TemplateGenerator to scan.TemplateAIGenerator.
type TemplateGeneratorAdapter struct{ g *TemplateGenerator }

func NewTemplateGeneratorAdapter(client llm.Client, model string) *TemplateGeneratorAdapter {
	return &TemplateGeneratorAdapter{g: NewTemplateGenerator(client, model)}
}

func (a *TemplateGeneratorAdapter) Generate(ctx context.Context, description string) (string, scan.TemplateValidation, int, error) {
	return a.g.Generate(ctx, description)
}
