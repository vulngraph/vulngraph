package iac

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// DeclaredCIAccess is one cloud-identity assumption declared in a GitHub Actions
// workflow. Resolved is false when the target is a ${{ … }} expression / env /
// matrix value we cannot statically resolve — recorded for coverage honesty,
// never joined.
type DeclaredCIAccess struct {
	Provider     string // "aws" | "gcp"
	TargetARN    string // aws: full role ARN
	TargetSA     string // gcp: service_account email
	WorkflowPath string
	Resolved     bool
}

// workflowDoc is the narrow slice of the Actions workflow schema we read.
type workflowDoc struct {
	Jobs map[string]struct {
		Steps []struct {
			Uses string                 `yaml:"uses"`
			With map[string]interface{} `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// ParseWorkflow scans one workflow file for aws-actions/configure-aws-credentials
// (role-to-assume) and google-github-actions/auth (service_account) steps.
func ParseWorkflow(path string, content []byte) []DeclaredCIAccess {
	var doc workflowDoc
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil
	}
	var out []DeclaredCIAccess
	for _, job := range doc.Jobs {
		for _, step := range job.Steps {
			uses := strings.ToLower(step.Uses)
			switch {
			case strings.HasPrefix(uses, "aws-actions/configure-aws-credentials"):
				v := stringArg(step.With, "role-to-assume")
				out = append(out, DeclaredCIAccess{
					Provider:     "aws",
					TargetARN:    resolvedOrEmpty(v),
					WorkflowPath: path,
					Resolved:     isResolvable(v),
				})
			case strings.HasPrefix(uses, "google-github-actions/auth"):
				v := stringArg(step.With, "service_account")
				out = append(out, DeclaredCIAccess{
					Provider:     "gcp",
					TargetSA:     resolvedOrEmpty(v),
					WorkflowPath: path,
					Resolved:     isResolvable(v),
				})
			}
		}
	}
	return out
}

func stringArg(with map[string]interface{}, key string) string {
	if with == nil {
		return ""
	}
	if s, ok := with[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// isResolvable is true only for a non-empty literal value with no GitHub
// expression syntax.
func isResolvable(v string) bool {
	return v != "" && !strings.Contains(v, "${{")
}

func resolvedOrEmpty(v string) string {
	if isResolvable(v) {
		return v
	}
	return ""
}
