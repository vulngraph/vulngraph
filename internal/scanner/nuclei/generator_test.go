package nuclei

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/llm"
)

func TestCleanYAML_StripsFences(t *testing.T) {
	fenced := "```yaml\nid: test\ninfo:\n  name: Test\n  severity: low\n```"
	got := cleanYAML(fenced)
	require.Equal(t, "id: test\ninfo:\n  name: Test\n  severity: low", got)
}

func TestCleanYAML_NoFences(t *testing.T) {
	plain := "id: test\ninfo:\n  name: Test"
	require.Equal(t, plain, cleanYAML(plain))
}

func TestBuildErrorList(t *testing.T) {
	errs := []scan.TemplateValidationError{
		{Line: 3, Message: "missing required field: id"},
		{Message: "no protocol block"},
	}
	list := buildErrorList(errs)
	require.Contains(t, list, "Line 3")
	require.Contains(t, list, "missing required field: id")
	require.Contains(t, list, "no protocol block")
}

func TestValidGoodTemplateRoundtrip(t *testing.T) {
	// End-to-end: cleanYAML + Validate on a known-good template
	raw := "```yaml\nid: test-roundtrip\ninfo:\n  name: Test\n  author: a\n  severity: medium\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers:\n      - type: word\n        words: [\"test\"]\n```"
	yaml := cleanYAML(raw)
	result := Validate(t.Context(), yaml)
	require.True(t, result.Valid, "cleaned template should be valid: %v", result.Errors)
	require.Equal(t, "test-roundtrip", result.Info.ID)
}

// erroringLLM fails every call, standing in for a bad key or an outage.
type erroringLLM struct{}

func (erroringLLM) Complete(context.Context, llm.Request) (*llm.Response, error) {
	return nil, errors.New("401 invalid key")
}

func (erroringLLM) Stream(context.Context, llm.Request, func(string)) (*llm.Response, error) {
	return nil, errors.New("401 invalid key")
}

func (erroringLLM) Provider() llm.Provider { return "fake" }

// TestGenerateLLMError verifies an LLM failure surfaces as an error with zero
// attempts counted — not a panic — without any network call.
func TestGenerateLLMError(t *testing.T) {
	gen := NewTemplateGenerator(erroringLLM{}, "")
	_, _, attempts, err := gen.Generate(context.Background(), "check for public S3 buckets")
	require.ErrorContains(t, err, "invalid key")
	require.Equal(t, 0, attempts, "0 attempts on immediate LLM error")
}

func TestGenerateNotConfigured(t *testing.T) {
	_, _, _, err := NewTemplateGenerator(nil, "").Generate(context.Background(), "x")
	require.ErrorContains(t, err, "no LLM provider configured")
}

// scriptedLLM returns its responses in order and records each request.
type scriptedLLM struct {
	resps []*llm.Response
	reqs  []llm.Request
}

func (s *scriptedLLM) Complete(_ context.Context, req llm.Request) (*llm.Response, error) {
	s.reqs = append(s.reqs, req)
	return s.resps[len(s.reqs)-1], nil
}

func (s *scriptedLLM) Stream(context.Context, llm.Request, func(string)) (*llm.Response, error) {
	return nil, errors.New("not used")
}

func (s *scriptedLLM) Provider() llm.Provider { return "fake" }

// An empty reply must not become a blank assistant turn in the retry
// conversation (Anthropic rejects those; the llm layer drops them).
func TestGenerateEmptyReplyGetsPlaceholderTurn(t *testing.T) {
	client := &scriptedLLM{resps: []*llm.Response{{Text: ""}, {Text: ""}, {Text: ""}}}
	_, _, attempts, err := NewTemplateGenerator(client, "").Generate(context.Background(), "check x")
	require.NoError(t, err)
	require.Equal(t, maxGenerationAttempts, attempts)
	second := client.reqs[1].Messages
	require.Len(t, second, 3)
	require.Equal(t, llm.RoleAssistant, second[1].Role)
	require.Equal(t, emptyReplyPlaceholder, second[1].Text)
}

func TestGenerateRefusalStopsRetrying(t *testing.T) {
	client := &scriptedLLM{resps: []*llm.Response{{StopReason: llm.StopRefusal, Refusal: llm.Refusal{Explanation: "policy"}}}}
	_, _, attempts, err := NewTemplateGenerator(client, "").Generate(context.Background(), "check x")
	require.ErrorContains(t, err, "refused")
	require.Equal(t, 1, attempts)
	require.Len(t, client.reqs, 1)
}
