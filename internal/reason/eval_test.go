//go:build eval

// eval_test.go — reasoning-quality gate. Opt-in: it makes real LLM calls,
// so it runs only under `-tags=eval` with a provider configured, never in
// normal CI. Its job is to catch reasoning regressions — a system-prompt
// edit, model change, or provider switch that flips a decision — before
// they ship. The provider comes from the same env the app reads (see
// internal/llm FromEnv); REASON_API_KEY is accepted as an Anthropic key.
//
//	REASON_API_KEY=sk-ant-... go test -tags=eval ./internal/reason/ -run TestReasoningGolden -v
//	LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3 go test -tags=eval ./internal/reason/ -v
//
// The seed set (goldenCases, golden_cases_test.go) is deliberately tiny and
// unambiguous. Grow it: every time a real finding is mis-decided, add it with
// the correct expectation so the gate locks the fix in. Judgement calls
// between adjacent classes (remediate vs modify) don't belong here — only
// cases where the right answer is not in doubt.
package reason_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/internal/reason"
)

// evalClient builds the LLM client the golden sets grade, skipping when no
// provider is configured.
func evalClient(t *testing.T) llm.Client {
	t.Helper()
	getenv := func(k string) string {
		if k == "ANTHROPIC_API_KEY" {
			if v := os.Getenv("REASON_API_KEY"); v != "" {
				return v
			}
		}
		return os.Getenv(k)
	}
	c, err := llm.New(llm.FromEnv(getenv))
	if errors.Is(err, llm.ErrNotConfigured) {
		t.Skip("no LLM provider configured (REASON_API_KEY / ANTHROPIC_API_KEY / LLM_*) — skipping live eval")
	}
	if err != nil {
		t.Fatalf("llm config: %v", err)
	}
	return c
}

func TestReasoningGolden(t *testing.T) {
	r := reason.New(evalClient(t), os.Getenv("REASON_MODEL"))

	for _, tc := range goldenCases() {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := r.Reason(context.Background(), tc.pack)
			if err != nil {
				t.Fatalf("Reason: %v", err)
			}
			observed := plan.ActionClass == respond.ClassObserve
			switch {
			case tc.mustObserve && !observed:
				t.Errorf("expected observe, got %q — rationale: %s", plan.ActionClass, plan.Rationale)
			case !tc.mustObserve && observed:
				t.Errorf("expected an action, got observe — rationale: %s", plan.Rationale)
			}
		})
	}
}
