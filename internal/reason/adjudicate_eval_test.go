//go:build eval

// adjudicate_eval_test.go — severity-adjudicator quality gate.
// Opt-in like eval_test.go: it makes real LLM calls, so it runs only under
// `-tags=eval` with a provider configured, never in normal CI.
//
//	REASON_API_KEY=sk-... go test -tags=eval ./internal/reason/ -run TestAdjudicatorGolden -v
//
// Measures whether the adjudicator gets the true severity right in both
// directions. Each case is coarse and unambiguous:
//   - mustHold: a genuinely reachable, uncontrolled critical must survive at
//     high/critical — falsifies a reflexive demotion bias.
//   - mustDemote: a contained / unreachable / mislabeled high must come down
//     to medium/low — catches false-highs.
//
// Grow it: every time a real finding is mis-adjudicated, add its context to
// adjGoldenCases (golden_cases_test.go) with the correct direction so the
// gate locks the fix in. Debatable one-band calls (high vs critical, medium
// vs low) are deliberately not pinned — only the hold-vs-demote boundary,
// where the right answer is not in doubt.
package reason_test

import (
	"context"
	"os"
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/reason"
)

func TestAdjudicatorGolden(t *testing.T) {
	r := reason.New(evalClient(t), os.Getenv("ADJUDICATOR_MODEL"))

	var pass int
	cases := adjGoldenCases()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := r.Sample(context.Background(), tc.in)
			if err != nil {
				t.Fatalf("Sample: %v", err)
			}
			// A miss is logged, not failed: a failed subtest fails the whole
			// test, which would make the fraction gate below an all-or-nothing
			// one. The gate decides.
			held := isHighOrAbove(v.Severity)
			switch {
			case tc.mustHold && !held:
				t.Logf("MISS — DEMOTION BIAS: expected the verdict to hold high/critical, got %q\n  evidence: %v", v.Severity, v.Evidence)
			case !tc.mustHold && held:
				t.Logf("MISS — FALSE HIGH: expected a demotion to medium/low, got %q\n  evidence: %v", v.Severity, v.Evidence)
			default:
				pass++
			}
		})
	}
	// Hard accuracy gate on the golden set: every case is a coarse, unambiguous
	// hold-vs-demote call, so the bar is high (adjMaxMisses).
	misses := len(cases) - pass
	t.Logf("adjudicator golden set: %d/%d correct (gate: at most %d miss)", pass, len(cases), adjMaxMisses)
	if misses > adjMaxMisses {
		t.Errorf("adjudicator missed %d of %d cases, more than the %d allowed — the prompt or corroboration logic has regressed", misses, len(cases), adjMaxMisses)
	}
}

func isHighOrAbove(s finding.Severity) bool {
	return s == finding.SeverityHigh || s == finding.SeverityCritical
}
