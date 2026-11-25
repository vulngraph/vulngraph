package belief

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// scriptedSampler returns a preset sequence of verdicts (one per Sample call).
type scriptedSampler struct {
	verdicts []Verdict
	errs     []error
	i        int
}

func (s *scriptedSampler) Sample(context.Context, AdjudicationInput) (Verdict, error) {
	i := s.i
	s.i++
	if i < len(s.errs) && s.errs[i] != nil {
		return Verdict{}, s.errs[i]
	}
	return s.verdicts[i], nil
}

func ev(sev finding.Severity) Verdict {
	return Verdict{Severity: sev, Evidence: []Evidence{{Clause: "adversarial review", Source: "reasoner", Fact: string(sev)}}}
}

func in3() AdjudicationInput {
	return AdjudicationInput{FindingID: "f1", ResourceID: "role/admin", RawScore: 92, RawBand: "page", Context: "graph ctx"}
}

// cancelDuringSampleSampler cancels its own context from INSIDE Sample, then
// returns the resulting cancellation error — simulating a real LLM call that
// was already in flight when a concurrent shutdown cancelled the sweep's
// context. context.CancelFunc is synchronous (ctx.Err() is non-nil the moment
// cancel() returns), so this reliably reproduces the shape a plain ctx.Err()
// check BEFORE calling Sample cannot catch: the context was still live at that
// moment, and only became cancelled during the call itself. Used by both
// Adjudicate's own cascade-level test (here) and Run's cheap-check-level test
// (sweep_test.go) — the identical gap existed at both call sites.
type cancelDuringSampleSampler struct {
	cancel context.CancelFunc
}

func (s cancelDuringSampleSampler) Sample(ctx context.Context, _ AdjudicationInput) (Verdict, error) {
	s.cancel()
	return Verdict{}, fmt.Errorf("Sample: do: %w", ctx.Err())
}

func TestAdjudicate_UnanimousHighConfidence(t *testing.T) {
	s := &scriptedSampler{verdicts: []Verdict{ev(finding.SeverityLow), ev(finding.SeverityLow), ev(finding.SeverityLow)}}
	b, _, err := Adjudicate(context.Background(), s, in3(), 3, time.Unix(0, 0))
	require.NoError(t, err)
	require.Equal(t, finding.SeverityLow, b.Severity)
	require.Equal(t, ConfidenceHigh, b.Confidence)
	require.Equal(t, StatusConfirmed, b.Status)
	require.Equal(t, "adjudicator", b.Provenance)
	require.NoError(t, b.Validate())
}

func TestAdjudicate_MajorityMediumConfidence(t *testing.T) {
	s := &scriptedSampler{verdicts: []Verdict{ev(finding.SeverityLow), ev(finding.SeverityLow), ev(finding.SeverityHigh)}}
	b, _, err := Adjudicate(context.Background(), s, in3(), 3, time.Unix(0, 0))
	require.NoError(t, err)
	require.Equal(t, finding.SeverityLow, b.Severity, "2/3 majority wins")
	require.Equal(t, ConfidenceMedium, b.Confidence)
	require.Equal(t, StatusConfirmed, b.Status)
}

func TestAdjudicate_SplitEscalates(t *testing.T) {
	s := &scriptedSampler{verdicts: []Verdict{ev(finding.SeverityLow), ev(finding.SeverityHigh), ev(finding.SeverityMedium)}}
	b, _, err := Adjudicate(context.Background(), s, in3(), 3, time.Unix(0, 0))
	require.NoError(t, err)
	require.Equal(t, ConfidenceLow, b.Confidence)
	require.Equal(t, StatusProposed, b.Status)
	require.Contains(t, b.Claim, "human review")
	require.NoError(t, b.Validate(), "escalation belief is still grounded (raw score cited)")
}

func TestAdjudicate_TooFewSamplesEscalates(t *testing.T) {
	// Two of three samples error → only one opinion → escalate.
	s := &scriptedSampler{
		verdicts: []Verdict{ev(finding.SeverityLow)},
		errs:     []error{nil, errors.New("timeout"), errors.New("timeout")},
	}
	// verdicts indexes: sample 0 ok (uses verdicts[0]); samples 1,2 error.
	s.verdicts = []Verdict{ev(finding.SeverityLow), {}, {}}
	b, fails, err := Adjudicate(context.Background(), s, in3(), 3, time.Unix(0, 0))
	require.NoError(t, err)
	require.Equal(t, ConfidenceLow, b.Confidence)
	require.Equal(t, StatusProposed, b.Status)
	require.Equal(t, 2, fails.Count, "the two failed escalation samples are surfaced, not hidden")
	// Regression: Adjudicate used to return only a bare int count, so the
	// escalation cascade's actual error message had nowhere to go and was
	// silently discarded even though it was right there in `err` inside the
	// loop — see SampleFailures' doc comment.
	require.EqualError(t, fails.First, "timeout", "the first failure's actual message must survive, not just its count")
}

// Regression: sweep.go's ctx.Err() check (Run's
// outer loop) only covers cancellation BETWEEN candidates — a candidate
// already inside Adjudicate's own N-sample cascade when the context is
// cancelled had no equivalent check, so every remaining escalation sample
// would fail with "context canceled" and get counted as an ordinary sample
// failure, exactly the GraphAdjudicatorDegraded{sample_error} false-positive
// this whole fix exists to close. panicSampler (sweep_test.go, same package)
// proves Sample is never even called once the context is already done.
func TestAdjudicate_ContextCanceledStopsCascadeWithoutCountingFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, fails, err := Adjudicate(ctx, panicSampler{t}, in3(), 3, time.Unix(0, 0))
	require.NoError(t, err)
	require.Zero(t, fails.Count, "a cancelled context must stop the cascade, not count every remaining attempt as a sample failure")
}

// Regression, found by a later review: the fix above
// only catches cancellation BETWEEN samples (ctx.Err() checked before calling
// Sample). A sample already in flight when cancellation happens still returns
// an ordinary-looking error from that specific call, which the first fix
// cannot distinguish from a genuine sampler failure — cancelDuringSampleSampler
// reproduces exactly that: it cancels its OWN context from inside Sample, so
// the context is still live when Adjudicate checks it before the call, and
// only becomes cancelled during the call itself.
func TestAdjudicate_ContextCanceledMidFlightStopsCascadeWithoutCountingFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, fails, err := Adjudicate(ctx, cancelDuringSampleSampler{cancel: cancel}, in3(), 3, time.Unix(0, 0))
	require.NoError(t, err)
	require.Zero(t, fails.Count,
		"a sample that failed BECAUSE its own context was cancelled mid-flight must not count as a sampler failure")
}

// agreeTwiceThenCancelSampler returns the same agreeing verdict for its first
// two calls, cancelling its OWN context as the second call returns — so by
// the time Adjudicate's top-of-loop ctx.Err() check runs before a 3rd
// attempt, the cascade has exactly 2 genuine, mutually-agreeing verdicts and
// a live cancellation, with no sampler failure anywhere in the picture.
type agreeTwiceThenCancelSampler struct {
	cancel context.CancelFunc
	v      Verdict
	i      int
}

func (s *agreeTwiceThenCancelSampler) Sample(context.Context, AdjudicationInput) (Verdict, error) {
	s.i++
	if s.i == 2 {
		s.cancel()
	}
	return s.v, nil
}

// Regression, found by a further review: majoritySeverity
// and the confidence branch below it have no notion of how many samples were
// actually requested versus how many came back — 2 agreeing verdicts out of a
// cascade cut short at n=3 looked byte-for-byte identical to a cascade
// genuinely configured for n=2, and were reported as ConfidenceHigh/
// StatusConfirmed ("all 2 samples agreed") even though the cascade never got
// the rigor it was asked for. The cancellation check makes this worse, not
// better: without it, the abandoned 3rd attempt would fail with a plain error
// and leave an incidental fails.Count>0 trace, so a human debugging a
// suspicious high-confidence belief has at least one clue. With it, the trace
// is gone and the misclassification is completely silent — the exact "value indistinguishable
// from a good one" shape this whole platform's degraded-input pattern exists
// to close (CLAUDE.md). truncated (Adjudicate's own variable) now
// forces escalation regardless of how many partial verdicts agree.
func TestAdjudicate_TruncatedCascadeEscalatesEvenWhenPartialVerdictsAgree(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &agreeTwiceThenCancelSampler{cancel: cancel, v: ev(finding.SeverityHigh)}
	b, fails, err := Adjudicate(ctx, s, in3(), 3, time.Unix(0, 0))
	require.NoError(t, err)
	require.Zero(t, fails.Count, "the cascade was cut short by its own cancellation, not a sampler failure")
	require.Equal(t, StatusProposed, b.Status,
		"2 agreeing verdicts out of an intended 3, cut short by cancellation, must escalate — not be reported as full unanimous convergence")
	require.NotEqual(t, ConfidenceHigh, b.Confidence)
	require.Contains(t, b.Claim, "human review")
	require.True(t, fails.Truncated,
		"the caller (Run) needs to know this escalation was caused by OUR cancellation, not genuine disagreement, so it can skip the full RevalidateAfter caching stamp")
}

// TestIsContextCancellation pins the shared helper's exact behavior: it is the
// single home for "was this Sample() failure (or about-to-be-made call) caused
// by our own context being torn down" — a plain ctx.Err() != nil check, no
// more, no less, so the helper cannot regress to a different check (e.g.
// errors.Is on the returned err) while it is the only place the logic lives.
func TestIsContextCancellation(t *testing.T) {
	require.False(t, isContextCancellation(context.Background()), "a live context is not a cancellation")

	deadlineCtx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	require.True(t, isContextCancellation(deadlineCtx), "an exceeded deadline counts as cancellation")

	cancelCtx, cancelFn := context.WithCancel(context.Background())
	require.False(t, isContextCancellation(cancelCtx), "not yet cancelled")
	cancelFn()
	require.True(t, isContextCancellation(cancelCtx), "cancelled context is reported")
}

// TestNoInlineCtxErrCancellationChecks keeps isContextCancellation the only
// cancellation check in this package's production code. An inline ctx.Err()
// at a call site can drift from the helper (checking only before Sample, or
// errors.Is on the sampler's error), and TestIsContextCancellation then pins a
// helper the call site no longer uses.
func TestNoInlineCtxErrCancellationChecks(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var inline []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "isContextCancellation" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Err" {
					return true
				}
				if recv, ok := sel.X.(*ast.Ident); ok && strings.HasSuffix(strings.ToLower(recv.Name), "ctx") {
					inline = append(inline, fset.Position(call.Pos()).String())
				}
				return true
			})
		}
	}
	require.Emptyf(t, inline, "inline ctx.Err() outside isContextCancellation: %v", inline)
}

// TestDedupeEvidence_ParaphrasedClausesCollapseOnFactIdentity is the
// regression guard for the multi-sample adjudicator's near-duplicate
// evidence bug: three independent LLM samples restating the SAME
// (source, fact) with different prose must collapse to one bullet, keyed
// on the grounding identity (Source, Fact), not on the rendered Clause.
func TestDedupeEvidence_ParaphrasedClausesCollapseOnFactIdentity(t *testing.T) {
	in := []Evidence{
		{Source: "must_fix", Fact: "elevated", Clause: "Reachability is a transitive trust-path claim (1 hop)"},
		{Source: "must_fix", Fact: "elevated", Clause: "Reachability is a transitive trust-path claim, verified by the deterministic graph traversal"},
		{Source: "must_fix", Fact: "elevated", Clause: "reachability is a transitive trust-path claim (1 hop)"}, // case-only variant
	}
	out := dedupeEvidence(in)
	require.Len(t, out, 1, "three paraphrases of the same (source, fact) must collapse to one bullet")
	require.Equal(t, in[0].Clause, out[0].Clause, "first-seen clause wins")
}

// TestDedupeEvidence_DistinctFactsSurvive proves the fix above does not
// over-merge: two genuinely different facts on the same source must both
// survive, even with similar-looking prose.
func TestDedupeEvidence_DistinctFactsSurvive(t *testing.T) {
	in := []Evidence{
		{Source: "blast_radius", Fact: "5 reachable asset(s); dependents=11", Clause: "Blast radius is real but moderate — 5 reachable assets, 11 dependents"},
		{Source: "blast_radius", Fact: "47 reachable asset(s); dependents=3", Clause: "Blast radius is real and broad — 47 reachable assets, 3 dependents"},
	}
	out := dedupeEvidence(in)
	require.Len(t, out, 2, "distinct facts on the same source must never merge")
}
