package belief

import (
	"sort"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Crystallization: once the adjudicator has judged the same structural shape
// of finding to the same true severity enough times — and every one of those
// verdicts survived the corroboration gate — the pattern is a candidate to
// become a cheap deterministic rule, so the LLM stops re-paying for a solved
// shape. This file is the pure mining core; it only identifies candidates.
// Promotion/auto-application is a separate, eval-gated slice — auto-trusting
// the model's own patterns is the collapse risk the anti-collapse design
// forbids.

// MinCrystallizeInstances is how many corroboration-surviving beliefs must share a
// signature+verdict before it is a candidate — enough that the pattern is a stable
// regularity, not a coincidence.
const MinCrystallizeInstances = 20

// PatternSignature is the tenant-agnostic STRUCTURAL shape of a finding — never its
// identity — so a crystallized rule generalizes across resources (and, eventually,
// anonymized across tenants).
type PatternSignature struct {
	ResourceType string
	Band         string
	MustFixClass string
}

// String renders the signature compactly for logs/metrics.
func (s PatternSignature) String() string {
	mfc := s.MustFixClass
	if mfc == "" {
		mfc = "-"
	}
	return s.ResourceType + "/" + s.Band + "/" + mfc
}

// CrystallizationInput is one corroboration-survivor adjudicator belief reduced to
// its structural signature and the true severity the adjudicator settled on.
type CrystallizationInput struct {
	Sig      PatternSignature
	Severity finding.Severity
}

// CrystallizationCandidate is a signature that maps to a single severity across at
// least MinCrystallizeInstances corroborated verdicts with no dissent — a stable,
// grounded pattern proposed for (eval-gated) crystallization.
type CrystallizationCandidate struct {
	Sig       PatternSignature
	Severity  finding.Severity
	Instances int
}

// MineCandidates groups corroboration-surviving inputs by signature and returns the
// stable ones: a signature qualifies ONLY when every input for it agrees on one
// severity (any dissent disqualifies it — an unstable shape must not crystallize)
// AND it recurs at least minInstances times. Deterministic order (most instances
// first, then signature) so logs/metrics are stable.
func MineCandidates(in []CrystallizationInput, minInstances int) []CrystallizationCandidate {
	if minInstances < 1 {
		minInstances = 1
	}
	type agg struct {
		sev      finding.Severity
		count    int
		dissents bool
	}
	bySig := map[PatternSignature]*agg{}
	for _, i := range in {
		a := bySig[i.Sig]
		if a == nil {
			bySig[i.Sig] = &agg{sev: i.Severity, count: 1}
			continue
		}
		a.count++
		if i.Severity != a.sev {
			a.dissents = true // the same shape got two different verdicts — not stable
		}
	}

	var out []CrystallizationCandidate
	for sig, a := range bySig {
		if a.dissents || a.count < minInstances {
			continue
		}
		out = append(out, CrystallizationCandidate{Sig: sig, Severity: a.sev, Instances: a.count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Instances != out[j].Instances {
			return out[i].Instances > out[j].Instances
		}
		return out[i].Sig.String() < out[j].Sig.String()
	})
	return out
}
