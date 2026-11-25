package enrich

import (
	"context"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// EPSSProvider returns a CVE's EPSS exploit-probability (0–1). Satisfied by the
// in-memory epss.Cache refreshed by the periodic EPSS job.
type EPSSProvider interface {
	Score(cve string) (float64, bool)
	// Loaded reports whether a catalog has been loaded at all. Before the first
	// successful refresh (boot, or a failing feed) "no score" means "not asked",
	// not "below 1%".
	Loaded() bool
}

// EPSS scores a CVE-bearing finding by its exploit probability — the "how
// likely to be exploited" axis that complements KEV (binary) and base severity.
// It applies to findings whose CheckID is a CVE (scanner and supply-chain
// findings) or that carry a CVE in metadata (nuclei templates keyed on a
// template slug); points scale with the probability band.
type EPSS struct{ Scores EPSSProvider }

func (EPSS) Name() string { return "epss" }

func (e EPSS) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	if e.Scores == nil {
		return Factor{}, false, nil
	}
	cve := findingCVE(f)
	if cve == "" {
		return Factor{}, false, nil
	}
	if !e.Scores.Loaded() {
		return Factor{}, false, fmt.Errorf("epss: catalog not loaded: %w", ErrSourceNotReady)
	}
	score, ok := e.Scores.Score(cve)
	if !ok {
		return Factor{}, false, nil
	}
	points := epssPoints(score)
	if points == 0 {
		return Factor{}, false, nil
	}
	return Factor{
		Source: "epss",
		Points: points,
		Detail: fmt.Sprintf("EPSS %.1f%% 30-day exploit probability", score*100),
	}, true, nil
}

// findingCVE returns the CVE a finding maps to — its CheckID when that is a
// CVE id (scanner/OSV/VM findings), else its "cve" metadata (nuclei
// templates keyed on a slug, MAL-* advisories with a CVE alias) — or "" when
// it maps to none. The same resolution the KEV refresh flags on.
func findingCVE(f finding.Finding) string {
	for _, c := range []string{f.CheckID, f.Metadata["cve"]} {
		if strings.HasPrefix(strings.ToUpper(c), "CVE-") {
			return c
		}
	}
	return ""
}

// epssPoints maps an EPSS probability to additive risk points. The bands favour
// the high end where exploitation is genuinely likely; sub-1% scores add nothing.
func epssPoints(score float64) int {
	switch {
	case score >= 0.5:
		return 15
	case score >= 0.1:
		return 8
	case score >= 0.01:
		return 3
	default:
		return 0
	}
}
