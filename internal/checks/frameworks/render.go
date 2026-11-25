package frameworks

import (
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
)

// RenderCoverage is the framework section of docs/cspm-coverage.md: per
// framework, how many requirements can pass at all, then how many have at
// least one mapped check (through a covered or partial benchmark control) out
// of every requirement listed. The percentage sits on "can pass" so a mapping
// count is never read as a pass rate. The live pass/fail/unknown rollup is the
// compliance API's (ADR 093).
func RenderCoverage(fws []Framework, bs []benchmarks.Benchmark) string {
	ix := NewIndex(bs)
	var w strings.Builder
	w.WriteString("\n## Compliance framework requirements\n\n")
	w.WriteString("Requirement-level mappings in `internal/checks/frameworks` (ADR 093). A requirement counts as mapped when ")
	w.WriteString("at least one benchmark control it maps has a registry check; whether it passes is decided live from ")
	w.WriteString("findings and inventory. \"Partial source mapping\" counts requirements where some source mappings (a Prowler check, an AWS related FSBP control) reach no graph control; those can never pass. ")
	w.WriteString("\"Can pass\" counts requirements with no structural gap: every control they map is fully covered by a check and every source mapping reaches one. Every other requirement shows failing or unknown at best, except that a control for a provider you do not connect is out of scope and does not block a pass, however much of it is covered. Requirement IDs and short titles only; ISO, PCI and AICPA titles are paraphrased.\n\n")
	w.WriteString("| Framework | Version | Requirements | Can pass | With ≥1 mapped check | Mapped to a control only | No mapping | Partial source mapping |\n")
	w.WriteString("|---|---|---:|---:|---:|---:|---:|---:|\n")
	for _, fw := range fws {
		var canPass, checked, controlOnly, none, partial int
		for _, r := range fw.Requirements {
			if ix.CanPass(r) {
				canPass++
			}
			switch {
			case ix.HasCheck(r):
				checked++
			case len(r.Controls) > 0:
				controlOnly++
			default:
				none++
			}
			if r.Unjoined > 0 {
				partial++
			}
		}
		total := len(fw.Requirements)
		fmt.Fprintf(&w, "| %s | %s | %d | %d (%s) | %d | %d | %d | %d |\n", fw.Name, fw.Version, total, canPass, pct(canPass, total), checked, controlOnly, none, partial)
	}
	return w.String()
}

func pct(n, total int) string {
	if total == 0 {
		return "0%"
	}
	return fmt.Sprintf("%d%%", n*100/total)
}
