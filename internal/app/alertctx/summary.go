package alertctx

import (
	"fmt"
	"sort"
	"strings"
)

// finish sets the deterministic one-paragraph summary of an asset context. An
// unavailable section reads "unmeasured", never as a clean result.
func finish(ac *AssetContext) {
	a := ac.Asset
	var where []string
	for _, v := range []string{a.Provider, a.AccountID, a.Region} {
		if v != "" {
			where = append(where, v)
		}
	}
	if a.Environment != "" {
		where = append(where, "env "+a.Environment)
	}
	if a.Owner != "" {
		where = append(where, "owner "+a.Owner)
	}
	head := a.Type + " " + a.Name
	if len(where) > 0 {
		head += " (" + strings.Join(where, ", ") + ")"
	}
	parts := []string{head, riskSentence(a)}

	switch {
	case !ac.Exposure.Known:
		parts = append(parts, "internet exposure unmeasured")
	case ac.Exposure.ExposedToInternet:
		parts = append(parts, "directly exposed to the internet")
	default:
		parts = append(parts, "no direct internet exposure")
	}

	if !ac.Blast.Known {
		parts = append(parts, "blast radius unmeasured")
	} else {
		s := fmt.Sprintf("blast radius %d assets", ac.Blast.Count)
		if ac.Blast.Truncated {
			s = "blast radius at least " + fmt.Sprintf("%d assets", ac.Blast.Count)
		}
		parts = append(parts, s)
	}

	parts = append(parts, findingsSentence(ac.Findings))

	if p := ac.Privileges; p != nil {
		switch {
		case !p.Known:
			parts = append(parts, "privilege escalation unmeasured")
		case p.CanEscalate:
			parts = append(parts, fmt.Sprintf("can escalate privileges (%d techniques)", len(p.Techniques)))
		default:
			parts = append(parts, "no privilege escalation path detected")
		}
	}
	ac.Summary = strings.Join(parts, "; ") + "."
}

func findingsSentence(f Findings) string {
	if !f.Known {
		return "open findings unmeasured"
	}
	atLeast := ""
	if f.Truncated {
		atLeast = "at least "
	}
	s := fmt.Sprintf("%s%d open findings", atLeast, f.Total)
	if sev := severityList(f.BySeverity); sev != "" {
		s += " (" + sev + ")"
	}
	if len(f.MustFix) > 0 {
		s += fmt.Sprintf(", %d must-fix", len(f.MustFix))
	}
	return s
}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// severityList renders counts in severity order, then any unknown severities
// alphabetically, so the string is deterministic.
func severityList(by map[string]int) string {
	var out []string
	known := map[string]bool{}
	for _, s := range severityOrder {
		known[s] = true
		if n := by[s]; n > 0 {
			out = append(out, fmt.Sprintf("%d %s", n, s))
		}
	}
	var rest []string
	for s := range by {
		if !known[s] {
			rest = append(rest, s)
		}
	}
	sort.Strings(rest)
	for _, s := range rest {
		out = append(out, fmt.Sprintf("%d %s", by[s], s))
	}
	return strings.Join(out, ", ")
}

// resultSummary reports resolution coverage so a caller cannot miss that an
// identifier did not resolve or that a lookup failed.
func resultSummary(r Result) string {
	var resolved int
	var unresolved, failed []string
	for _, id := range r.Identifiers {
		switch id.Status {
		case StatusResolved:
			resolved++
		case StatusLookupFailed:
			failed = append(failed, id.Input)
		default:
			unresolved = append(unresolved, id.Input)
		}
	}
	s := fmt.Sprintf("%d of %d identifiers resolved to %d assets", resolved, len(r.Identifiers), len(r.Assets)+len(r.OmittedAssets))
	if len(unresolved) > 0 {
		s += "; unresolved: " + strings.Join(unresolved, ", ")
	}
	if len(failed) > 0 {
		s += "; lookup failed (not proof of absence): " + strings.Join(failed, ", ")
	}
	if r.Truncated {
		s += "; output truncated"
	}
	return s + "."
}

// riskSentence names the score's source: a stored score has not been raised by
// what the asset can reach, so it must not read as the propagated one.
func riskSentence(a AssetSummary) string {
	if a.RiskScoreSource == RiskSourceLadybug {
		return fmt.Sprintf("propagated risk score %d/100", a.RiskScore)
	}
	return fmt.Sprintf("stored risk score %d/100 (not graph-propagated)", a.RiskScore)
}
