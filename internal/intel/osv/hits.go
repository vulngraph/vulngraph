package osv

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CVEs returns every CVE the advisory names — aliases first (GHSA and the
// language ecosystems put it there), then upstream (the distro databases) — in
// order and without repeats.
func (v Vuln) CVEs() []string {
	var out []string
	for _, list := range [][]string{v.Aliases, v.Upstream} {
		for _, a := range list {
			if strings.HasPrefix(a, "CVE-") && !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// CheckIDs is what one advisory becomes as findings: one per CVE it names. A
// distro advisory (DSA, USN, RHSA, SUSE-SU) bundles several CVEs, and KEV and
// EPSS match one CVE per finding — keying the finding on the first CVE alone
// would hide a known-exploited CVE listed second. An advisory naming no CVE keeps its
// own id, and so does a MAL-* advisory whatever it aliases: isMaliciousPackage
// (internal/app/enrich/sources_supply_chain.go) gates on the "MAL-" prefix.
func (v Vuln) CheckIDs() []string {
	if cves := v.CVEs(); len(cves) > 0 && !IsMalicious(v.ID) {
		return cves
	}
	return []string{v.ID}
}

// Hit is one check id matched on one package, merged across every advisory
// that names it: Debian publishes DSA-5611-1 and DEBIAN-CVE-2023-6246 for the
// same glibc CVE, Ubuntu a USN and an UBUNTU-CVE record, and both answer one
// query. One finding per (check id × package) needs one Hit, decided the same
// way whatever order OSV returned them in.
type Hit struct {
	CheckID string
	// Vuln is the most specific advisory naming the check id — the one naming
	// the fewest others (the per-CVE record over the bundle), then the lowest id.
	// Its summary, details and fixed version describe the hit.
	Vuln Vuln
	// Severity is the highest any merged advisory assigns.
	Severity finding.Severity
	// Advisories lists every merged advisory id, sorted.
	Advisories []string
}

// Hits merges a package's advisories into one Hit per check id, sorted by check
// id.
func Hits(vulns []Vuln) []Hit {
	byCheck := map[string]*Hit{}
	for _, v := range vulns {
		checks := v.CheckIDs()
		for _, check := range checks {
			h := byCheck[check]
			if h == nil {
				byCheck[check] = &Hit{CheckID: check, Vuln: v, Severity: v.Severity, Advisories: []string{v.ID}}
				continue
			}
			if !slices.Contains(h.Advisories, v.ID) {
				h.Advisories = append(h.Advisories, v.ID)
			}
			if moreSpecific(v, h.Vuln) {
				h.Vuln = v
			}
			if severityRank(v.Severity) > severityRank(h.Severity) {
				h.Severity = v.Severity
			}
		}
	}
	out := make([]Hit, 0, len(byCheck))
	for _, h := range byCheck {
		sort.Strings(h.Advisories)
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CheckID < out[j].CheckID })
	return out
}

// Describe titles and describes the hit as a finding. name is the package the
// advisory was asked about (the source package for source-keyed families), so
// every producer writing the same finding id writes the same text. An advisory
// bundling several CVEs is summarised for the bundle ("openssl - security
// update"), so its findings are titled per CVE and say what else it fixes.
func (h Hit) Describe(name string) (title, description string) {
	title, description = h.Vuln.Summary, h.Vuln.Details
	if bundled := h.Vuln.CheckIDs(); len(bundled) > 1 {
		title = fmt.Sprintf("%s in %s (%s)", h.CheckID, name, h.Vuln.ID)
		description = strings.TrimSpace(description + "\n\n" + h.Vuln.ID + " also fixes: " + strings.Join(bundled, ", ") + ".")
	}
	if title == "" {
		title = h.CheckID + " in " + name
	}
	return title, description
}

// Advisory is the hit's advisory reference for finding metadata: every merged
// advisory id, comma-separated.
func (h Hit) Advisory() string { return strings.Join(h.Advisories, ",") }

func moreSpecific(a, b Vuln) bool {
	if na, nb := len(a.CheckIDs()), len(b.CheckIDs()); na != nb {
		return na < nb
	}
	return a.ID < b.ID
}

func severityRank(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 4
	case finding.SeverityHigh:
		return 3
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 1
	}
	return 0
}
