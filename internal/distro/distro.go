// Package distro is the one place that knows, per Linux distribution, which
// advisory source covers its packages, how that source names them, and when the
// release stops being patched at all.
//
// It is pure data. The VM inventory producers read it to decide whether a host's
// package list can support a CVE verdict (internal/scanner/pkginventory), the OSV
// client reads it to choose a query name (internal/intel/osv), the end-of-life
// checks read the lifecycle table (internal/checks), and the coverage report
// renders it so a gap stays visible. A second copy in any of those would drift.
//
// Ecosystem strings are the package coordinate the producers stamp: an OSV
// ecosystem verbatim where OSV has one ("Debian:12", "Ubuntu:22.04:LTS",
// "openSUSE:Leap 15.5"), else "<Family>:<release>" ("Red Hat:9", "SUSE:15.5",
// "Amazon Linux:2023") which the matching source translates.
package distro

import (
	"sort"
	"strings"
)

// Advisory sources a family can be matched against.
const (
	SourceOSV  = "osv"  // api.osv.dev
	SourceALAS = "alas" // Amazon Linux Security Center, via the repos' updateinfo.xml
	SourceELSA = "elsa" // Oracle Linux errata, via the public yum server's updateinfo.xml
)

// Family is one distribution's advisory coverage.
type Family struct {
	Name string
	// Source names the advisory source that covers the family, "" for none.
	Source string
	// SourceKeyed means the source publishes advisories against SOURCE package
	// names (openssl-3) rather than the binary names an rpm/dpkg inventory lists
	// (libopenssl3). Querying such a source by binary name silently matches only
	// the binaries that happen to share their source's name.
	SourceKeyed bool
	// NoSourceReason explains an empty Source, for the coverage report.
	NoSourceReason string
	// Rolling means the distribution has no releases: its advisories are
	// published under the bare family, so a coordinate without a release is
	// complete rather than unresolved.
	Rolling bool
}

// families is keyed by the ecosystem family (the part before the first ':').
var families = map[string]Family{
	"Debian":       {Name: "Debian", Source: SourceOSV, SourceKeyed: true},
	"Ubuntu":       {Name: "Ubuntu", Source: SourceOSV, SourceKeyed: true},
	"Alpine":       {Name: "Alpine", Source: SourceOSV, SourceKeyed: true},
	"Wolfi":        {Name: "Wolfi", Source: SourceOSV, SourceKeyed: true, Rolling: true},
	"Chainguard":   {Name: "Chainguard", Source: SourceOSV, SourceKeyed: true, Rolling: true},
	"AlmaLinux":    {Name: "AlmaLinux", Source: SourceOSV},
	"Rocky Linux":  {Name: "Rocky Linux", Source: SourceOSV, SourceKeyed: true},
	"Red Hat":      {Name: "Red Hat", Source: SourceOSV},
	"SUSE":         {Name: "SUSE", Source: SourceOSV, SourceKeyed: true},
	"openSUSE":     {Name: "openSUSE", Source: SourceOSV, SourceKeyed: true},
	"Amazon Linux": {Name: "Amazon Linux", Source: SourceALAS},
	"Oracle Linux": {Name: "Oracle Linux", Source: SourceELSA},
	"CentOS": {Name: "CentOS",
		NoSourceReason: "CentOS Linux 7/8 are end-of-life and CentOS Stream publishes no advisory feed; RHEL advisories describe different builds and are not borrowed"},
}

// FamilyOf returns the family of an ecosystem coordinate ("Debian:12" → Debian).
func FamilyOf(ecosystem string) (Family, bool) {
	name, _, _ := strings.Cut(ecosystem, ":")
	f, ok := families[name]
	return f, ok
}

// MatchedByOSV reports whether a package's advisories come from OSV: a
// language ecosystem (no distro family), or a family whose Source is OSV.
// Amazon Linux and Oracle Linux packages are matched by their vendor feeds from
// the package nodes; CentOS by nothing. A scanner that queries OSV inline must
// leave them out — OSV reports them unqueried, which fails the whole lookup.
func MatchedByOSV(ecosystem string) bool {
	f, ok := FamilyOf(ecosystem)
	return !ok || f.Source == SourceOSV
}

// AdvisoryQuery returns the package name and version an advisory source must be
// asked about for one installed binary package. A source-keyed family publishes
// against the source package at the SOURCE version, so a binary that carries its
// source identity is asked by that: Debian's libssl3 by openssl, a binNMU
// "1.2-3+b1" by its source's "1.2-3", gcc 4:12.2.0-3 by gcc-defaults 1.203.
// sourceVersion is empty when it equals the binary's. Everything else — a
// binary-keyed family, a language ecosystem, a binary with no source name — is
// asked by its own name and version.
func AdvisoryQuery(ecosystem, name, version, sourceName, sourceVersion string) (queryName, queryVersion string) {
	if f, ok := FamilyOf(ecosystem); !ok || !f.SourceKeyed || sourceName == "" {
		return name, version
	}
	if sourceVersion != "" {
		return sourceName, sourceVersion
	}
	return sourceName, version
}

// Sources is the set of advisory sources a deployment actually queries, keyed by
// Source*. A feed is switched off on its own (INTEL_OSV_DISABLED,
// INTEL_ALAS_DISABLED, INTEL_ELSA_DISABLED) or with every other (OFFLINE_MODE).
// The zero value enables nothing, so a caller that never says which feeds are
// on reports every family unmatchable rather than matchable and clean.
type Sources map[string]bool

// Families lists every known family, sorted by name, for the coverage report.
func Families() []Family {
	out := make([]Family, 0, len(families))
	for _, f := range families {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Release returns the release an ecosystem coordinate names: "Ubuntu:22.04:LTS"
// → "22.04", "openSUSE:Leap 15.5" → "15.5", "Debian" → "".
func Release(ecosystem string) string {
	_, rest, ok := strings.Cut(ecosystem, ":")
	if !ok {
		return ""
	}
	rel, _, _ := strings.Cut(rest, ":")
	return strings.TrimPrefix(rel, "Leap ")
}
