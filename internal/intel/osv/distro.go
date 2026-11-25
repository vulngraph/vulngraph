package osv

import (
	"sort"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/intel/rpmver"
)

// supportedFamilies is OSV's ecosystem list
// (https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt, read
// 2026-10-07), reduced to the family before any ':' qualifier. One query naming
// a family outside it fails the WHOLE /v1/querybatch call with HTTP 400
// ("invalid ecosystem"), so a package on such a family is excluded per package
// before it can cost every other package its refresh. queryIDs also recovers if
// this list goes stale — see errInvalidQuery.
var supportedFamilies = map[string]bool{
	"AlmaLinux": true, "Alpaquita": true, "Alpine": true, "Android": true,
	"Azure Linux": true, "BellSoft Hardened Containers": true, "Bitnami": true,
	"CRAN": true, "Chainguard": true, "CleanStart": true, "Debian": true, "Echo": true,
	"GHC": true, "GIT": true, "GSD": true, "GitHub Actions": true, "Go": true,
	"Hackage": true, "Hex": true, "Julia": true, "Linux": true, "Mageia": true,
	"Maven": true, "MinimOS": true, "NuGet": true, "OSS-Fuzz": true, "Packagist": true,
	"Pub": true, "PyPI": true, "Red Hat": true, "Rocky Linux": true, "Root": true,
	"RubyGems": true, "SUSE": true, "SwiftURL": true, "TuxCare": true, "UVI": true,
	"Ubuntu": true, "VSCode": true, "Wolfi": true, "crates.io": true, "npm": true,
	"opam": true, "openEuler": true, "openSUSE": true,
}

// Supported reports whether OSV serves an ecosystem coordinate's family.
// Amazon Linux, Oracle Linux and CentOS are not: the first two are matched by
// the distro advisory feeds (internal/intel/updateinfo), CentOS by nothing.
func Supported(ecosystem string) bool {
	family, _, _ := strings.Cut(ecosystem, ":")
	return supportedFamilies[family]
}

// target is how one Package is asked of OSV and how its answers are read back.
//
// Most coordinates are OSV ecosystems verbatim, and OSV's own version match is
// trusted. Two families are not: OSV keys Red Hat by CPE product stream
// ("Red Hat:enterprise_linux:9::appstream") and SUSE by product and service pack
// ("SUSE:Linux Enterprise Module for Basesystem 15 SP5"), and an inventory knows
// neither the repository a package came from nor the modules a host subscribes
// to. Those are queried by the bare family — which OSV matches across EVERY
// stream, so a RHEL 9 package is held against RHEL 7, 8 and 10 fixes too — and
// each returned advisory is kept only when an entry for the host's release
// contains the installed version, re-evaluated here with rpm's comparison.
type target struct {
	queryEcosystem string
	// match selects the affected[] entries that describe the host's release.
	match func(affectedEcosystem string) bool
	// recheck means the server's verdict spanned other releases and the
	// version must be re-evaluated against the matching entries.
	recheck bool
}

func targetFor(ecosystem string) target {
	family, release, _ := strings.Cut(ecosystem, ":")
	switch {
	case family == "Red Hat" && release != "":
		// enterprise_linux is the mainline stream: "…:9::baseos" through RHEL 9,
		// minor-scoped "…:10.1" from RHEL 10 (a mainline host rolls forward
		// through minors, so every minor's fix applies to it). EUS/AUS/E4S pins
		// (rhel_eus:9.4, enterprise_linux_eus:10.0) cannot be told apart from
		// an inventory and are not matched.
		streams := "Red Hat:enterprise_linux:" + release + "::"
		minors := "Red Hat:enterprise_linux:" + release + "."
		return target{queryEcosystem: family, recheck: true,
			match: func(a string) bool { return strings.HasPrefix(a, streams) || strings.HasPrefix(a, minors) }}
	case family == "SUSE" && release != "":
		token := suseToken(release)
		return target{queryEcosystem: family, recheck: true,
			match: func(a string) bool { return suseProductMatches(a, token) }}
	}
	return target{queryEcosystem: ecosystem, match: func(a string) bool { return a == ecosystem }}
}

// suseToken renders an os-release VERSION_ID the way SUSE product names spell
// it: "15.5" → "15 SP5", "15" → "15", "16.0" → "16.0" (SLES 16 dropped
// service packs).
func suseToken(release string) string {
	major, minor, ok := strings.Cut(release, ".")
	if !ok {
		return release
	}
	if minor == "0" {
		if n, err := strconv.Atoi(major); err == nil && n >= 16 {
			return release
		}
		return major
	}
	return major + " SP" + minor
}

// suseProductMatches reports whether a SUSE product ecosystem
// ("SUSE:Linux Enterprise Server 15 SP5-LTSS") is for the release token: the
// name ends with " <token>" or continues with "-<tier>" after it. LTSS and other
// tiers are kept: their fixes are what a host on that release needs, subscribed
// or not.
func suseProductMatches(affected, token string) bool {
	product, ok := strings.CutPrefix(affected, "SUSE:")
	if !ok {
		return false
	}
	return strings.HasSuffix(product, " "+token) || strings.Contains(product, " "+token+"-")
}

// affectsPackage reports whether v describes p at p's installed version. For
// re-checked families it requires an entry for p's release whose range holds
// the version; otherwise the server's answer stands.
func (v Vuln) affectsPackage(p Package) bool {
	t := targetFor(p.Ecosystem)
	if !t.recheck {
		return true
	}
	for _, a := range v.affected {
		if a.Package.Name == p.Name && t.match(a.Package.Ecosystem) && a.contains(p.Version) {
			return true
		}
	}
	return false
}

// contains evaluates an affected entry's explicit versions and ECOSYSTEM ranges
// with rpm version semantics. Used only for the rpm families targetFor
// re-checks.
func (a affectedPkg) contains(version string) bool {
	for _, ver := range a.Versions {
		if rpmver.Compare(ver, version) == 0 {
			return true
		}
	}
	for _, r := range a.Ranges {
		if r.Type == "ECOSYSTEM" && rpmRangeContains(r.Events, version) {
			return true
		}
	}
	return false
}

// rpmRangeContains walks a range's events in version order (OSV does not
// guarantee their order): introduced opens the range, fixed closes it at that
// version, last_affected closes it just after.
func rpmRangeContains(events []rangeEvent, version string) bool {
	sorted := append([]rangeEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return compareEvent(sorted[i].version(), sorted[j].version()) < 0
	})
	affected := false
	for _, e := range sorted {
		switch {
		case e.Introduced != "":
			if e.Introduced != "0" && rpmver.Compare(e.Introduced, version) > 0 {
				return affected
			}
			affected = true
		case e.Fixed != "":
			if rpmver.Compare(e.Fixed, version) > 0 {
				return affected
			}
			affected = false
		case e.LastAffected != "":
			if rpmver.Compare(e.LastAffected, version) >= 0 {
				return affected
			}
			affected = false
		}
	}
	return affected
}

// compareEvent orders event versions; "0" (introduced at the beginning of
// time) sorts first.
func compareEvent(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "0":
		return -1
	case b == "0":
		return 1
	}
	return rpmver.Compare(a, b)
}
