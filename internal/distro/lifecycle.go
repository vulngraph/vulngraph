package distro

import (
	"sort"
	"strings"
	"time"
)

// Lifecycle is when a release stops receiving standard vendor support.
type Lifecycle struct {
	End time.Time
	// Final means the vendor publishes NO advisories for the release after End —
	// no paid extended tier whose fixes still land in the feed. A host on a final
	// release can never be called clean by the absence of CVE findings: every
	// vulnerability disclosed after End is simply never published for it.
	Final bool
	// Note qualifies End for a responder (extended support tiers, renames).
	Note string
}

// Past reports whether the release is past its standard support end at now.
func (l Lifecycle) Past(now time.Time) bool { return !l.End.IsZero() && now.After(l.End) }

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic("distro: bad lifecycle date " + s)
	}
	return t
}

// Notes shared by every release of a family.
const (
	noteUbuntuESM  = "Ubuntu Pro ESM extends security fixes"
	noteDebianLTS  = "end of Debian LTS"
	noteRHELELS    = "Extended Life-cycle Support is sold separately"
	noteOracleES   = "Extended Support is sold separately"
	noteSUSELTSS   = "end of general support for this service pack; Long Term Service Pack Support (LTSS) is sold separately"
	noteAlpineEOL  = "Alpine publishes no fixes for a branch after its end of support"
	noteOpenSUSE   = "openSUSE Leap publishes no updates after a minor release's end of life"
	noteCentOSStrm = "CentOS Stream"
)

// lifecycles is end of STANDARD support per release, keyed by family and by
// the release distro.Release returns for that family's ecosystem coordinate
// ("Alpine:v3.20" → "v3.20", "openSUSE:Leap 15.6" → "15.6").
//
// Source: endoflife.date (https://endoflife.date/api/<product>.json — debian,
// ubuntu, alpine-linux, amazon-linux, rhel, rocky-linux, almalinux,
// oracle-linux, sles, opensuse, centos, centos-stream), checked 2026-10-08,
// which tracks the vendors' own lifecycle pages (linked in
// docs/iam/vm-software-inventory.md). End is the product's "eol" field: for
// Debian that is the end of LTS, for Ubuntu LTS the end of standard support
// (ESM is the "extendedSupport" field), for SUSE the service pack's end of
// general support (LTSS is the extended field).
//
// Only releases a fleet or an image plausibly still runs are listed. An
// unlisted release is "unknown", never "supported" — see EndOfLife.
var lifecycles = map[string]map[string]Lifecycle{
	"Amazon Linux": {
		"1":    {End: day("2023-12-31"), Final: true},
		"2":    {End: day("2026-06-30"), Final: true},
		"2023": {End: day("2029-06-30"), Final: true},
	},
	"CentOS": {
		"6":  {End: day("2020-11-30"), Final: true},
		"7":  {End: day("2024-06-30"), Final: true},
		"8":  {End: day("2021-12-31"), Final: true, Note: "CentOS Linux 8; CentOS Stream 8 ended 2024-05-31"},
		"9":  {End: day("2027-05-31"), Final: true, Note: noteCentOSStrm + " 9"},
		"10": {End: day("2030-05-31"), Final: true, Note: noteCentOSStrm + " 10"},
	},
	"Red Hat": {
		"6":  {End: day("2020-11-30"), Note: noteRHELELS},
		"7":  {End: day("2024-06-30"), Note: noteRHELELS},
		"8":  {End: day("2029-05-31"), Note: noteRHELELS},
		"9":  {End: day("2032-05-31"), Note: noteRHELELS},
		"10": {End: day("2035-05-31"), Note: noteRHELELS},
	},
	"Oracle Linux": {
		"6":  {End: day("2021-03-31"), Note: noteOracleES},
		"7":  {End: day("2024-12-31"), Note: noteOracleES},
		"8":  {End: day("2029-07-31"), Note: noteOracleES},
		"9":  {End: day("2032-06-30"), Note: noteOracleES},
		"10": {End: day("2035-06-30"), Note: noteOracleES},
	},
	"AlmaLinux": {
		"8":  {End: day("2029-05-31")},
		"9":  {End: day("2032-05-31")},
		"10": {End: day("2035-05-31")},
	},
	"Rocky Linux": {
		"8":  {End: day("2029-05-31")},
		"9":  {End: day("2032-05-31")},
		"10": {End: day("2035-05-31")},
	},
	"Ubuntu": {
		"14.04": {End: day("2019-04-30"), Note: noteUbuntuESM},
		"16.04": {End: day("2021-04-30"), Note: noteUbuntuESM},
		"18.04": {End: day("2023-05-31"), Note: noteUbuntuESM},
		"20.04": {End: day("2025-05-31"), Note: noteUbuntuESM},
		"22.04": {End: day("2027-06-01"), Note: noteUbuntuESM},
		"24.04": {End: day("2029-05-31"), Note: noteUbuntuESM},
		"26.04": {End: day("2031-05-29"), Note: noteUbuntuESM},
		"20.10": {End: day("2021-07-22"), Final: true},
		"21.04": {End: day("2022-01-20"), Final: true},
		"21.10": {End: day("2022-07-14"), Final: true},
		"22.10": {End: day("2023-07-20"), Final: true},
		"23.04": {End: day("2024-01-20"), Final: true},
		"23.10": {End: day("2024-07-12"), Final: true},
		"24.10": {End: day("2025-07-10"), Final: true},
		"25.04": {End: day("2026-01-17"), Final: true},
		"25.10": {End: day("2026-07-01"), Final: true},
	},
	"Debian": {
		"7":  {End: day("2018-05-31"), Final: true, Note: noteDebianLTS},
		"8":  {End: day("2020-06-30"), Final: true, Note: noteDebianLTS},
		"9":  {End: day("2022-07-01"), Final: true, Note: noteDebianLTS},
		"10": {End: day("2024-06-30"), Final: true, Note: noteDebianLTS},
		"11": {End: day("2026-08-31"), Final: true, Note: noteDebianLTS},
		"12": {End: day("2028-06-30"), Final: true, Note: noteDebianLTS},
		"13": {End: day("2030-06-30"), Final: true, Note: noteDebianLTS},
	},
	"Alpine": {
		"v3.9":  {End: day("2020-11-01"), Final: true, Note: noteAlpineEOL},
		"v3.10": {End: day("2021-05-01"), Final: true, Note: noteAlpineEOL},
		"v3.11": {End: day("2021-11-01"), Final: true, Note: noteAlpineEOL},
		"v3.12": {End: day("2022-05-01"), Final: true, Note: noteAlpineEOL},
		"v3.13": {End: day("2022-11-01"), Final: true, Note: noteAlpineEOL},
		"v3.14": {End: day("2023-05-01"), Final: true, Note: noteAlpineEOL},
		"v3.15": {End: day("2023-11-01"), Final: true, Note: noteAlpineEOL},
		"v3.16": {End: day("2024-05-23"), Final: true, Note: noteAlpineEOL},
		"v3.17": {End: day("2024-11-22"), Final: true, Note: noteAlpineEOL},
		"v3.18": {End: day("2025-05-09"), Final: true, Note: noteAlpineEOL},
		"v3.19": {End: day("2025-11-01"), Final: true, Note: noteAlpineEOL},
		"v3.20": {End: day("2026-04-01"), Final: true, Note: noteAlpineEOL},
		"v3.21": {End: day("2026-11-01"), Final: true, Note: noteAlpineEOL},
		"v3.22": {End: day("2027-05-01"), Final: true, Note: noteAlpineEOL},
		"v3.23": {End: day("2027-11-01"), Final: true, Note: noteAlpineEOL},
		"v3.24": {End: day("2028-06-01"), Final: true, Note: noteAlpineEOL},
	},
	"SUSE": {
		"12.5": {End: day("2024-10-31"), Note: noteSUSELTSS},
		"15.2": {End: day("2021-12-31"), Note: noteSUSELTSS},
		"15.3": {End: day("2022-12-31"), Note: noteSUSELTSS},
		"15.4": {End: day("2023-12-31"), Note: noteSUSELTSS},
		"15.5": {End: day("2024-12-31"), Note: noteSUSELTSS},
		"15.6": {End: day("2025-12-31"), Note: noteSUSELTSS},
		"15.7": {End: day("2031-07-31"), Note: noteSUSELTSS},
		"16.0": {End: day("2027-11-30"), Note: noteSUSELTSS},
	},
	"openSUSE": {
		"15.3": {End: day("2022-12-31"), Final: true, Note: noteOpenSUSE},
		"15.4": {End: day("2023-12-07"), Final: true, Note: noteOpenSUSE},
		"15.5": {End: day("2024-12-31"), Final: true, Note: noteOpenSUSE},
		"15.6": {End: day("2026-04-30"), Final: true, Note: noteOpenSUSE},
		"16.0": {End: day("2027-10-31"), Final: true, Note: noteOpenSUSE},
	},
}

// EndOfLife returns the lifecycle of the release an ecosystem coordinate names.
// ok=false means the release is not in the table: unknown, which a caller must
// not read as "supported".
func EndOfLife(ecosystem string) (Lifecycle, bool) {
	name, _, _ := strings.Cut(ecosystem, ":")
	l, ok := lifecycles[name][Release(ecosystem)]
	return l, ok
}

// LifecycleEcosystems lists one ecosystem coordinate per release in the
// lifecycle table, sorted. The end-of-life checks probe with them: their
// predicate reads the table, not literals, so the checks package's own probe
// derivation cannot see which values would make it fire.
func LifecycleEcosystems() []string {
	var out []string
	for family, releases := range lifecycles {
		for release := range releases {
			out = append(out, family+":"+release)
		}
	}
	sort.Strings(out)
	return out
}

// LatestSupported returns the family's release whose standard support runs the
// longest past now — the release a migration off an end-of-life one should
// target. ok=false when the family is not in the table or every listed release
// is already past its end. Ties (RHEL rebuilds released together) break on the
// release string so the answer is stable.
func LatestSupported(family string, now time.Time) (release string, ok bool) {
	var best time.Time
	for rel, l := range lifecycles[family] {
		if l.Past(now) {
			continue
		}
		if !ok || l.End.After(best) || (l.End.Equal(best) && rel > release) {
			release, best, ok = rel, l.End, true
		}
	}
	return release, ok
}
