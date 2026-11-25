package pkginventory

import "strings"

// ubuntuEcosystem returns the OSV ecosystem for an Ubuntu release.
//
// LTS releases are keyed WITH the ":LTS" suffix and interim releases without
// it. The suffix is load-bearing: "Ubuntu:20.04" and "Ubuntu:20.04:LTS" are
// BOTH accepted by the API but are not the same set — the bare form
// over-matches, unioning in advisories scoped to other releases entirely.
//
// Interim releases are genuinely unsuffixed — OSV publishes "Ubuntu:25.10" —
// so the suffix is applied only to actual LTS releases, which are the .04
// releases of even-numbered years.
func ubuntuEcosystem(versionID string) string {
	if versionID == "" {
		return "Ubuntu"
	}
	if isUbuntuLTS(versionID) {
		return "Ubuntu:" + versionID + ":LTS"
	}
	return "Ubuntu:" + versionID
}

// isUbuntuLTS reports whether a YY.MM version is an LTS release: Canonical ships
// LTS every two years in April, so it is the .04 release of an even year.
func isUbuntuLTS(versionID string) bool {
	year, month, ok := strings.Cut(versionID, ".")
	if !ok || month != "04" || len(year) != 2 {
		return false
	}
	for _, r := range year {
		if r < '0' || r > '9' {
			return false
		}
	}
	return (year[1]-'0')%2 == 0
}
