// Package rpmver compares RPM package versions the way rpm itself does, so a
// distro advisory's "fixed in" version can be held against an installed one.
//
// It is a port of rpmvercmp (rpm/lib/rpmvercmp.c, rpm >= 4.15 for the caret)
// plus the epoch:version-release split rpm applies before calling it. A string
// compare or a semver library gets these wrong in exactly the cases distro
// backports produce: "1.0.2k" vs "1.0.2", "2.el9_4" vs "2.el9", a bumped epoch.
package rpmver

import (
	"strings"
)

// EVR is one parsed epoch:version-release. Epoch is kept as a digit string with
// leading zeros stripped ("" means 0), so arbitrarily large epochs compare
// correctly without integer overflow.
type EVR struct {
	Epoch   string
	Version string
	Release string
}

// Parse splits "[epoch:]version[-release]". The epoch is everything before the
// first ':' when that prefix is all digits; the release is everything after the
// LAST '-' (versions cannot contain '-', releases can contain neither).
func Parse(s string) EVR {
	var e EVR
	if i := strings.IndexByte(s, ':'); i >= 0 && allDigits(s[:i]) {
		e.Epoch = strings.TrimLeft(s[:i], "0")
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		e.Version, e.Release = s[:i], s[i+1:]
	} else {
		e.Version = s
	}
	return e
}

// Compare orders two full EVR strings: -1 when a is older than b, 0 when rpm
// treats them as equal, 1 when a is newer. A missing epoch is 0. The release is
// compared only when both sides carry one, as rpm does — "1.0" satisfies a
// requirement on "1.0-3".
func Compare(a, b string) int {
	return CompareEVR(Parse(a), Parse(b))
}

// CompareEVR is Compare over already-parsed values.
func CompareEVR(a, b EVR) int {
	if c := compareDigits(a.Epoch, b.Epoch); c != 0 {
		return c
	}
	if c := Vercmp(a.Version, b.Version); c != 0 {
		return c
	}
	if a.Release == "" || b.Release == "" {
		return 0
	}
	return Vercmp(a.Release, b.Release)
}

// Vercmp is rpmvercmp: it compares one version OR release segment. Both strings
// are split into maximal runs of digits or letters; separators are skipped. Runs
// compare numerically when numeric, lexically otherwise, and a numeric run is
// always newer than an alphabetic one. '~' sorts before everything, including
// the end of the string (1.0~rc1 < 1.0); '^' sorts after the end of the string
// but before anything else (1.0 < 1.0^git1 < 1.0.1).
func Vercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		if at(a, i) == '~' || at(b, j) == '~' {
			if at(a, i) != '~' {
				return 1
			}
			if at(b, j) != '~' {
				return -1
			}
			i++
			j++
			continue
		}

		if at(a, i) == '^' || at(b, j) == '^' {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case a[i] != '^':
				return 1
			case b[j] != '^':
				return -1
			}
			i++
			j++
			continue
		}

		if i >= len(a) || j >= len(b) {
			break
		}

		si, sj := i, j
		numeric := isDigit(a[i])
		if numeric {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		segA, segB := a[si:i], b[sj:j]
		if segB == "" {
			// b's run is of the other kind: a numeric run beats an alpha one.
			if numeric {
				return 1
			}
			return -1
		}
		var c int
		if numeric {
			c = compareDigits(strings.TrimLeft(segA, "0"), strings.TrimLeft(segB, "0"))
		} else {
			c = strings.Compare(segA, segB)
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

// compareDigits orders two digit strings with no leading zeros by value.
func compareDigits(a, b string) int {
	if len(a) != len(b) {
		if len(a) > len(b) {
			return 1
		}
		return -1
	}
	return strings.Compare(a, b)
}

func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }
