package distro

import "strings"

// CompareDpkg orders two Debian package versions ([epoch:]upstream[-revision])
// the way dpkg does (Debian Policy 5.6.12): -1 when a is older, 0 equal, 1
// newer. A string or rpm compare gets the distro cases wrong — "~" sorts
// before everything, even the end of the string, so 1.0~rc1 < 1.0.
func CompareDpkg(a, b string) int {
	ae, au, ar := splitDpkg(a)
	be, bu, br := splitDpkg(b)
	if c := compareNumeric(ae, be); c != 0 {
		return c
	}
	if c := verrevcmp(au, bu); c != 0 {
		return c
	}
	return verrevcmp(ar, br)
}

// splitDpkg splits epoch (before the first ':', digits), upstream and revision
// (after the last '-').
func splitDpkg(v string) (epoch, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// dpkgOrder is a character's weight in a non-digit run: '~' below the end of
// the string, letters before everything else.
func dpkgOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	}
	return int(c) + 256
}

// verrevcmp is dpkg's alternating non-digit / digit comparison.
func verrevcmp(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			ac, bc := 0, 0
			if a != "" {
				ac = dpkgOrder(a[0])
			}
			if b != "" {
				bc = dpkgOrder(b[0])
			}
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			a, b = a[1:], b[1:]
		}
		var ad, bd string
		ad, a = leadingDigits(a)
		bd, b = leadingDigits(b)
		if c := compareNumeric(ad, bd); c != 0 {
			return c
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func leadingDigits(s string) (digits, rest string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

// compareNumeric compares digit strings of any length without overflow.
func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
