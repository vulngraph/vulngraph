package keyscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const baseSrc = `package checks

import "time"

const threshold = 90

type Check struct {
	ID       string
	Violates func(a Asset) bool
}

type Asset struct{ Metadata map[string]string }

var old = Check{ID: "old", Violates: tooOld}

var clock = Check{ID: "clock", Violates: func(a Asset) bool { return time.Now().Year() > 2000 && a.Metadata["k"] == "x" }}

func tooOld(a Asset) bool { return len(a.Metadata["age"]) > threshold }
`

func scanSrc(t *testing.T, src string) map[string]Result {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "c.go"), []byte(src), 0o600))
	out, err := Scan(dir)
	require.NoError(t, err)
	return out
}

func edit(t *testing.T, old, repl string) string {
	t.Helper()
	require.Contains(t, baseSrc, old)
	return strings.Replace(baseSrc, old, repl, 1)
}

// The logic digest moves when a check's reachable source changes — including a
// helper and a const it reads — and does not move for comments or blank lines,
// so documenting a check never forces a fleet-wide re-check.
func TestScan_LogicDigest(t *testing.T) {
	base := scanSrc(t, baseSrc)
	require.NotEmpty(t, base["old"].Logic)

	commented := scanSrc(t, edit(t, "func tooOld(a Asset) bool {",
		"// tooOld is documented now.\n\nfunc tooOld(a Asset) bool {\n\t// inline note\n\n"))
	require.Equal(t, base["old"].Logic, commented["old"].Logic, "comments and blank lines are not logic")

	helper := scanSrc(t, edit(t, "> threshold }", ">= threshold }"))
	require.NotEqual(t, base["old"].Logic, helper["old"].Logic, "a helper edit is a logic edit")
	require.Equal(t, base["clock"].Logic, helper["clock"].Logic, "an unrelated check keeps its digest")

	constant := scanSrc(t, edit(t, "const threshold = 90", "const threshold = 30"))
	require.NotEqual(t, base["old"].Logic, constant["old"].Logic, "a referenced const is part of the logic")
}

// A check calling into a logicPackages package carries that package's source
// in its digest: a behaviour change there moves it, a comment does not, and a
// check that never calls the package keeps its digest.
func TestScan_LogicPackageDigest(t *testing.T) {
	const checksSrc = `package checks

import "github.com/vulngraph/vulngraph/internal/cidrset"

type Check struct {
	ID       string
	Violates func(a Asset) bool
}

type Asset struct{ Metadata map[string]string }

var world = Check{ID: "world", Violates: func(a Asset) bool { return cidrset.CoversWorld([]string{a.Metadata["cidr"]}) }}

var plain = Check{ID: "plain", Violates: func(a Asset) bool { return a.Metadata["k"] == "x" }}
`
	const cidrsetSrc = `package cidrset

func CoversWorld(cidrs []string) bool { return len(cidrs) > 0 && cidrs[0] == "0.0.0.0/0" }
`
	scan := func(t *testing.T, pkgSrc string) map[string]Result {
		t.Helper()
		root := t.TempDir()
		for dir, src := range map[string]string{"checks": checksSrc, "cidrset": pkgSrc} {
			require.NoError(t, os.Mkdir(filepath.Join(root, dir), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(root, dir, dir+".go"), []byte(src), 0o600))
		}
		out, err := Scan(filepath.Join(root, "checks"))
		require.NoError(t, err)
		return out
	}

	base := scan(t, cidrsetSrc)
	changed := scan(t, strings.Replace(cidrsetSrc, `"0.0.0.0/0"`, `"::/0"`, 1))
	require.NotEqual(t, base["world"].Logic, changed["world"].Logic, "a behaviour change in a logic package is a logic edit")
	require.Equal(t, base["plain"].Logic, changed["plain"].Logic, "a check that never calls the package keeps its digest")

	commented := scan(t, strings.Replace(cidrsetSrc, "func CoversWorld", "// CoversWorld is documented.\n\nfunc CoversWorld", 1))
	require.Equal(t, base["world"].Logic, commented["world"].Logic, "comments in a logic package are not logic")

	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "checks"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "checks", "c.go"), []byte(checksSrc), 0o600))
	_, err := Scan(filepath.Join(root, "checks"))
	require.Error(t, err, "an unreadable logic package fails the scan rather than digesting nothing")
}

func TestScan_TimeDependent(t *testing.T) {
	got := scanSrc(t, baseSrc)
	require.True(t, got["clock"].TimeDependent)
	require.False(t, got["old"].TimeDependent)
}

// An imported value used as a comparand is reported, because the literal
// harvest cannot turn it into a probe; a comparison on a structural field is not.
func TestScan_UnresolvedComparands(t *testing.T) {
	src := `package checks

import "example.com/asset"

type Check struct {
	ID       string
	Violates func(a Asset) bool
}

type Asset struct {
	Provider string
	Metadata map[string]string
}

var pub = Check{ID: "pub", Violates: func(a Asset) bool { return a.Metadata["public_access"] == asset.Confirmed }}

var sw = Check{ID: "sw", Violates: isTier}

var structural = Check{ID: "structural", Violates: func(a Asset) bool { return a.Provider == asset.AWS && a.Metadata["k"] == "x" }}

func isTier(a Asset) bool {
	switch a.Metadata["tier"] {
	case asset.High:
		return true
	}
	return false
}
`
	got := scanSrc(t, src)
	require.Equal(t, []string{"asset.Confirmed"}, got["pub"].Unresolved)
	require.Equal(t, []string{"asset.High"}, got["sw"].Unresolved)
	require.Empty(t, got["structural"].Unresolved)
}
