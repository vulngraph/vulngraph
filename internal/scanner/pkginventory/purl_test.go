package pkginventory

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPURLMatchesTheSBOMUniverse pins the package node id against REAL ids that
// already exist in graph.assets, one per shape that differs from a naive
// lowercase-everything purl.
//
// This is the single most important correctness property of image package
// scanning: the purl IS the node id, so an image-side purl that differs by one
// byte from the repo-SBOM side does not "partly match" — it mints a second,
// disconnected node, and "where does this package run" stays unanswerable while
// looking like it works. Each expectation below matches the id shape the repo
// SBOM collector emits (SELECT id FROM graph.assets WHERE type='package'), not
// one derived by hand from the purl spec.
func TestPURLMatchesTheSBOMUniverse(t *testing.T) {
	tests := []struct {
		name string
		pkg  InstalledPackage
		want string
	}{
		{
			// A scoped first-party package: depends_on edges from repos must meet
			// the runs_package edge on the same node.
			name: "npm scoped package keeps its scope path",
			pkg:  InstalledPackage{Ecosystem: "npm", Name: "@example/widget", Version: "1.4.0"},
			want: "pkg:npm/@example/widget@1.4.0",
		},
		{
			// npm ids can carry capitals. Lowercasing forks them.
			name: "npm keeps its case",
			pkg:  InstalledPackage{Ecosystem: "npm", Name: "JSONStream", Version: "1.3.5"},
			want: "pkg:npm/JSONStream@1.3.5",
		},
		{
			name: "gem keeps its case",
			pkg:  InstalledPackage{Ecosystem: "RubyGems", Name: "CFPropertyList", Version: "3.0.8"},
			want: "pkg:gem/CFPropertyList@3.0.8",
		},
		{
			// GitHub's dependency graph lowercases Go module paths: golang ids
			// are lowercase, this one included, even though the real module path
			// is github.com/Azure/….
			name: "golang module path is lowercased",
			pkg:  InstalledPackage{Ecosystem: "Go", Name: "github.com/Azure/azure-sdk-for-go", Version: "v54.0.0+incompatible"},
			want: "pkg:golang/github.com/azure/azure-sdk-for-go@v54.0.0%2Bincompatible",
		},
		{
			name: "golang ordinary module",
			pkg:  InstalledPackage{Ecosystem: "Go", Name: "aead.dev/minisign", Version: "v0.3.0"},
			want: "pkg:golang/aead.dev/minisign@v0.3.0",
		},
		{
			// pypi ids carry no underscore, dot or capital: GitHub emits the
			// PEP 503 normalised name.
			name: "pypi is PEP 503 normalised",
			pkg:  InstalledPackage{Ecosystem: "PyPI", Name: "Zope.Interface", Version: "4.7.1"},
			want: "pkg:pypi/zope-interface@4.7.1",
		},
		{
			name: "pypi already-normalised name is unchanged",
			pkg:  InstalledPackage{Ecosystem: "PyPI", Name: "absl-py", Version: "2.4.0"},
			want: "pkg:pypi/absl-py@2.4.0",
		},
		{
			// Many deb ids carry a literal +. Percent-encoding it here would
			// re-key every one of them and orphan their findings.
			name: "deb versions keep their literal plus",
			pkg:  InstalledPackage{Ecosystem: "Debian:11", Name: "adduser", Version: "3.118+deb11u1"},
			want: "pkg:deb/debian/adduser@3.118+deb11u1",
		},
		{
			name: "alpine keeps its distro scope and drops the release qualifier",
			pkg:  InstalledPackage{Ecosystem: "Alpine:v3.19", Name: "openssl", Version: "3.1.4-r5"},
			want: "pkg:apk/alpine/openssl@3.1.4-r5",
		},
		{
			name: "ubuntu is its own scope",
			pkg:  InstalledPackage{Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "3.0.2-0ubuntu1.15"},
			want: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15",
		},
		{
			name: "an unmapped ecosystem still gets a stable id",
			pkg:  InstalledPackage{Ecosystem: "Conda", Name: "NumPy", Version: "1.26.0"},
			want: "pkg:generic/conda/numpy@1.26.0",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, PURL(tc.pkg))
		})
	}
}

// The OSV ecosystem strings the parsers stamp are the ones OSV actually
// publishes under. Every value here was checked against the LIVE api.osv.dev,
// the way the distro qualifiers were: the near-miss spellings return zero
// advisories, which is indistinguishable from a clean image.
//
//	npm      lodash 4.17.20                → 5
//	PyPI     requests 2.25.1               → 8
//	RubyGems rack 2.2.3                    → 32   ("gem"    → 0)
//	Go       github.com/gin-gonic/gin v1.6.0 → 5   ("golang" → 0)
func TestLanguageEcosystemsAreTheOSVNames(t *testing.T) {
	require.Equal(t, "npm",
		npmInstalledPackages("node_modules/x/package.json", []byte(`{"name":"x","version":"1"}`))[0].Ecosystem)
	require.Equal(t, "PyPI",
		pyDistInfoPackages("x-1.dist-info/METADATA", []byte("Name: x\nVersion: 1\n"))[0].Ecosystem)
	require.Equal(t, "RubyGems",
		gemSpecPackages("specifications/x-1.gemspec")[0].Ecosystem)
	require.Equal(t, "Go",
		goModulePackages("bin/app", []*debug.Module{{Path: "x", Version: "v1"}})[0].Ecosystem)
}
