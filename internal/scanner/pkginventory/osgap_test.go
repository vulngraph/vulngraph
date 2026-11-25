package pkginventory

import (
	"bytes"
	"context"
	"testing"
	"testing/fstest"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
)

var allFeeds = distro.Sources{distro.SourceOSV: true, distro.SourceALAS: true, distro.SourceELSA: true}

func osGap(t *testing.T, root fstest.MapFS) (eco, gap, detail string) {
	t.Helper()
	pkgs := InventoryPackages(context.Background(), root).Packages
	return OSCVEGap(root, pkgs, allFeeds, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
}

// "No OS package database" is not "no OS". A root whose os-release names a
// distribution but which yields no OS packages read as clean — Ubuntu Chiseled
// without its manifest, a dpkg database that parsed to nothing. Only a root
// with no os-release AND no database (scratch, a static binary) has no OS.
func TestOSCVEGap_DegradedRoots(t *testing.T) {
	const dpkg = "Package: openssl\nVersion: 3.0.11-1~deb12u2\nSource: openssl\n\n"
	tests := []struct {
		name    string
		root    fstest.MapFS
		wantEco string
		wantGap string
	}{
		{"scratch: no os-release, no database", fstest.MapFS{"app/server": {Data: []byte("x")}}, "", ""},
		{"ubuntu with no package database", fstest.MapFS{
			usrOSReleasePath: {Data: []byte("ID=ubuntu\nVERSION_ID=\"22.04\"\n")},
		}, "Ubuntu:22.04:LTS", asset.CVEGapPackageDBUnread},
		{"debian whose dpkg database parsed to nothing", fstest.MapFS{
			osReleasePath:  {Data: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			dpkgStatusPath: {Data: []byte("garbage\n")},
		}, "Debian:12", asset.CVEGapPackageDBUnread},
		{"alpine whose apk database is empty", fstest.MapFS{
			alpineReleasePath: {Data: []byte("3.21.0\n")},
			apkInstalledPath:  {Data: []byte("")},
		}, "Alpine:v3.21", asset.CVEGapPackageDBUnread},
		{"an unknown distribution is uncovered, not clean", fstest.MapFS{
			osReleasePath: {Data: []byte("ID=gentoo\n")},
		}, "", asset.CVEGapNoAdvisorySource},
		// The P0's tail: the base layer lost, so the dpkg database survived but
		// os-release did not. The unqualified "Debian" fallback is not a
		// release reading and must not be exempted as one.
		{"dpkg packages without os-release", fstest.MapFS{
			dpkgStatusPath: {Data: []byte(dpkg)},
		}, "Debian", asset.CVEGapUnknownRelease},
		{"debian testing has a real os-release with no VERSION_ID", fstest.MapFS{
			osReleasePath:  {Data: []byte("ID=debian\n")},
			dpkgStatusPath: {Data: []byte(dpkg)},
		}, "Debian", ""},
		{"distroless: status.d paragraphs are a database", fstest.MapFS{
			usrOSReleasePath:                       {Data: []byte("PRETTY_NAME=\"Distroless\"\nID=debian\nVERSION_ID=\"12\"\n")},
			"var/lib/dpkg/status.d/base-files":     {Data: []byte("Package: base-files\nVersion: 12.4+deb12u5\n\n")},
			"var/lib/dpkg/status.d/tzdata":         {Data: []byte("Package: tzdata\nVersion: 2024a-0+deb12u1\n\n")},
			"var/lib/dpkg/status.d/tzdata.md5sums": {Data: []byte("abc  usr/share/zoneinfo/UTC\n")},
		}, "Debian:12", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eco, gap, _ := osGap(t, tt.root)
			require.Equal(t, tt.wantEco, eco)
			require.Equal(t, tt.wantGap, gap)
		})
	}
}

// An rpm database on a Debian or Alpine root is not that root's OS inventory:
// it used to be read and stamped Debian:12, minting phantom Debian packages.
func TestInventoryPackages_RPMDatabaseOnlyForRPMDistributions(t *testing.T) {
	root := rpmRoot("ID=debian\nVERSION_ID=\"12\"\n", "var/lib/rpm/rpmdb.sqlite", rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz"))
	root[dpkgStatusPath] = &fstest.MapFile{Data: []byte("Package: rpm\nVersion: 4.18.0-4\n\n")}

	pkgs := InventoryPackages(context.Background(), root).Packages
	require.Len(t, pkgs, 1, "only the dpkg package — none from the rpm database")
	require.Equal(t, "rpm", pkgs[0].Name)
}

// Wolfi and Chainguard images use apk but are not Alpine. Stamped "Alpine"
// (no release) they matched nothing; OSV serves them as rolling ecosystems.
func TestInventoryPackages_WolfiAndChainguard(t *testing.T) {
	for _, tc := range []struct{ id, eco, purl string }{
		{"wolfi", "Wolfi", "pkg:apk/wolfi/openssl@3.3.2-r0"},
		{"chainguard", "Chainguard", "pkg:apk/chainguard/openssl@3.3.2-r0"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			root := fstest.MapFS{
				osReleasePath:    {Data: []byte("ID=" + tc.id + "\nVERSION_ID=20230201\n")},
				apkInstalledPath: {Data: []byte("P:openssl\nV:3.3.2-r0\no:openssl\n\n")},
			}
			pkgs := InventoryPackages(context.Background(), root).Packages
			require.Len(t, pkgs, 1)
			require.Equal(t, tc.eco, pkgs[0].Ecosystem)
			require.Equal(t, tc.purl, PURL(pkgs[0]))

			eco, gap, _ := OSCVEGap(root, pkgs, allFeeds, time.Now())
			require.Equal(t, tc.eco, eco)
			require.Empty(t, gap, "a rolling distribution needs no release to be matchable")
		})
	}
}

func chiselManifest(t *testing.T, lines string) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	require.NoError(t, err)
	_, err = enc.Write([]byte(lines))
	require.NoError(t, err)
	require.NoError(t, enc.Close())
	return buf.Bytes()
}

// Ubuntu Chiseled ships no dpkg database; chisel's manifest is its only
// inventory. It names no source package, so the Ubuntu advisories (keyed by
// source) are reported as not fully matchable rather than as clean.
func TestInventoryPackages_ReadsChiselManifest(t *testing.T) {
	wall := `{"jsonwall":"1.0","schema":"1.0","count":5}
{"kind":"package","name":"libc6","version":"2.35-0ubuntu3.8","sha256":"aa","arch":"amd64"}
{"kind":"package","name":"libssl3","version":"3.0.2-0ubuntu1.18","sha256":"bb","arch":"amd64"}
{"kind":"path","path":"/usr/lib/x86_64-linux-gnu/libc.so.6","mode":"0755","slices":["libc6_libs"]}
{"kind":"slice","name":"libc6_libs"}
`
	root := fstest.MapFS{
		usrOSReleasePath:   {Data: []byte("ID=ubuntu\nVERSION_ID=\"22.04\"\n")},
		chiselManifestPath: {Data: chiselManifest(t, wall)},
	}
	pkgs := InventoryPackages(context.Background(), root).Packages
	require.Len(t, pkgs, 2)
	require.Equal(t, "Ubuntu:22.04:LTS", pkgs[0].Ecosystem)
	require.Equal(t, "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.18", PURL(pkgs[1]))

	_, gap, _ := OSCVEGap(root, pkgs, allFeeds, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	require.Equal(t, asset.CVEGapNoSourceNames, gap)

	root[chiselManifestPath] = &fstest.MapFile{Data: []byte("not zstd")}
	_, gap, _ = osGap(t, root)
	require.Equal(t, asset.CVEGapPackageDBUnread, gap, "an unreadable manifest is an unread database, not no OS")
}
