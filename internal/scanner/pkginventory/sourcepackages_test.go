package pkginventory

import (
	"context"
	"os"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"
)

// The fixtures under testdata/ are trimmed from real images (debian:12.0,
// ubuntu:22.04, alpine:3.18.0, gcr.io/distroless/base-debian12), read
// 2026-10-07.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return data
}

func byName(pkgs []InstalledPackage) map[string]InstalledPackage {
	out := map[string]InstalledPackage{}
	for _, p := range pkgs {
		out[p.Name] = p
	}
	return out
}

// OSV keys Debian and Ubuntu advisories by SOURCE package, so every dpkg package
// must carry its source: the Source field when present, its own name when
// absent, and the source version only when it differs from the binary's (bash
// 5.2.15-2+b2 is a binNMU of source bash 5.2.15-2).
//
// The release comes from usr/lib/os-release: on Debian and Ubuntu,
// etc/os-release is a symlink to it, which the image scanner never follows.
func TestDpkgPackages_CarrySourcePackage(t *testing.T) {
	root := fstest.MapFS{
		usrOSReleasePath: {Data: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
		dpkgStatusPath:   {Data: readFixture(t, "dpkg-status-debian12")},
	}
	got := byName(InventoryPackages(context.Background(), root).Packages)
	require.Len(t, got, 4)

	tests := []struct {
		bin, version, srcName, srcVersion string
	}{
		{"libc6", "2.36-9", "glibc", ""},
		{"bash", "5.2.15-2+b2", "bash", "5.2.15-2"},
		{"mount", "2.38.1-5+b1", "util-linux", "2.38.1-5"},
		{"base-files", "12.4", "base-files", ""},
	}
	for _, tt := range tests {
		p := got[tt.bin]
		require.Equal(t, "Debian:12", p.Ecosystem, tt.bin)
		require.Equal(t, tt.version, p.Version, tt.bin)
		require.Equal(t, tt.srcName, p.SourceName, tt.bin)
		require.Equal(t, tt.srcVersion, p.SourceVersion, tt.bin)
	}
}

func TestDpkgPackages_UbuntuSource(t *testing.T) {
	root := fstest.MapFS{
		osReleasePath:  {Data: []byte("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n")},
		dpkgStatusPath: {Data: readFixture(t, "dpkg-status-ubuntu2204")},
	}
	got := byName(InventoryPackages(context.Background(), root).Packages)
	require.Equal(t, "openssl", got["libssl3"].SourceName,
		"libssl3 in Ubuntu:22.04:LTS matches 0 OSV advisories; openssl matches 66")
	require.Equal(t, "Ubuntu:22.04:LTS", got["libssl3"].Ecosystem)
	require.Equal(t, "zlib", got["zlib1g"].SourceName)
	require.Empty(t, got["zlib1g"].SourceVersion)
}

// A removed package whose config files linger keeps its paragraph in the status
// file; it is not installed software.
func TestDpkgPackages_SkipsPackagesNotInstalled(t *testing.T) {
	status := "Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0-1\n\n" +
		"Package: half\nStatus: install ok half-configured\nVersion: 1.0-1\n\n" +
		"Package: here\nStatus: install ok installed\nVersion: 1.0-1\n"
	got := byName(InventoryPackages(context.Background(), fstest.MapFS{dpkgStatusPath: {Data: []byte(status)}}).Packages)
	require.Len(t, got, 1)
	require.Contains(t, got, "here")
}

// Distroless images ship no status file: each package is a paragraph under
// status.d/, beside an md5sums file that is not a package.
func TestDpkgPackages_DistrolessStatusD(t *testing.T) {
	got := byName(InventoryPackages(context.Background(), os.DirFS("testdata/distroless")).Packages)
	require.Len(t, got, 2, "libssl3 and libc6; the md5sums file is not a package")
	require.Equal(t, "openssl", got["libssl3"].SourceName)
	require.Equal(t, "3.0.20-1~deb12u2", got["libssl3"].Version)
	require.Equal(t, "glibc", got["libc6"].SourceName)
	require.Equal(t, "Debian:12", got["libc6"].Ecosystem)
	require.Equal(t, "var/lib/dpkg/status.d/libssl3", got["libssl3"].Source)
}

func TestClassifyManifest_DpkgStatusD(t *testing.T) {
	require.Equal(t, KindDpkgStatusD, ClassifyManifest("var/lib/dpkg/status.d/libssl3", fileMode, 400))
	require.Equal(t, KindDpkgStatusD, ClassifyManifest("var/lib/dpkg/status.d/python3.11-minimal", fileMode, 400))
	require.Equal(t, KindNone, ClassifyManifest("var/lib/dpkg/status.d/libssl3.md5sums", fileMode, 400))
	require.Equal(t, KindNone, ClassifyManifest("var/lib/dpkg/status.d/nested/libssl3", fileMode, 400))
	require.Equal(t, KindOSRelease, ClassifyManifest(usrOSReleasePath, fileMode, 200))
	require.False(t, KindDpkgStatusD.IsLanguage(), "a status.d paragraph needs the release to be stamped")
}

// Alpine's secdb, and so OSV, is keyed by origin (the aport): libcrypto3 3.1.0-r0
// in Alpine:v3.18 matches 0 advisories, openssl matches 19.
func TestApkPackages_CarryOrigin(t *testing.T) {
	root := fstest.MapFS{
		osReleasePath:    {Data: []byte("ID=alpine\nVERSION_ID=3.18.0\n")},
		apkInstalledPath: {Data: readFixture(t, "apk-installed-alpine318")},
	}
	got := byName(InventoryPackages(context.Background(), root).Packages)
	require.Equal(t, "openssl", got["libcrypto3"].SourceName)
	require.Equal(t, "openssl", got["libssl3"].SourceName)
	require.Equal(t, "musl", got["musl"].SourceName)
	require.Empty(t, got["libcrypto3"].SourceVersion, "a subpackage always shares its origin's version")

	noOrigin := byName(InventoryPackages(context.Background(), fstest.MapFS{
		apkInstalledPath: {Data: []byte("P:custom\nV:1.0-r0\n\n")},
	}).Packages)
	require.Equal(t, "custom", noOrigin["custom"].SourceName, "no origin: the package is its own")
}

func TestPackageAsset_StampsSourceIdentity(t *testing.T) {
	p := InstalledPackage{Ecosystem: "Debian:12", Name: "bash", Version: "5.2.15-2+b2", SourceName: "bash", SourceVersion: "5.2.15-2"}
	a := packageAsset(p, PURL(p), "ec2_instance", time.Now())
	require.Equal(t, "bash", a.Metadata[MetaSourcePackage])
	require.Equal(t, "5.2.15-2", a.Metadata[MetaSourceVersion])

	p.SourceVersion = ""
	require.NotContains(t, packageAsset(p, PURL(p), "ec2_instance", time.Now()).Metadata, MetaSourceVersion)
}
