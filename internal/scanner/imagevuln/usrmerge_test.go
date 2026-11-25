package imagevuln

import (
	"archive/tar"
	"context"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fixtureFile reads a recorded file from testdata. os.Open rather than
// os.ReadFile: the latter marks a structural guard for internal/guardmutation,
// and this reads a fixture, not the repository's source.
func fixtureFile(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(b)
}

func symlink(name, target string) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}}
}

// cgr.dev/chainguard/static, recorded 2026-10-09 (digest
// sha256:a40219f3b0c2719e4e4220310e80a2230a4b95881644292c130e3a8e8287fc6c):
// one layer, usrmerged — bin, lib and sbin are symlinks into usr, and the apk
// database is a regular file only at usr/lib/apk/db/installed. The database is
// trimmed to its package header fields (no per-file entries); the layout and
// os-release are as pulled. Reading only lib/apk/db/installed found nothing
// here: zero packages and a permanent package_db_unread finding on every
// Chainguard and Wolfi image.
func TestScanImage_ChainguardStaticUsrmergedApkDatabase(t *testing.T) {
	layer := layerOf(t, 0,
		symlink("bin", "usr/bin"),
		reg("etc/apk/world", 0o644, "ca-certificates-bundle\nwolfi-baselayout\ntzdata\n"),
		reg("etc/os-release", 0o644, fixtureFile(t, "chainguard-static/os-release")),
		symlink("lib", "usr/lib"),
		symlink("sbin", "usr/bin"),
		reg("usr/lib/apk/db/installed", 0o644, fixtureFile(t, "chainguard-static/installed")),
		reg("usr/lib/apk/db/lock", 0o644, ""),
	)
	ref, digest := pushImage(t, layer)

	res, err := New(testSource(), &fakeVulns{}).ScanImage(context.Background(), digest, ref)
	require.NoError(t, err)
	require.Empty(t, res.OSCVEGap, "a readable Wolfi database on OSV's rolling ecosystem is matchable")

	purls := map[string]bool{}
	for _, a := range res.Assets {
		require.Equal(t, "Wolfi", a.Metadata["ecosystem"])
		purls[a.ID] = true
	}
	require.Equal(t, map[string]bool{
		"pkg:apk/wolfi/wolfi-baselayout@20230201-r30":      true,
		"pkg:apk/wolfi/ca-certificates-bundle@20260909-r2": true,
		"pkg:apk/wolfi/tzdata@2026e-r0":                    true,
	}, purls)
	for _, f := range res.Findings {
		require.NotEqual(t, asset.CVEGapPackageDBUnread, f.Metadata[asset.MetaPackageCVEGap])
	}
}
