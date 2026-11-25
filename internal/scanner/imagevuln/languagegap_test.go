package imagevuln

import (
	"archive/tar"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func hardlink(name, target string) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeLink, Linkname: target, Mode: 0o644}}
}

// A hardlink at a manifest path is taken without being read: the content is
// the link target's. At a language manifest that is a language gap; at an OS
// package database it is an unread OS database, so the walk is incomplete.
func TestReadManifests_HardlinkedManifestsAreGaps(t *testing.T) {
	layer := layerOf(t, 0,
		reg("opt/real.json", 0o644, `{"name":"lodash","version":"4.17.21"}`),
		hardlink("app/node_modules/lodash/package.json", "opt/real.json"),
	)
	w, err := RegistryImageSource{}.readManifests(imageOf(t, layer))
	require.NoError(t, err)
	require.Contains(t, w.languageGap, "app/node_modules/lodash/package.json is a hardlink")
	require.Empty(t, w.incomplete)

	osLayer := layerOf(t, 0,
		reg("opt/status", 0o644, "Package: a\nVersion: 1\n\n"),
		hardlink("var/lib/dpkg/status", "opt/status"),
	)
	w, err = RegistryImageSource{}.readManifests(imageOf(t, osLayer))
	require.NoError(t, err)
	require.Contains(t, w.incomplete, "var/lib/dpkg/status is a hardlink")

	// A root lockfile is a language manifest too: hardlinked, it is a language gap.
	lockLayer := layerOf(t, 0,
		reg("opt/lock", 0o644, "{}"),
		hardlink("package-lock.json", "opt/lock"),
	)
	w, err = RegistryImageSource{}.readManifests(imageOf(t, lockLayer))
	require.NoError(t, err)
	require.Contains(t, w.languageGap, "package-lock.json is a hardlink")
	require.Empty(t, w.incomplete, "a lockfile is not the OS database")
}

// A hardlink whose target the walk already read adds the same packages again,
// so it is no gap: a conda image links every env file to its pkgs/ cache. A
// pnpm-style store the walk does not read stays a gap.
func TestReadManifests_HardlinkToAReadTargetIsNoGap(t *testing.T) {
	const meta = "Name: requests\nVersion: 2.31.0\n"
	conda := layerOf(t, 0,
		reg("opt/conda/pkgs/requests-2.31.0/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA", 0o644, meta),
		hardlink("opt/conda/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA",
			"opt/conda/pkgs/requests-2.31.0/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA"),
	)
	w, err := RegistryImageSource{}.readManifests(imageOf(t, conda))
	require.NoError(t, err)
	require.Empty(t, w.languageGap, "the linked content was inventoried at its target")
	require.Len(t, w.packages, 1)

	pnpm := layerOf(t, 0,
		reg("root/.local/share/pnpm/store/v3/files/3f/9a1c", 0o644, `{"name":"lodash","version":"4.17.21"}`),
		hardlink("app/node_modules/lodash/package.json", "./root/.local/share/pnpm/store/v3/files/3f/9a1c"),
	)
	w, err = RegistryImageSource{}.readManifests(imageOf(t, pnpm))
	require.NoError(t, err)
	require.Contains(t, w.languageGap, "app/node_modules/lodash/package.json is a hardlink")
}

// A language gap is reported as its own coverage finding and never touches the
// OS verdict: a fully matched Debian base stays matched while a Go binary or a
// lockfile is missed.
func TestScanImage_LanguageGapDoesNotFlipTheOSGap(t *testing.T) {
	layer := layerOf(t, 0,
		reg("etc/os-release", 0o644, "ID=debian\nVERSION_ID=\"12\"\n"),
		reg("var/lib/dpkg/status", 0o644, "Package: openssl\nVersion: 3.0.11-1~deb12u2\nSource: openssl\n\n"),
		reg("opt/real.json", 0o644, `{"name":"lodash","version":"4.17.21"}`),
		hardlink("app/node_modules/lodash/package.json", "opt/real.json"),
	)
	ref, digest := pushImage(t, layer)
	res, err := New(testSource(), &fakeVulns{}).ScanImage(context.Background(), digest, ref)
	require.NoError(t, err)
	require.Empty(t, res.OSCVEGap, "the OS packages are matched in full")
	require.Contains(t, res.LanguageGap, "is a hardlink")

	var lang, os int
	for _, f := range res.Findings {
		switch f.CheckID {
		case languageCoverageCheckID:
			lang++
			require.Equal(t, LanguageCoverageFindingID(digest), f.ID)
		case osCoverageCheckID:
			os++
		}
		require.NotEqual(t, asset.CVEGapScanIncomplete, f.Metadata[asset.MetaPackageCVEGap])
	}
	require.Equal(t, 1, lang)
	require.Zero(t, os)
}
