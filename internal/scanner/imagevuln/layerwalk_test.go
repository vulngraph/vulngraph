package imagevuln

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// loopbackTransport is the guarded registry transport with loopback allowed,
// which the in-process test registry needs — and nothing else.
var loopbackTransport = safenet.NewGuardedTransport(5*time.Second, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})

// testSource is a RegistryImageSource that can reach the in-process registry.
func testSource() RegistryImageSource { return RegistryImageSource{Transport: loopbackTransport} }

// walkOf runs the layer walk and returns what it kept and why it stopped early.
func walkOf(t *testing.T, s RegistryImageSource, img v1.Image) (map[string][]byte, []pkginventory.InstalledPackage, string) {
	t.Helper()
	w, err := s.readManifests(img)
	require.NoError(t, err)
	return w.files, w.packages, w.incomplete
}

// entry is one tar entry for layerOf: a header and its body.
type entry struct {
	hdr  tar.Header
	body []byte
}

func reg(name string, mode int64, body string) entry {
	return entry{hdr: tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg}, body: []byte(body)}
}

// layerOf builds a layer from ordered entries; truncateAt > 0 cuts the tar
// stream to that many bytes, as a corrupt or partly-uploaded blob would be.
func layerOf(t *testing.T, truncateAt int, entries ...entry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		require.NoError(t, tw.WriteHeader(&hdr))
		if len(e.body) > 0 {
			_, err := tw.Write(e.body)
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	b := buf.Bytes()
	if truncateAt > 0 {
		b = b[:truncateAt]
	}
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	})
	require.NoError(t, err)
	return layer
}

func imageOf(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	require.NoError(t, err)
	return img
}

// A layer that breaks mid-stream stops the walk and SAYS so. It used to return
// what it had read as if the image were whole — and because layers are read
// newest-first, the layer lost was the base, carrying os-release and the OS
// package database. The older layers are not read either: the broken layer's
// unread remainder may have whited them out.
func TestReadManifests_CorruptLayerStopsTheWalkAndSaysSo(t *testing.T) {
	base := countingLayer{Layer: layerOf(t, 0,
		reg("etc/os-release", 0o644, "ID=debian\nVERSION_ID=\"12\"\n"),
		reg("var/lib/dpkg/status", 0o644, "Package: openssl\nVersion: 3.0.11-1~deb12u2\n\n"),
	)}
	corrupt := layerOf(t, 700,
		reg("usr/share/doc/filler", 0o644, strings.Repeat("z", 400)),
		reg("var/lib/dpkg/.wh.status", 0o644, ""),
		reg("usr/share/doc/more", 0o644, strings.Repeat("z", 4000)),
	)
	top := layerOf(t, 0, reg("app/node_modules/lodash/package.json", 0o644, `{"name":"lodash","version":"4.17.21"}`))

	files, pkgs, incomplete := walkOf(t, RegistryImageSource{}, imageOf(t, &base, corrupt, top))
	require.Contains(t, incomplete, "corrupt layer")
	require.Contains(t, incomplete, "layer 2 of 3")
	require.Len(t, pkgs, 1, "what the intact newer layer held is kept")
	require.Empty(t, files)
	require.Zero(t, base.reads, "no layer older than the broken one may be read")
}

// The end-to-end shape of the P0: an image whose base layer was never read
// must NOT be recorded as a clean, complete scan. OSCVEGap alone sees no OS
// packages and no os-release and calls the root package-less; the walk's
// incomplete reason overrides that with scan_incomplete.
func TestScanImage_IncompleteWalkIsAGapNotAClean(t *testing.T) {
	base := layerOf(t, 0,
		reg("etc/os-release", 0o644, "ID=debian\nVERSION_ID=\"12\"\n"),
		reg("var/lib/dpkg/status", 0o644, "Package: openssl\nVersion: 3.0.11-1~deb12u2\n\n"),
		reg("usr/share/filler", 0o644, strings.Repeat("y", 8192)),
	)
	top := layerOf(t, 0, reg("app/node_modules/lodash/package.json", 0o644, `{"name":"lodash","version":"4.17.21"}`))
	ref, digest := pushImage(t, base, top)

	src := RegistryImageSource{MaxStreamBytes: 4096, Transport: loopbackTransport}
	res, err := New(src, &fakeVulns{}).ScanImage(context.Background(), digest, ref)
	require.NoError(t, err)
	require.Equal(t, asset.CVEGapScanIncomplete, res.OSCVEGap)
	require.Len(t, res.Edges, 2, "the packages that WERE read are still linked")

	var cov []string
	for _, f := range res.Findings {
		if f.CheckID == osCoverageCheckID {
			cov = append(cov, f.Metadata[asset.MetaPackageCVEGap], f.Metadata["package_cve_gap_reason"])
		}
	}
	require.Len(t, cov, 2, "one coverage finding")
	require.Equal(t, asset.CVEGapScanIncomplete, cov[0])
	require.Contains(t, cov[1], "byte budget")
}

// An image whose walk read nothing before it broke is a failed scan, not an
// empty one.
func TestOpen_IncompleteWithNothingReadIsAnError(t *testing.T) {
	ref, digest := pushImage(t, layerOf(t, 0, reg("usr/share/filler", 0o644, strings.Repeat("y", 8192))))
	_, _, err := RegistryImageSource{MaxStreamBytes: 1024, Transport: loopbackTransport}.Open(context.Background(), ref, digest)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNoManifests, "a walk cut short is not an image with no manifests")
	require.Contains(t, err.Error(), "byte budget")
}

// `rm -rf /app/node_modules` in a newer layer is ONE tombstone, on the
// directory. Only exact paths used to be checked, so every package.json under
// it was resurrected from the layer below as a phantom package with phantom CVEs.
func TestReadManifests_DirectoryWhiteoutHidesItsTree(t *testing.T) {
	base := layerOf(t, 0,
		reg("app/node_modules/lodash/package.json", 0o644, `{"name":"lodash","version":"4.17.20"}`),
		reg("app/node_modules/@scope/pkg/package.json", 0o644, `{"name":"@scope/pkg","version":"1.0.0"}`),
		reg("app/keep/node_modules/left-pad/package.json", 0o644, `{"name":"left-pad","version":"1.3.0"}`),
	)
	top := layerOf(t, 0, reg("app/.wh.node_modules", 0o644, ""))

	_, pkgs, incomplete := walkOf(t, RegistryImageSource{}, imageOf(t, base, top))
	require.Empty(t, incomplete)
	require.Len(t, pkgs, 1)
	require.Equal(t, "left-pad", pkgs[0].Name, "only the tree under the tombstone is deleted")
}

// A non-directory entry in a newer layer replaces whatever an older layer had
// at that path — a symlink over a directory hides the directory's contents, and a
// symlink over a manifest hides the manifest. (A plain non-executable file is
// not tracked unless it is itself a manifest: recording every path of every
// layer would cost memory proportional to the whole image.)
func TestReadManifests_NewerNonDirectoryEntriesShadowOlderPaths(t *testing.T) {
	base := layerOf(t, 0,
		reg("app/node_modules/lodash/package.json", 0o644, `{"name":"lodash","version":"4.17.20"}`),
		reg("etc/os-release", 0o644, "ID=debian\nVERSION_ID=\"11\"\n"),
		reg("srv/node_modules/express/package.json", 0o644, `{"name":"express","version":"4.0.0"}`),
	)
	top := layerOf(t, 0,
		entry{hdr: tar.Header{Name: "app/node_modules/lodash/package.json", Typeflag: tar.TypeSymlink, Linkname: "/elsewhere", Mode: 0o777}},
		entry{hdr: tar.Header{Name: "etc/os-release", Typeflag: tar.TypeSymlink, Linkname: "../usr/lib/os-release", Mode: 0o777}},
		entry{hdr: tar.Header{Name: "srv/node_modules", Typeflag: tar.TypeSymlink, Linkname: "/opt/shared", Mode: 0o777}},
	)

	files, pkgs, incomplete := walkOf(t, RegistryImageSource{}, imageOf(t, base, top))
	require.Empty(t, incomplete)
	require.Empty(t, pkgs, "neither shadowed manifest may be resurrected")
	require.NotContains(t, files, "etc/os-release", "the older os-release names a release the image no longer runs")
}

// An older layer's Go binary replaced by a newer non-ELF executable at the
// same path is gone from the running container; its modules must not be read.
func TestReadManifests_NonELFExecutableShadowsOlderBinary(t *testing.T) {
	// An ELF-headed candidate: enough to be probed, which is what is observed.
	binary := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 2<<20)...)
	goLayer := layerOf(t, 0, entry{hdr: tar.Header{Name: "usr/local/bin/app", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg}, body: binary})

	// Whether the binary was READ is observed through the probe budget.
	control, err := RegistryImageSource{}.readManifests(imageOf(t, goLayer))
	require.NoError(t, err)
	require.Less(t, control.goBudget, int64(maxGoProbeBytes), "control: the binary alone is probed")

	script := layerOf(t, 0, reg("usr/local/bin/app", 0o755, "#!/bin/sh\nexec /opt/app \"$@\"\n"))
	shadowed, err := RegistryImageSource{}.readManifests(imageOf(t, goLayer, script))
	require.NoError(t, err)
	require.Empty(t, shadowed.incomplete)
	require.Equal(t, int64(maxGoProbeBytes), shadowed.goBudget,
		"the replaced binary is not in the merged filesystem and must not be read")
}

// A hostile image cannot make the walk buffer without bound: a file over the
// per-manifest cap, more package files than the count cap, are both reported as
// an incomplete walk — never silently truncated. The walk carries on past them:
// the layer is sound, and one oversized lockfile must not cost the base layer.
func TestReadManifests_RetentionCapsAreAGap(t *testing.T) {
	t.Run("one file over the manifest cap", func(t *testing.T) {
		base := layerOf(t, 0,
			reg("etc/os-release", 0o644, "ID=debian\n"),
			reg("var/lib/dpkg/status", 0o644, "Package: a\nVersion: 1\n\n"),
			reg("package-lock.json", 0o644, "{}"),
		)
		top := layerOf(t, 0,
			reg("var/lib/dpkg/status", 0o644, strings.Repeat("Package: x\n", 20)),
			reg("package-lock.json", 0o644, strings.Repeat(" ", 200)),
		)
		w, err := RegistryImageSource{MaxManifestBytes: 64}.readManifests(imageOf(t, base, top))
		require.NoError(t, err)
		require.Contains(t, w.incomplete, "var/lib/dpkg/status is 220 bytes, over the 64-byte manifest cap",
			"an unread OS database is an OS gap")
		require.Contains(t, w.languageGap, "package-lock.json is 200 bytes, over the 64-byte manifest cap",
			"an unread lockfile is a language gap, not an OS one")
		require.NotContains(t, w.incomplete, "package-lock.json")
		require.Contains(t, w.files, "etc/os-release", "the walk carries on to the base layer")
		require.NotContains(t, w.files, "var/lib/dpkg/status", "the older, smaller copy is not what the image runs")
		require.NotContains(t, w.files, "package-lock.json")
	})
	t.Run("more status.d files than the count cap", func(t *testing.T) {
		entries := make([]entry, 0, maxRetainedFiles+1)
		for i := range maxRetainedFiles + 1 {
			entries = append(entries, reg(fmt.Sprintf("var/lib/dpkg/status.d/pkg%d", i), 0o644, "Package: p\nVersion: 1\n"))
		}
		_, _, incomplete := walkOf(t, RegistryImageSource{}, imageOf(t, layerOf(t, 0, entries...)))
		require.Contains(t, incomplete, fmt.Sprintf("more than %d package database files", maxRetainedFiles))
	})
	t.Run("retained bytes over the total cap", func(t *testing.T) {
		w := &manifestWalk{files: map[string][]byte{}, resolved: map[string]struct{}{}, read: map[string]struct{}{}, retainedBytes: maxRetainedBytes - 4}
		w.keep("var/lib/dpkg/status.d/a", []byte("1234"))
		require.Empty(t, w.incomplete)
		w.keep("var/lib/dpkg/status.d/b", []byte("5"))
		require.Contains(t, w.incomplete, "in total")
		require.NotContains(t, w.files, "var/lib/dpkg/status.d/b")
		require.False(t, w.wanted("var/lib/dpkg/status.d/b"),
			"a refused file still settles its path: an older layer's copy is not what the image runs")
	})
	t.Run("a language manifest over the cap is a language gap, the walk goes on", func(t *testing.T) {
		base := layerOf(t, 0,
			reg("app/node_modules/lodash/package.json", 0o644, `{"name":"lodash","version":"4.17.20"}`),
			reg("usr/lib/python3/site-packages/requests-2.0.dist-info/METADATA", 0o644, "Name: requests\nVersion: 2.0\n"),
		)
		top := layerOf(t, 0, reg("app/node_modules/lodash/package.json", 0o644,
			`{"name":"lodash","version":"4.17.21","description":"`+strings.Repeat("x", 200)+`"}`))
		w, err := RegistryImageSource{MaxManifestBytes: 128}.readManifests(imageOf(t, base, top))
		require.NoError(t, err)
		require.Contains(t, w.languageGap, "app/node_modules/lodash/package.json is")
		require.Contains(t, w.languageGap, "over the 128-byte manifest cap")
		require.Empty(t, w.incomplete, "a language manifest is not the OS database")
		pkgs := w.packages
		require.Len(t, pkgs, 1, "the base layer is still read, and the older lodash is not resurrected")
		require.Equal(t, "requests", pkgs[0].Name)
	})
}

// A multi-arch index resolves to amd64 when it has one and to arm64 otherwise:
// an arm64-only image used to fail the pull outright.
func TestSelectPlatform(t *testing.T) {
	amd := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: "aa"}, Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}
	arm := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: "bb"}, Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}
	att := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: "cc"}, Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"}}
	s390 := v1.Descriptor{Digest: v1.Hash{Algorithm: "sha256", Hex: "dd"}, Platform: &v1.Platform{OS: "linux", Architecture: "s390x"}}

	got, err := selectPlatform([]v1.Descriptor{att, arm, amd})
	require.NoError(t, err)
	require.Equal(t, amd.Digest, got.Digest)

	got, err = selectPlatform([]v1.Descriptor{att, arm})
	require.NoError(t, err)
	require.Equal(t, arm.Digest, got.Digest)

	_, err = selectPlatform([]v1.Descriptor{s390, att, {Digest: v1.Hash{Algorithm: "sha256", Hex: "ee"}}})
	require.ErrorContains(t, err, "linux/s390x")
}

func TestOpen_ArmOnlyIndexIsScanned(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	img := imageOf(t, layerOf(t, 0,
		reg("etc/os-release", 0o644, "ID=debian\nVERSION_ID=\"12\"\n"),
		reg("var/lib/dpkg/status", 0o644, "Package: openssl\nVersion: 3.0.11-1~deb12u2\n\n"),
	))
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        img,
		Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
	})
	tag, err := name.NewTag(u.Host + "/test/arm:v1")
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(tag, idx))
	d, err := idx.Digest()
	require.NoError(t, err)

	root, cleanup, err := testSource().Open(context.Background(), tag.String(), d.String())
	require.NoError(t, err)
	defer cleanup()
	require.Len(t, pkginventory.InventoryPackages(context.Background(), root).Packages, 1)
}

// Registry pulls are SSRF-guarded at dial time. With no allow list the
// in-process registry on loopback is unreachable — the same rule that keeps a
// connector-supplied image ref off the pod network.
func TestOpen_DefaultTransportBlocksPrivateRegistries(t *testing.T) {
	ref, digest := pushImage(t, layerOf(t, 0, reg("var/lib/dpkg/status", 0o644, "Package: a\nVersion: 1\n\n")))
	_, _, err := RegistryImageSource{}.Open(context.Background(), ref, digest)
	require.ErrorContains(t, err, "SSRF blocked")
}

// A hostile registry names the token realm. Pointed at the instance metadata
// endpoint, the token fetch must fail even where the registry itself is
// allowed. go-containerregistry refuses an IP-literal private realm itself; a
// hostname that resolves to one is refused by the guarded transport's dial
// check (TestNewGuardedTransport_AllowListAndRedirects).
func TestOpen_TokenRealmCannotReachMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="http://169.254.169.254/latest/meta-data/iam/",service="evil"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	const dg = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, _, err = testSource().Open(context.Background(), u.Host+"/evil/img:v1", dg)
	require.ErrorContains(t, err, "169.254.169.254")
}

// A malformed digest is refused: falling back to the mutable tag would store
// whatever the tag names now under the digest's key.
func TestPullReference_MalformedDigestIsRefused(t *testing.T) {
	_, err := pullReference("eu.gcr.io/p/nginx:latest", "sha256:not-hex")
	require.ErrorContains(t, err, "refusing to pull the mutable tag")
}
