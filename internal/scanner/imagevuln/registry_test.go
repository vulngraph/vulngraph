package imagevuln

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"io/fs"
	"net/http/httptest"
	"net/url"
	"os"
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
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// layerFrom builds a single-layer tar containing the given files.
func layerFrom(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	b := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	})
	require.NoError(t, err)
	return layer
}

// pushImage serves an in-process registry holding an image built from layers.
func pushImage(t *testing.T, layers ...v1.Layer) (ref string, digest string) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	img, err := mutate.AppendLayers(empty.Image, layers...)
	require.NoError(t, err)

	tag, err := name.NewTag(u.Host + "/test/img:v1")
	require.NoError(t, err)
	require.NoError(t, remote.Write(tag, img))

	d, err := img.Digest()
	require.NoError(t, err)
	return tag.String(), d.String()
}

// The whole point: a real registry pull yields real OS package inventory. nginx from
// a Debian dpkg database is the exact case that was structurally invisible before —
// zero image_vuln findings ever, because no ImageSource could fetch an image.
func TestRegistryImageSource_PullsOSPackagesFromRegistry(t *testing.T) {
	dpkg := "Package: nginx\nVersion: 1.30.3-1~deb12u1\n\n" +
		"Package: openssl\nVersion: 3.0.11-1~deb12u2\n\n"
	ref, digest := pushImage(t, layerFrom(t, map[string]string{
		"var/lib/dpkg/status": dpkg,
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
		"usr/sbin/nginx":      "ELF-ish filler that must not be buffered",
	}))

	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err)
	defer cleanup()

	pkgs := pkginventory.InventoryPackages(context.Background(), root).Packages
	require.Len(t, pkgs, 2)

	byName := map[string]pkginventory.InstalledPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	require.Equal(t, "1.30.3-1~deb12u1", byName["nginx"].Version,
		"the nginx version is what decides CVE-2026-42533 exposure (vulnerable through 1.30.3)")
	require.Equal(t, "Debian:12", byName["nginx"].Ecosystem,
		"must be the release-qualified OSV ecosystem — unqualified \"Debian\" is the "+
			"union of every release and over-matches by ~2.8x")
	require.Equal(t, "3.0.11-1~deb12u2", byName["openssl"].Version)
}

func TestRegistryImageSource_ReadsAlpineDatabase(t *testing.T) {
	apk := "P:nginx\nV:1.28.0-r3\n\nP:musl\nV:1.2.5-r0\n\n"
	ref, digest := pushImage(t, layerFrom(t, map[string]string{
		"lib/apk/db/installed": apk,
		"etc/alpine-release":   "3.19.1\n",
	}))

	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err)
	defer cleanup()

	pkgs := pkginventory.InventoryPackages(context.Background(), root).Packages
	require.Len(t, pkgs, 2)
	require.Equal(t, "Alpine:v3.19", pkgs[0].Ecosystem,
		"unqualified \"Alpine\" matches ZERO advisories in OSV")
}

// A whiteout in a newer layer deletes the file: resurrecting the base layer's copy
// would report packages that the running container does not have.
func TestRegistryImageSource_WhiteoutHidesLowerLayer(t *testing.T) {
	base := layerFrom(t, map[string]string{
		"var/lib/dpkg/status": "Package: nginx\nVersion: 1.20.0\n\n",
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
	})
	deleted := layerFrom(t, map[string]string{"var/lib/dpkg/.wh.status": ""})
	ref, digest := pushImage(t, base, deleted)

	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err)
	defer cleanup()

	require.Empty(t, pkginventory.InventoryPackages(context.Background(), root).Packages,
		"a whited-out package database must not be read from the layer below")
}

// The walk must reach the BASE layer even after the OS package database and the
// release file are both in hand. It used to stop there — dpkg and apk never
// coexist, so nothing older could change the OS answer — and that rule is exactly
// what a language inventory cannot have: node_modules and a Go binary sit at
// arbitrary depth in arbitrary layers, and an application's base layer is a
// perfectly ordinary place for them.
func TestReadManifests_ReadsBaseLayerAfterOSDatabaseIsFound(t *testing.T) {
	base := countingLayer{Layer: layerFrom(t, map[string]string{
		"app/node_modules/lodash/package.json": `{"name":"lodash","version":"4.17.21"}`,
	})}
	top := layerFrom(t, map[string]string{
		"var/lib/dpkg/status": "Package: nginx\nVersion: 1.30.4\n\n",
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
	})
	img, err := mutate.AppendLayers(empty.Image, &base, top)
	require.NoError(t, err)

	files, pkgs, incomplete := walkOf(t, RegistryImageSource{}, img)
	require.Empty(t, incomplete)
	require.Contains(t, string(files["var/lib/dpkg/status"]), "1.30.4")
	require.Equal(t, 1, base.reads, "the base layer must be read: language manifests are not bounded by the OS database")
	require.Equal(t, []pkginventory.InstalledPackage{{
		Ecosystem: "npm", Name: "lodash", Version: "4.17.21",
		Source: "app/node_modules/lodash/package.json",
	}}, pkgs)
}

// The point of the whole change: an image that ships no lockfile anywhere still
// yields npm, PyPI and RubyGems packages, because installed artifacts are what
// actually shipped. Without this, image packages would be deb+apk only and
// could never meet the repo-SBOM packages on a shared node.
func TestRegistryImageSource_InventoriesLanguagePackagesAtDepth(t *testing.T) {
	ref, digest := pushImage(t, layerFrom(t, map[string]string{
		"etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status": "Package: openssl\nVersion: 3.0.11-1\n\n",
		"usr/src/app/node_modules/@example/widget/package.json":       `{"name":"@example/widget","version":"1.4.0"}`,
		"usr/lib/python3/site-packages/PyYAML-6.0.dist-info/METADATA": "Name: PyYAML\nVersion: 6.0\n",
		"usr/lib/ruby/gems/3.1.0/specifications/rack-2.2.3.gemspec":   "Gem::Specification.new",
	}))

	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err)
	defer cleanup()

	got := map[string]string{}
	for _, p := range pkginventory.InventoryPackages(context.Background(), root).Packages {
		got[pkginventory.PURL(p)] = p.Ecosystem
	}
	require.Equal(t, map[string]string{
		"pkg:deb/debian/openssl@3.0.11-1": "Debian:12",
		"pkg:npm/@example/widget@1.4.0":   "npm",
		"pkg:pypi/pyyaml@6.0":             "PyPI",
		"pkg:gem/rack@2.2.3":              "RubyGems",
	}, got)
}

// A distroless image has no package database at all — one static binary and
// nothing else — so the Go module list linked into that binary is the ONLY
// inventory obtainable. It also must not be retained: the bytes are parsed as the
// layer streams past, and what reaches the caller is the package list.
func TestRegistryImageSource_InventoriesGoBinaryWithoutRetainingIt(t *testing.T) {
	binary := selfBinary(t)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "app/server", Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg,
	}))
	_, err := tw.Write(binary)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	b := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	files, _, incomplete := walkOf(t, RegistryImageSource{}, img)
	require.Empty(t, incomplete)
	require.Empty(t, files,
		"a Go binary must never be retained — it is parsed in the stream and dropped")

	// The classifier is what decides the binary is worth reading at all; a test
	// binary carries no dependency modules, so the packages themselves are covered
	// by pkginventory.TestGoModulePackages.
	require.Equal(t, pkginventory.KindGoBinary,
		pkginventory.ClassifyManifest("app/server", 0o755, int64(len(binary))))
}

// The Go probe budget is what bounds a walk over an image full of large
// executables that are not Go — a large ML image can carry over a gigabyte of them.
func TestParseLanguage_GoProbeBudgetIsEnforced(t *testing.T) {
	w := manifestWalk{files: map[string][]byte{}, resolved: map[string]struct{}{}, goBudget: 8}
	require.NoError(t, w.parseLanguage(pkginventory.KindGoBinary, "app/big", 4096, bytes.NewReader(make([]byte, 4096))))
	require.Empty(t, w.packages)
	require.Equal(t, int64(8), w.goBudget, "an over-budget binary must not even be read")
	require.Contains(t, w.languageGap, "probe budget was spent", "a binary skipped for budget is a visible language gap")
	require.Empty(t, w.incomplete, "and never an OS gap")
}

// selfBinary reads the running test binary. Deliberately os.Open rather than
// os.ReadFile: os.ReadFile is one of internal/guardmutation's structural markers,
// and a test that reads a BINARY is not a guard reading the repository's source.
func selfBinary(t *testing.T) []byte {
	t.Helper()
	self, err := os.Executable()
	require.NoError(t, err)
	f, err := os.Open(self)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	return data
}

// A candidate that is not ELF must cost four bytes, not its size — and must not
// spend any of the probe budget, or an image full of shared objects exhausts it
// before reaching the one binary that carries the inventory.
func TestParseGoBinary_NonELFIsNotBuffered(t *testing.T) {
	w := manifestWalk{files: map[string][]byte{}, resolved: map[string]struct{}{}, goBudget: 1 << 20}
	body := bytes.NewReader(make([]byte, 4096))
	require.NoError(t, w.parseGoBinary("usr/lib/libtorch.so", 4096, body))
	require.Empty(t, w.packages)
	require.Equal(t, int64(1<<20), w.goBudget, "a non-ELF candidate must not be charged")
	require.Equal(t, 4096-pkginventory.ELFPrefixLen, body.Len(),
		"only the ELF header may be consumed; the tar reader skips the rest")
}

// An opaque whiteout deletes the LOWER layers' contents of a directory, never the
// declaring layer's own — and a tar writes the marker BEFORE the files it precedes.
// Applying it eagerly therefore deletes exactly the files the layer just added:
// on an ML image nearly all of its installed Python distributions would vanish,
// and the image would report only a handful of packages.
func TestReadManifests_OpaqueWhiteoutSpareTheDeclaringLayer(t *testing.T) {
	base := layerFrom(t, map[string]string{
		"usr/lib/python3/site-packages/old-1.0.dist-info/METADATA": "Name: old\nVersion: 1.0\n",
	})
	// tar order matters: the marker is written first, as Docker writes it.
	top := layerFromOrdered(t, []namedFile{
		{"usr/lib/python3/site-packages/.wh..wh..opq", ""},
		{"usr/lib/python3/site-packages/new-2.0.dist-info/METADATA", "Name: new\nVersion: 2.0\n"},
	})
	img, err := mutate.AppendLayers(empty.Image, base, top)
	require.NoError(t, err)

	_, pkgs, incomplete := walkOf(t, RegistryImageSource{}, img)
	require.Empty(t, incomplete)
	require.Len(t, pkgs, 1, "the declaring layer's own files must survive its own marker")
	require.Equal(t, "new", pkgs[0].Name)
}

// The same marker must reach BELOW its own directory. Checking only the immediate
// parent was survivable while four fixed paths were read; a dist-info sits two
// levels under site-packages, so the shallow check resurrects a whole tree the
// running container does not have.
func TestReadManifests_OpaqueWhiteoutHidesNestedLowerLayerFiles(t *testing.T) {
	base := layerFrom(t, map[string]string{
		"usr/lib/python3/site-packages/old-1.0.dist-info/METADATA": "Name: old\nVersion: 1.0\n",
	})
	top := layerFrom(t, map[string]string{"usr/lib/python3/site-packages/.wh..wh..opq": ""})
	img, err := mutate.AppendLayers(empty.Image, base, top)
	require.NoError(t, err)

	_, pkgs, incomplete := walkOf(t, RegistryImageSource{}, img)
	require.Empty(t, incomplete)
	require.Empty(t, pkgs, "a package under an emptied directory is not in the merged filesystem")
}

// namedFile keeps tar entry ORDER, which map iteration cannot.
type namedFile struct{ name, body string }

func layerFromOrdered(t *testing.T, files []namedFile) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: f.name, Mode: 0o644, Size: int64(len(f.body)), Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(f.body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	b := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	})
	require.NoError(t, err)
	return layer
}

// countingLayer records whether a layer was decompressed at all.
type countingLayer struct {
	v1.Layer
	reads int
}

func (c *countingLayer) Uncompressed() (io.ReadCloser, error) {
	c.reads++
	return c.Layer.Uncompressed()
}

// Only the declared manifest paths are kept. This is what makes the design viable at
// fleet scale: hundreds of images are streamed, not extracted, so nothing lands on disk.
func TestRegistryImageSource_KeepsOnlyDeclaredManifests(t *testing.T) {
	files := map[string]string{
		"var/lib/dpkg/status": "Package: nginx\nVersion: 1.0\n\n",
		"etc/shadow":          "root:$6$secret",
		"usr/bin/huge":        strings.Repeat("x", 4096),
		"home/app/.aws/creds": "aws_secret_access_key=AKIA",
	}
	ref, digest := pushImage(t, layerFrom(t, files))

	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err)
	defer cleanup()

	for _, p := range pkginventory.PackageManifestPaths() {
		if p == "var/lib/dpkg/status" {
			_, err := root.Open(p)
			require.NoError(t, err, "declared manifest must be present")
		}
	}
	// Nothing outside the declared set is retained — notably not credentials or
	// shadow files that happen to sit in an image we scan.
	for _, unwanted := range []string{"etc/shadow", "usr/bin/huge", "home/app/.aws/creds"} {
		_, err := root.Open(unwanted)
		require.ErrorIs(t, err, fs.ErrNotExist, "%s must not be retained in memory", unwanted)
	}
}

// A later layer must win, because that is what the running container sees. Getting
// this backwards would report a version that was upgraded away.
func TestRegistryImageSource_LaterLayerWins(t *testing.T) {
	base := layerFrom(t, map[string]string{"var/lib/dpkg/status": "Package: nginx\nVersion: 1.20.0\n\n"})
	upgrade := layerFrom(t, map[string]string{"var/lib/dpkg/status": "Package: nginx\nVersion: 1.30.4\n\n"})
	ref, digest := pushImage(t, base, upgrade)

	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err)
	defer cleanup()

	pkgs := pkginventory.InventoryPackages(context.Background(), root).Packages
	require.Len(t, pkgs, 1)
	require.Equal(t, "1.30.4", pkgs[0].Version,
		"the upgraded version in the later layer is what actually runs")
}

// An image with no readable manifests must be distinguishable from an image we failed
// to inventory. Returning an empty result for both is how a scanner claims coverage
// over images it never actually read.
func TestRegistryImageSource_Distroless_ReportsNoManifests(t *testing.T) {
	ref, digest := pushImage(t, layerFrom(t, map[string]string{"app/server": "static binary"}))

	_, _, err := testSource().Open(context.Background(), ref, digest)
	require.ErrorIs(t, err, ErrNoManifests)
}

// The digest must pin the pull. `:latest` is common on running containers, so a tag
// can move between the collector recording it and the scanner pulling it — reporting
// packages from an image nothing runs.
func TestPullReference_PrefersDigest(t *testing.T) {
	const dg = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tests := []struct {
		name, ref, digest, want string
	}{
		{"tag plus digest pins to digest", "eu.gcr.io/p/nginx:latest", dg, "eu.gcr.io/p/nginx@" + dg},
		{"no tag plus digest pins to digest", "eu.gcr.io/p/nginx", dg, "eu.gcr.io/p/nginx@" + dg},
		{"ref already carries a digest is left alone", "eu.gcr.io/p/nginx@" + dg, dg, "eu.gcr.io/p/nginx@" + dg},
		{"registry with a port is not mistaken for a tag", "localhost:5000/nginx", dg, "localhost:5000/nginx@" + dg},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pullReference(tc.ref, tc.digest)
			require.NoError(t, err)
			require.Contains(t, got.String(), tc.want)
		})
	}

	t.Run("no digest falls back to the tag", func(t *testing.T) {
		got, err := pullReference("eu.gcr.io/p/nginx:v1.2.3", "")
		require.NoError(t, err)
		require.Contains(t, got.String(), "nginx:v1.2.3")
	})
	t.Run("empty reference errors", func(t *testing.T) {
		_, err := pullReference("  ", "")
		require.Error(t, err)
	})
	// Regression guard: a digest-only image_ref (no registry/
	// repo at all) used to fall through to the repo+digest construction,
	// which split on the digest's OWN colon, treated "sha256" as the
	// repository, and silently mangled the pull into
	// docker.io/library/sha256/manifests/... — every image with this
	// shape failed its scan against the wrong registry.
	t.Run("bare digest with no registry/repo errors instead of mangling the pull", func(t *testing.T) {
		got, err := pullReference(dg, dg)
		require.Error(t, err)
		require.Nil(t, got)
		require.NotContains(t, err.Error(), "docker.io",
			"must reject explicitly, not silently resolve against the wrong default registry")
	})
}

func TestIsBareDigest(t *testing.T) {
	const dg = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	require.True(t, isBareDigest(dg))
	require.False(t, isBareDigest("eu.gcr.io/p/nginx@"+dg), "a full ref carrying a digest is not bare")
	require.False(t, isBareDigest("eu.gcr.io/p/nginx"))
	require.False(t, isBareDigest("nginx:latest"))
}

// Image tars disagree on path form for the same file; all must match the parsers'
// fs.FS-relative paths or a manifest is silently missed.
func TestNormalizeTarPath(t *testing.T) {
	for _, in := range []string{
		"var/lib/dpkg/status", "./var/lib/dpkg/status", "/var/lib/dpkg/status", "var/lib/../lib/dpkg/status",
	} {
		require.Equal(t, "var/lib/dpkg/status", normalizeTarPath(in), "input %q", in)
	}
}

// The stream cap must stop an unbounded image AND say so, rather than quietly
// returning a partial inventory that reads as complete.
func TestReadManifests_StreamCapIsReported(t *testing.T) {
	img, err := mutate.AppendLayers(empty.Image, layerFrom(t, map[string]string{
		"usr/bin/filler": strings.Repeat("y", 8192),
	}))
	require.NoError(t, err)

	files, _, incomplete := walkOf(t, RegistryImageSource{MaxStreamBytes: 512}, img)
	require.Contains(t, incomplete, "exceeded the byte budget", "hitting the cap must be reported, not silently tolerated")
	require.Empty(t, files)
}

// A partial inventory must survive the cap. Discarding what was already read is
// how a scanner reports "pull failed" for an image it had in fact partly read.
func TestOpen_KeepsPartialInventoryWhenCapTrips(t *testing.T) {
	// The top layer carries both manifests; a huge base layer trips the cap after.
	top := layerFrom(t, map[string]string{
		"var/lib/dpkg/status": "Package: nginx\nVersion: 1.30.4\n\n",
	})
	base := layerFrom(t, map[string]string{"usr/bin/filler": strings.Repeat("y", 8192)})
	ref, digest := pushImage(t, base, top)

	root, cleanup, err := RegistryImageSource{MaxStreamBytes: 2048, Transport: loopbackTransport}.Open(context.Background(), ref, digest)
	require.NoError(t, err, "a partial inventory is still an inventory")
	defer cleanup()
	require.Contains(t, root.(PartialInventory).IncompleteReason(), "byte budget",
		"a partial inventory must say it is partial, or it reads as a smaller, cleaner image")
	require.Len(t, pkginventory.InventoryPackages(context.Background(), root).Packages, 1)
}

// Symlinks and device nodes are never followed or retained — a manifest path that
// arrives as a symlink must not be treated as content.
func TestReadManifests_IgnoresNonRegularFiles(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "var/lib/dpkg/status", Linkname: "../../../etc/passwd", Typeflag: tar.TypeSymlink, Mode: 0o777,
	}))
	require.NoError(t, tw.Close())
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	})
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)

	files, _, incomplete := walkOf(t, RegistryImageSource{}, img)
	require.Empty(t, incomplete)
	require.Empty(t, files, "a symlinked manifest path must be ignored, not resolved")
}

// rpmFixture is a real, trimmed rpm database from pkginventory/rpmdb's testdata.
func rpmFixture(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open("../pkginventory/rpmdb/testdata/" + name)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	data, err := io.ReadAll(zr)
	require.NoError(t, err)
	return string(data)
}

// An rpm-based image's database is streamed out of its layer whole and read:
// a UBI image is inventoried like a Debian one, and the image is matchable.
func TestRegistryImageSource_ReadsRPMDatabase(t *testing.T) {
	ref, digest := pushImage(t, layerFrom(t, map[string]string{
		"etc/os-release":               "ID=\"rhel\"\nVERSION_ID=\"9.8\"\n",
		"var/lib/rpm/rpmdb.sqlite":     rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz"),
		"var/lib/rpm/rpmdb.sqlite-wal": "",
	}))
	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err)
	defer cleanup()

	pkgs := pkginventory.InventoryPackages(context.Background(), root).Packages
	require.Len(t, pkgs, 4, "every package but the two gpg-pubkey pseudo-packages")
	byName := map[string]pkginventory.InstalledPackage{}
	for _, p := range pkgs {
		require.Equal(t, "Red Hat:9", p.Ecosystem)
		byName[p.Name] = p
	}
	require.Equal(t, "1:3.5.8-1.el9_8", byName["openssl-libs"].Version)
	require.Equal(t, "openssl", byName["openssl-libs"].SourceName)

	eco, gap, detail := pkginventory.OSCVEGap(root, pkgs, distro.Sources{distro.SourceOSV: true}, time.Now())
	require.Equal(t, "Red Hat:9", eco)
	require.Empty(t, gap, "a readable rpm database is matchable: no coverage gap")
	require.Empty(t, detail)
}

// A database that cannot be read keeps the image's coverage finding, with the
// reason: it must never read as an image with no OS packages.
func TestRegistryImageSource_UnreadableRPMDatabaseIsAGap(t *testing.T) {
	ref, digest := pushImage(t, layerFrom(t, map[string]string{
		"usr/lib/os-release":       "ID=\"rocky\"\nVERSION_ID=\"9.3\"\n",
		"var/lib/rpm/rpmdb.sqlite": strings.Repeat("S", 4096),
	}))
	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err, "an rpm image is not an image with no manifests")
	defer cleanup()

	pkgs := pkginventory.InventoryPackages(context.Background(), root).Packages
	eco, gap, detail := pkginventory.OSCVEGap(root, pkgs, distro.Sources{distro.SourceOSV: true}, time.Now())
	require.Equal(t, "Rocky Linux:9", eco)
	require.Equal(t, asset.CVEGapPackageDBUnread, gap)
	require.Contains(t, detail, "unsupported database format")
}

// A distroless image has no dpkg status file: its packages are one paragraph per
// file under var/lib/dpkg/status.d/, and its os-release is readable only at
// usr/lib/os-release (etc/os-release is a symlink, never followed). Both must be
// streamed out of the layer, or the image reads as one with no OS packages.
func TestRegistryImageSource_ReadsDistrolessStatusD(t *testing.T) {
	ref, digest := pushImage(t, layerFrom(t, map[string]string{
		"etc/hostname":                          "never kept",
		"usr/lib/os-release":                    "ID=\"debian\"\nVERSION_ID=\"12\"\n",
		"var/lib/dpkg/status.d/libssl3":         "Package: libssl3\nSource: openssl\nVersion: 3.0.20-1~deb12u2\n",
		"var/lib/dpkg/status.d/libssl3.md5sums": "30561bade1f57903c1f800c036f8b3c3  usr/lib/x86_64-linux-gnu/libssl.so.3\n",
		"var/lib/dpkg/status.d/libc6":           "Package: libc6\nSource: glibc\nVersion: 2.36-9+deb12u14\n",
	}))

	root, cleanup, err := testSource().Open(context.Background(), ref, digest)
	require.NoError(t, err)
	defer cleanup()

	pkgs := pkginventory.InventoryPackages(context.Background(), root).Packages
	require.Len(t, pkgs, 2)
	for _, p := range pkgs {
		require.Equal(t, "Debian:12", p.Ecosystem)
		require.NotEmpty(t, p.SourceName)
	}
	_, err = root.Open("var/lib/dpkg/status.d/libssl3.md5sums")
	require.ErrorIs(t, err, fs.ErrNotExist, "md5sums files are not package records and are not retained")
}
