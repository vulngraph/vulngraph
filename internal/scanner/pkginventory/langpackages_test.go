package pkginventory

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"io"
	"io/fs"
	"os"
	"runtime/debug"
	"testing"
	"testing/fstest"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

const (
	execMode = fs.FileMode(0o755)
	fileMode = fs.FileMode(0o644)
)

// TestClassifyManifestCoversEveryParser is the language half of the invariant
// TestPackageManifestPathsCoversEveryParser holds for fixed paths: every kind
// ParseManifest handles must be reachable from a real path, and every kind
// ClassifyManifest can produce must be handled. A parser wired to a pattern
// nothing matches is the failure this codebase keeps hitting — the two language
// manifests that used to be in the fixed list were matched at the rootfs ROOT,
// where no application keeps its lockfile, so they covered nothing for years.
func TestClassifyManifestCoversEveryParser(t *testing.T) {
	// One real path per language kind, with the bytes that path would carry.
	cases := []struct {
		kind ManifestKind
		path string
		data string
		want InstalledPackage
	}{
		{
			kind: KindNpmInstalled,
			path: "usr/src/app/node_modules/lodash/package.json",
			data: `{"name":"lodash","version":"4.17.21"}`,
			want: InstalledPackage{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
		},
		{
			kind: KindPyDistInfo,
			path: "usr/lib/python3.11/site-packages/requests-2.25.1.dist-info/METADATA",
			data: "Metadata-Version: 2.1\nName: requests\nVersion: 2.25.1\n\nName: not a header\n",
			want: InstalledPackage{Ecosystem: "PyPI", Name: "requests", Version: "2.25.1"},
		},
		{
			kind: KindGemSpec,
			path: "usr/lib/ruby/gems/3.1.0/specifications/rack-2.2.3.gemspec",
			want: InstalledPackage{Ecosystem: "RubyGems", Name: "rack", Version: "2.2.3"},
		},
	}

	covered := map[ManifestKind]bool{}
	for _, tc := range cases {
		got := ClassifyManifest(tc.path, fileMode, int64(len(tc.data)))
		require.Equal(t, tc.kind, got, "path %q", tc.path)
		require.True(t, got.IsLanguage(), "%q must be parseable from bytes alone", tc.path)

		pkgs := ParseManifest(got, tc.path, []byte(tc.data))
		require.Len(t, pkgs, 1, "path %q must yield exactly one package", tc.path)
		tc.want.Source = tc.path
		require.Equal(t, tc.want, pkgs[0])
		covered[tc.kind] = true
	}
	// KindGoBinary has no path fixture — its candidates are recognised by mode and
	// size, not by name — and is covered by TestGoBinaryPackages_ReadsARealGoBinary
	// plus TestGoModulePackages.
	covered[KindGoBinary] = true

	for k := KindNone; k <= KindGoBinary; k++ {
		if k.IsLanguage() {
			require.True(t, covered[k], "language kind %d has no ClassifyManifest+ParseManifest case", k)
		}
	}
}

// The patterns must be narrow enough that they describe INSTALLED software.
func TestClassifyManifest_Rejections(t *testing.T) {
	tests := []struct {
		name string
		path string
		mode fs.FileMode
		size int64
	}{
		{"a package's own test fixture is not an installed package",
			"node_modules/tar/test/fixtures/pkg/package.json", fileMode, 40},
		{"an application's own package.json is not an installed package",
			"usr/src/app/package.json", fileMode, 40},
		{"a lockfile below the root describes a build, not an install",
			"var/www/vendor/bower-asset/inputmask/package-lock.json", fileMode, 40},
		{"a gemspec outside specifications/ is a source file",
			"usr/src/app/rack.gemspec", fileMode, 40},
		// Sized well inside the ceiling so only the .so rule can reject it: on a
		// large ML image these are most of the walk and hold no Go.
		{"a shared object is ELF and executable but never a Go program",
			"usr/lib/libtorch_cpu.so", execMode, 200 << 20},
		{"a versioned shared object too", "usr/lib/x86_64-linux-gnu/libc.so.6", execMode, 2 << 20},
		{"a shell script is too small to be a Go binary",
			"usr/local/bin/entrypoint.sh", execMode, 512},
		{"a non-executable file is not a binary candidate",
			"opt/data/model.bin", fileMode, 40 << 20},
		{"an executable beyond the memory ceiling is not buffered",
			"opt/huge", execMode, 1 << 30},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, KindNone, ClassifyManifest(tc.path, tc.mode, tc.size))
		})
	}
}

// METADATA headers end at the first blank line; everything after it is the
// package's long description, which routinely contains changelog lines that look
// exactly like headers. Reading past the blank line lets a README quote decide a
// package's version — and a wrong version is a wrong node id and a wrong CVE match.
func TestPyDistInfoPackages_StopsAtTheHeaderBlock(t *testing.T) {
	const metadata = "Metadata-Version: 2.1\nName: examplepkg\n\n" +
		"Changelog\n=========\nVersion: 99.0 was a bad release\n"
	require.Empty(t, pyDistInfoPackages("examplepkg-1.dist-info/METADATA", []byte(metadata)),
		"a description line must never supply the version")
}

// Scoped npm packages nest one level deeper; missing them would drop the whole
// @scope namespace, which is where first-party packages commonly live
// (e.g. pkg:npm/@example/widget).
func TestClassifyManifest_ScopedNpmPackage(t *testing.T) {
	require.Equal(t, KindNpmInstalled,
		ClassifyManifest("app/node_modules/@example/widget/package.json", fileMode, 100))
}

// A platform-suffixed gemspec must still resolve to name+version: RubyGems writes
// specifications/<name>-<version>[-<platform>].gemspec, and treating the platform
// as part of the version mints a node id no SBOM can ever join to.
func TestGemSpecPackages_PlatformSuffix(t *testing.T) {
	tests := []struct{ path, name, version string }{
		{"specifications/rack-2.2.3.gemspec", "rack", "2.2.3"},
		{"specifications/net-http-0.4.1.gemspec", "net-http", "0.4.1"},
		{"specifications/nokogiri-1.13.10-x86_64-linux.gemspec", "nokogiri", "1.13.10"},
		{"specifications/CFPropertyList-3.0.8.gemspec", "CFPropertyList", "3.0.8"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			pkgs := gemSpecPackages(tc.path)
			require.Len(t, pkgs, 1)
			require.Equal(t, tc.name, pkgs[0].Name)
			require.Equal(t, tc.version, pkgs[0].Version)
		})
	}
	require.Empty(t, gemSpecPackages("specifications/noversion.gemspec"))
}

// Go binaries carry their module list with no manifest at all, which is the only
// reason a distroless image can be inventoried at all. The read path is exercised
// against a REAL Go binary — the test binary itself — because a hand-built fixture
// could drift from whatever the linker actually emits.
//
// It asserts the read succeeds rather than a module list: `go test` binaries carry
// no dependency modules. Real Go binaries typically carry from tens to a few
// hundred modules each.
func TestGoBinaryPackages_ReadsARealGoBinary(t *testing.T) {
	data := selfBinary(t)
	info, err := buildinfo.Read(bytes.NewReader(data))
	require.NoError(t, err, "debug/buildinfo must read a genuine Go binary")
	require.NotEmpty(t, info.GoVersion)

	require.Nil(t, goBinaryPackages("etc/passwd", []byte("root:x:0:0")),
		"a file that is not a Go binary must yield nothing, not an error")
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

// goModulePackages is the mapping from a binary's module list to package
// identity, and every rule in it decides whether a package can be joined to a
// repo SBOM at all.
func TestGoModulePackages(t *testing.T) {
	deps := []*debug.Module{
		{Path: "github.com/gin-gonic/gin", Version: "v1.6.0"},
		{Path: "github.com/Azure/azure-sdk-for-go", Version: "v14.6.0+incompatible"},
		{Path: "example.com/vendored", Version: "v1.0.0", Replace: &debug.Module{
			Path: "github.com/fork/vendored", Version: "v1.0.1",
		}},
		{Path: "example.com/local", Version: "(devel)"},
		{Path: "example.com/noversion", Version: ""},
		nil,
	}
	pkgs := goModulePackages("usr/local/bin/app", deps)

	require.Equal(t, []InstalledPackage{
		{Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "v1.6.0", Source: "usr/local/bin/app"},
		{Ecosystem: "Go", Name: "github.com/Azure/azure-sdk-for-go", Version: "v14.6.0+incompatible", Source: "usr/local/bin/app"},
		{Ecosystem: "Go", Name: "github.com/fork/vendored", Version: "v1.0.1", Source: "usr/local/bin/app"},
	}, pkgs, "replaced modules report the replacement; unversioned modules are dropped")

	// The Name keeps its real module path because that is what OSV keys on
	// (e.g. OSV lists advisories under Go/github.com/gin-gonic/gin), while
	// the purl lowercases it because that is what the SBOM collector emits.
	require.Equal(t, "pkg:golang/github.com/azure/azure-sdk-for-go@v14.6.0%2Bincompatible", PURL(pkgs[1]))
}

// A file that is a plausible binary but not ELF must cost four bytes, not its
// whole size — the probe budget is the only thing bounding this walk.
func TestReadCapped_NonELFIsRejectedBeforeBuffering(t *testing.T) {
	root := fstest.MapFS{
		"opt/data": &fstest.MapFile{Data: make([]byte, 4<<20), Mode: execMode},
	}
	_, err := readCapped(root, "opt/data", KindGoBinary)
	require.ErrorIs(t, err, fs.ErrInvalid)
}

// The end-to-end claim: an image-shaped filesystem with no lockfile anywhere
// still yields npm, PyPI and RubyGems packages, because installed artifacts are
// what actually shipped. Before this, the only paths read were at the rootfs root
// and the answer was zero.
func TestInventoryPackages_FindsLanguagePackagesAtDepth(t *testing.T) {
	root := fstest.MapFS{
		osReleasePath:  &fstest.MapFile{Data: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
		dpkgStatusPath: &fstest.MapFile{Data: []byte("Package: openssl\nVersion: 3.0.11-1\n\n")},
		"usr/src/app/node_modules/@example/widget/package.json": &fstest.MapFile{
			Data: []byte(`{"name":"@example/widget","version":"1.4.0"}`),
		},
		"usr/lib/python3/site-packages/PyYAML-6.0.dist-info/METADATA": &fstest.MapFile{
			Data: []byte("Name: PyYAML\nVersion: 6.0\n"),
		},
		"usr/lib/ruby/gems/3.1.0/specifications/rack-2.2.3.gemspec": &fstest.MapFile{Data: []byte("Gem::Specification.new")},
	}

	byPURL := map[string]InstalledPackage{}
	for _, p := range InventoryPackages(context.Background(), root).Packages {
		byPURL[PURL(p)] = p
	}
	require.Contains(t, byPURL, "pkg:deb/debian/openssl@3.0.11-1")
	require.Contains(t, byPURL, "pkg:npm/@example/widget@1.4.0")
	require.Contains(t, byPURL, "pkg:pypi/pyyaml@6.0")
	require.Contains(t, byPURL, "pkg:gem/rack@2.2.3")
}

// Kernel pseudo-filesystems hold no installed software and walking them on a
// mounted disk is unbounded work.
func TestInventoryPackages_SkipsPseudoFilesystems(t *testing.T) {
	root := fstest.MapFS{
		"proc/1/root/node_modules/lodash/package.json": &fstest.MapFile{
			Data: []byte(`{"name":"lodash","version":"4.17.21"}`),
		},
	}
	require.Empty(t, InventoryPackages(context.Background(), root).Packages)
}

// The probe budget must actually stop the walk, and must say so: a scan that
// silently skipped the binary carrying the whole inventory would report a
// distroless image as having no packages, which is indistinguishable from one
// that genuinely has none.
func TestLanguagePackages_GoProbeBudgetStopsTheWalk(t *testing.T) {
	binary := append([]byte{0x7f, 0x45, 0x4c, 0x46}, make([]byte, 2<<20)...)
	root := fstest.MapFS{
		"usr/local/bin/app": &fstest.MapFile{Data: binary, Mode: execMode},
	}

	var buf bytes.Buffer
	orig := zlog.Logger
	zlog.Logger = zerolog.New(&buf)
	t.Cleanup(func() { zlog.Logger = orig })

	pkgs, gap := languagePackages(context.Background(), root, 1024)
	require.Empty(t, pkgs)
	require.Contains(t, gap, "probe budget was spent", "a binary past the budget is a gap, not a package-free binary")
	require.Contains(t, buf.String(), "probe budget exhausted")

	// With budget, the same file is read (and yields nothing only because a
	// zero-filled ELF stub carries no build info).
	buf.Reset()
	pkgs, gap = languagePackages(context.Background(), root, 8<<20)
	require.Empty(t, pkgs)
	require.Empty(t, gap)
	require.Empty(t, buf.String(), "a walk inside its budget must be silent")
}

// preInventoried is a filesystem view that resolved packages while it was built.
type preInventoried struct {
	fs.FS
	pkgs []InstalledPackage
}

func (p preInventoried) InventoriedPackages() []InstalledPackage { return p.pkgs }

// The image scanner parses Go binaries as the layer stream goes past and keeps
// only the result. If InventoryPackages ignored that, every Go image would report
// its OS packages and nothing else — which is the entire content of a distroless
// image.
func TestInventoryPackages_IncludesPreInventoriedPackages(t *testing.T) {
	want := InstalledPackage{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.17.0", Source: "app/server"}
	pkgs := InventoryPackages(context.Background(), preInventoried{
		FS: fstest.MapFS{}, pkgs: []InstalledPackage{want},
	}).Packages
	require.Equal(t, []InstalledPackage{want}, pkgs)
}
