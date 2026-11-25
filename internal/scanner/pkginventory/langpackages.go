package pkginventory

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// ManifestKind identifies which parser reads a discovered file.
//
// The split into OS and LANGUAGE kinds is load-bearing, not taxonomy. A
// language manifest is self-describing: its bytes alone name a package and a
// version, so ParseManifest converts it with no other context and a streaming
// caller never has to retain the file. An OS package database is not:
// /var/lib/dpkg/status means nothing until /etc/os-release has been read, and
// those two can live in different layers — so OS kinds are parsed by
// InventoryPackages, which has the whole filesystem.
type ManifestKind int

const (
	KindNone ManifestKind = iota
	// OS kinds — parsed by InventoryPackages once the release is known.
	KindOSRelease
	KindAlpineRelease
	KindDpkgStatus
	KindDpkgStatusD // one distroless status.d paragraph; see dpkgPackages
	KindApkInstalled
	KindRpmDB          // an rpm database, or its SQLite write-ahead log; see rpmPackages
	KindChiselManifest // Ubuntu Chiseled; see chiselPackages
	KindNpmLock
	KindPyRequirements
	// Language kinds — self-describing; see ParseManifest.
	KindNpmInstalled
	KindPyDistInfo
	KindGemSpec
	KindGoBinary
)

// IsLanguage reports whether ParseManifest can convert this kind from bytes
// alone. Everything else needs the filesystem and is InventoryPackages' job.
func (k ManifestKind) IsLanguage() bool {
	switch k {
	case KindNpmInstalled, KindPyDistInfo, KindGemSpec, KindGoBinary:
		return true
	}
	return false
}

// Discovery limits. Language manifests live at arbitrary depth, so unlike the OS
// databases there is no "found it, stop looking" bound — these caps are what
// bounds the work instead.
const (
	// maxLangManifestBytes caps one language manifest. A node_modules
	// package.json or a dist-info METADATA is a few KiB; the cap stops a hostile
	// or corrupt file from being buffered without bound.
	maxLangManifestBytes = 4 << 20
	// minGoBinaryBytes is below any real Go binary (the runtime alone is ~1 MiB),
	// so it excludes the shell scripts and small C utilities that make up most of
	// an image's executable files without excluding anything we want.
	minGoBinaryBytes = 1 << 20
	// maxGoBinaryBytes caps one binary. buildinfo needs the whole file as a
	// ReaderAt, so this is a real memory ceiling per in-flight scan.
	maxGoBinaryBytes = 256 << 20
	// maxGoProbeBytes caps how much a single filesystem may spend probing
	// executables that turn out not to be Go — without it, an image full of
	// large non-Go executables would have the probe buffer all of it looking
	// for something that isn't there.
	maxGoProbeBytes = 512 << 20
)

// elfMagic starts every ELF file. Checked before a candidate is buffered: it is
// the cheapest way to reject the large non-executable data files that share an
// executable bit, and a Go program binary is always ELF on the platforms we scan.
var elfMagic = []byte{0x7f, 0x45, 0x4c, 0x46}

// ELFPrefixLen is how many leading bytes IsELF needs.
const ELFPrefixLen = 4

// IsELF reports whether a file's leading bytes are an ELF header.
//
// Exported for the image scanner, which sees candidate binaries as a tar entry
// rather than a file: it needs to make the same four-byte decision before
// buffering as this walk does, rather than buffering non-Go executables whole
// looking for build info that isn't there.
func IsELF(head []byte) bool {
	return len(head) >= ELFPrefixLen && bytes.Equal(head[:ELFPrefixLen], elfMagic)
}

// ClassifyManifest maps one filesystem entry to the parser that reads it.
//
// It is the SINGLE definition of "what is worth reading", shared by both
// readers: InventoryPackages classifies directory entries of an assembled
// root, and the image scanner classifies tar headers as it streams a layer. A
// pattern added here is therefore covered on both paths by construction.
//
// mode and size are the entry's; they are only consulted for KindGoBinary,
// whose candidates cannot be recognised by path.
func ClassifyManifest(p string, mode fs.FileMode, size int64) ManifestKind {
	switch p {
	case osReleasePath, usrOSReleasePath:
		return KindOSRelease
	case alpineReleasePath:
		return KindAlpineRelease
	case dpkgStatusPath:
		return KindDpkgStatus
	case apkInstalledPath, usrApkInstalledPath:
		return KindApkInstalled
	case chiselManifestPath:
		return KindChiselManifest
	case nodeLockPath:
		return KindNpmLock
	case pyRequirementsPath:
		return KindPyRequirements
	}

	if slices.Contains(rpmDBPaths, p) || isRPMWAL(p) {
		return KindRpmDB
	}

	base, dir := path.Base(p), path.Dir(p)
	switch {
	case dir == dpkgStatusDir && !strings.HasSuffix(base, ".md5sums"):
		return KindDpkgStatusD
	case base == "package.json" && inNodeModules(dir):
		return KindNpmInstalled
	case base == "METADATA" && strings.HasSuffix(path.Base(dir), ".dist-info"):
		return KindPyDistInfo
	case base == "PKG-INFO" && strings.HasSuffix(path.Base(dir), ".egg-info"):
		return KindPyDistInfo
	case strings.HasSuffix(base, ".gemspec") && path.Base(dir) == "specifications":
		return KindGemSpec
	case isGoBinaryCandidate(base, mode, size):
		return KindGoBinary
	}
	return KindNone
}

// inNodeModules reports whether dir is an installed npm package's directory:
// node_modules/<name> or node_modules/@<scope>/<name>. Deeper package.json files
// (a package's own test fixtures) are ignored — they describe software that was
// never installed.
func inNodeModules(dir string) bool {
	parent := path.Dir(dir)
	if path.Base(parent) == "node_modules" {
		return true
	}
	return strings.HasPrefix(path.Base(parent), "@") && path.Base(path.Dir(parent)) == "node_modules"
}

// isGoBinaryCandidate reports whether an entry is worth buffering to look for Go
// build info. Shared objects are excluded by name: they are ELF and executable
// but are never a Go program binary, and on an ML image they are most of the
// bytes (libtorch and friends).
func isGoBinaryCandidate(base string, mode fs.FileMode, size int64) bool {
	if !mode.IsRegular() || mode&0o111 == 0 {
		return false
	}
	if size < minGoBinaryBytes || size > maxGoBinaryBytes {
		return false
	}
	return !strings.Contains(base, ".so")
}

// ParseManifest converts one language manifest's bytes into installed
// packages.
//
// Bytes in, packages out, no filesystem: that is what lets the image scanner
// call it while streaming a layer and keep only the result, rather than
// retaining every manifest to parse later.
//
// A kind this cannot parse (an OS database, KindNone) yields nil rather than
// an error: discovery is best-effort by design, and a manifest that fails to
// parse is degraded coverage, never a failed scan.
func ParseManifest(kind ManifestKind, p string, data []byte) []InstalledPackage {
	switch kind {
	case KindNpmInstalled:
		return npmInstalledPackages(p, data)
	case KindPyDistInfo:
		return pyDistInfoPackages(p, data)
	case KindGemSpec:
		return gemSpecPackages(p)
	case KindGoBinary:
		return goBinaryPackages(p, data)
	}
	return nil
}

// languagePackages walks root and parses every language manifest it finds.
//
// A full walk is the termination rule: unlike the OS databases, which a
// filesystem holds at most one of, language manifests have no such bound.
// What limits the walk instead is the caps above (per-file, and a probe
// budget for executables) plus the caller's own limits. gap says which
// packages a limit kept out, "" when none: a binary past the probe budget is
// uninventoried, not package-free.
func languagePackages(ctx context.Context, root fs.FS, goBudget int64) (pkgs []InstalledPackage, gap string) {
	var (
		out       []InstalledPackage
		budget    = goBudget
		exhausted bool
	)
	_ = fs.WalkDir(root, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, never fatal
		}
		if d.IsDir() {
			if skipPackageDirs[p] || skipPackageDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		kind := ClassifyManifest(p, info.Mode(), info.Size())
		if !kind.IsLanguage() {
			return nil
		}
		if kind == KindGoBinary && budget < info.Size() {
			exhausted = true
			return nil
		}
		data, readErr := readCapped(root, p, kind)
		if readErr != nil {
			return nil
		}
		if kind == KindGoBinary {
			// Charged AFTER the read, which fails on the ELF check for anything
			// that is not a binary at all: a budget spent on shared objects and
			// data files would run out before the one binary that matters.
			budget -= int64(len(data))
		}
		out = append(out, ParseManifest(kind, p, data)...)
		return nil
	})
	if exhausted {
		gap = fmt.Sprintf("the %d MiB Go build-info probe budget was spent; later Go binaries were not inventoried", goBudget>>20)
		log.FromContext(ctx).Warn().Int64("budget_bytes", goBudget).
			Msg("pkginventory: Go build-info probe budget exhausted; some binaries were not inventoried")
	}
	return out, gap
}

// skipPackageDirs are directories that hold no installed software: kernel and
// device pseudo-filesystems. It does NOT exclude node_modules or vendor — those
// are exactly where installed language packages live.
var skipPackageDirs = map[string]bool{
	"proc": true, "sys": true, "dev": true, "run": true,
}

// readCapped reads a discovered file under the cap appropriate to its kind. A Go
// binary is checked for the ELF magic before the rest is buffered, so a large
// non-ELF file costs four bytes instead of its whole size.
func readCapped(root fs.FS, p string, kind ManifestKind) ([]byte, error) {
	f, err := root.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	if kind != KindGoBinary {
		return io.ReadAll(io.LimitReader(f, maxLangManifestBytes))
	}
	head := make([]byte, ELFPrefixLen)
	if _, err := io.ReadFull(f, head); err != nil || !IsELF(head) {
		return nil, fs.ErrInvalid
	}
	rest, err := io.ReadAll(io.LimitReader(f, maxGoBinaryBytes))
	if err != nil {
		return nil, err
	}
	return append(head, rest...), nil
}

// npmInstalledPackages reads an installed package's own package.json.
// Installed artifacts rather than the lockfile: a lockfile lists what a build
// resolved, including dev and optional dependencies that `npm ci --omit=dev`
// then pruned, while node_modules is what actually shipped.
func npmInstalledPackages(p string, data []byte) []InstalledPackage {
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &pkg) != nil || pkg.Name == "" || pkg.Version == "" {
		return nil
	}
	return []InstalledPackage{{Ecosystem: "npm", Name: pkg.Name, Version: pkg.Version, Source: p}}
}

// pyDistInfoPackages reads the Name/Version headers of an installed
// distribution's METADATA (or an egg-info PKG-INFO). Both are RFC 822 headers
// terminated by the first blank line, after which the long description begins —
// which may itself contain lines starting with "Name:".
func pyDistInfoPackages(p string, data []byte) []InstalledPackage {
	var name, version string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers
		}
		if v, ok := strings.CutPrefix(line, "Name:"); ok && name == "" {
			name = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Version:"); ok && version == "" {
			version = strings.TrimSpace(v)
		}
	}
	_ = sc.Err()
	if name == "" || version == "" {
		return nil
	}
	return []InstalledPackage{{Ecosystem: "PyPI", Name: name, Version: version, Source: p}}
}

// gemSpecPackages reads an installed gem's coordinates from its stub filename.
// RubyGems writes specifications/<name>-<version>[-<platform>].gemspec, so the
// name is authoritative there — and reading it beats parsing the file, which is
// executable Ruby.
func gemSpecPackages(p string) []InstalledPackage {
	segs := strings.Split(strings.TrimSuffix(path.Base(p), ".gemspec"), "-")
	for i := 1; i < len(segs); i++ {
		if segs[i] == "" || segs[i][0] < '0' || segs[i][0] > '9' {
			continue // still in the name (rack-2.2.3, net-http-0.4.1)
		}
		// Anything after the version is the platform (x86_64-linux), not identity.
		return []InstalledPackage{{
			Ecosystem: "RubyGems", Name: strings.Join(segs[:i], "-"),
			Version: segs[i], Source: p,
		}}
	}
	return nil
}

// goBinaryPackages reads the module list Go links into every binary it
// builds. This is the only language inventory that needs no manifest at all —
// a distroless image ships one static binary and nothing else, so there is no
// lockfile to find and no other way to learn what is in it.
//
// The main module is skipped along with every other "(devel)" version: an
// unversioned module cannot be matched against an advisory, and emitting it
// would mint a package node that no repo SBOM can ever join to.
func goBinaryPackages(p string, data []byte) []InstalledPackage {
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return nil // not a Go binary, or one too old to carry module info
	}
	return goModulePackages(p, info.Deps)
}

// goModulePackages maps a binary's linked modules to packages. A module replaced
// at build time is reported as its REPLACEMENT: that is the code in the binary,
// and the original path would name software the image does not contain.
func goModulePackages(p string, deps []*debug.Module) []InstalledPackage {
	out := make([]InstalledPackage, 0, len(deps))
	for _, dep := range deps {
		if dep == nil {
			continue
		}
		if dep.Replace != nil {
			dep = dep.Replace
		}
		if dep.Path == "" || dep.Version == "" || dep.Version == "(devel)" {
			continue
		}
		out = append(out, InstalledPackage{
			Ecosystem: "Go", Name: dep.Path, Version: dep.Version, Source: p,
		})
	}
	return out
}

// PreInventoried is implemented by a filesystem view that already resolved
// some packages while it was being assembled.
//
// It exists for the image scanner: that source streams layer tars and never
// materialises a rootfs, so packages read out of a Go binary at stream time
// can't be re-derived later without retaining the whole binary. Handing the
// RESULT to InventoryPackages keeps one inventory entry point, so the two
// scanners cannot drift, without that memory cost.
type PreInventoried interface {
	InventoriedPackages() []InstalledPackage
}
