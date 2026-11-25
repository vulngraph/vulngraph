// Package pkginventory turns a software inventory into packages the CVE path
// can match. It parses installed-package lists out of a root filesystem (dpkg,
// apk, rpm, Ubuntu chisel manifests, language manifests and Go binaries) for
// the container image scanner, and maps the package lists that OS inventory
// APIs report (AWS SSM Inventory, GCP OS Config) for the VM collectors.
//
// Both paths share one package identity (InstalledPackage and PURL), so a
// package seen on a VM, in an image and in a repo SBOM is one graph node, and
// one gap verdict (CVEGap, OSCVEGap) saying whether an advisory source can
// match the inventory at all. It reads the files it is handed and never
// acquires a disk.
package pkginventory

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// InstalledPackage is one package discovered on the scanned filesystem, in OSV
// ecosystem terms so it can be matched against the existing OSV/KEV/EPSS path.
//
// Ecosystem is the OSV ecosystem string VERBATIM, including the release
// qualifier OSV requires for distro packages ("Debian:12", "Ubuntu:22.04",
// "Alpine:v3.19"). The qualifier is not cosmetic: OSV's unqualified "Debian"
// ecosystem is the union of every Debian release and so over-matches, while
// "Alpine" unqualified matches NOTHING at all.
type InstalledPackage struct {
	Ecosystem string // OSV ecosystem: "Debian:12", "Alpine:v3.19", "npm", "PyPI", …
	Name      string
	Version   string
	Source    string // manifest path it was found in
	// SourceName is the source package the binary was built from, when the
	// producer reports it (dpkg's Source field, apk's origin, SSM Inventory's rpm
	// PackageId). Advisory sources keyed by source package are queried by it; see
	// distro.Family.SourceKeyed.
	SourceName string
	// SourceVersion is the source package's version when it differs from the
	// binary's (a Debian binNMU, a separately-versioned binary), else "".
	SourceVersion string
}

// Manifest paths read by the parsers below. Declared as consts because they are
// also the fetch list the image scanner streams out of a registry layer.
const (
	osReleasePath       = "etc/os-release"
	usrOSReleasePath    = "usr/lib/os-release" // what etc/os-release symlinks to on Debian, Ubuntu and distroless
	alpineReleasePath   = "etc/alpine-release"
	dpkgStatusPath      = "var/lib/dpkg/status"
	dpkgStatusDir       = "var/lib/dpkg/status.d" // distroless: one paragraph per package, no status file
	apkInstalledPath    = "lib/apk/db/installed"
	usrApkInstalledPath = "usr/lib/apk/db/installed" // usrmerged Wolfi/Chainguard: lib is a symlink to usr/lib
	nodeLockPath        = "package-lock.json"
	pyRequirementsPath  = "requirements.txt"
)

// PackageManifestPaths is every FIXED path InventoryPackages reads, declared
// once so callers that must FETCH those files can derive the list instead of
// duplicating it. TestPackageManifestPathsCoversEveryParser locks the two
// together.
//
// It is not the whole read set: language manifests live at arbitrary depth
// (node_modules/<pkg>/package.json, <dist>.dist-info/METADATA) and cannot be
// enumerated as paths, so a caller must classify against ClassifyManifest
// instead, which recognises these paths too.
func PackageManifestPaths() []string {
	return append([]string{
		osReleasePath,       // distro + release detection
		usrOSReleasePath,    // the same file, where etc/os-release is a symlink
		alpineReleasePath,   // Alpine release fallback on images without os-release
		dpkgStatusPath,      // Debian/Ubuntu
		apkInstalledPath,    // Alpine
		usrApkInstalledPath, // Wolfi/Chainguard (usrmerged)
		chiselManifestPath,  // Ubuntu Chiseled, which ships no dpkg database
		nodeLockPath,        // npm
		pyRequirementsPath,  // PyPI
	}, rpmDBPaths...) // RHEL family, Amazon Linux, SUSE
}

// Inventory is a root's installed packages and what the walk could not see.
type Inventory struct {
	Packages []InstalledPackage
	// LanguageGap says which language packages a walk limit kept out (the Go
	// build-info probe budget), "" when none were. It is never an OS gap: the
	// OS databases are fixed paths no limit skips.
	LanguageGap string
}

// InventoryPackages walks a filesystem root and returns installed OS + language
// packages, and any language gap. It reads the standard manifests in place — no package manager is
// invoked — so it works on a read-only root such as a mounted image rootfs.
//
// ctx is used only for logging: an Alpine root whose release cannot be resolved
// yields packages that match zero advisories, and that has to be visible rather
// than silently returning an empty CVE list forever.
func InventoryPackages(ctx context.Context, root fs.FS) Inventory {
	rel := detectRelease(root)

	alpineEco := apkEcosystem(rel)
	apk := apkPackages(root, alpineEco)
	if len(apk) > 0 && alpineEco == alpineUnqualified {
		// Unlike Debian's, this fallback does NOT keep coverage: OSV has no
		// unqualified "Alpine" ecosystem, so every one of these packages matches
		// zero advisories. Warn only when there are apk packages to lose — a
		// Debian root legitimately produces the same string and no apk database.
		log.FromContext(ctx).Warn().
			Str("os_release_id", rel.id).
			Str("version_id", rel.versionID).
			Int("packages", len(apk)).
			Msg("apk packages could not be assigned an Alpine release ecosystem — OSV has no unqualified \"Alpine\" ecosystem, so these packages will match zero advisories")
	}

	rpm, err := rpmPackages(root, rpmEcosystem(rel))
	if err != nil {
		// OSCVEGap reports the root's OS packages unread, with this reason.
		log.FromContext(ctx).Warn().Err(err).
			Str("os_release_id", rel.id).
			Str("version_id", rel.versionID).
			Msg("rpm database could not be read in full — no OS packages inventoried from it")
	}

	var out []InstalledPackage
	out = append(out, dpkgPackages(root, debianEcosystem(rel))...)   // Debian/Ubuntu
	out = append(out, apk...)                                        // Alpine
	out = append(out, chiselPackages(root, debianEcosystem(rel))...) // Ubuntu Chiseled
	out = append(out, rpm...)                                        // RHEL family, Amazon Linux, SUSE
	out = append(out, nodePackages(root)...)                         // npm (package-lock.json)
	out = append(out, pythonPackages(root)...)                       // PyPI (requirements.txt)
	lang, gap := languagePackages(ctx, root, maxGoProbeBytes)
	out = append(out, lang...) // npm/PyPI/RubyGems/Go, at any depth
	if pre, ok := root.(PreInventoried); ok {
		// A streaming source resolved these while assembling the view; see
		// PreInventoried.
		out = append(out, pre.InventoriedPackages()...)
	}
	return Inventory{Packages: out, LanguageGap: gap}
}

// osRelease is the distro identity read off the scanned filesystem.
type osRelease struct {
	id        string // ID= — "debian", "ubuntu", "alpine"
	idLike    string // ID_LIKE= — "debian" on derivatives (raspbian, …)
	versionID string // VERSION_ID= — "12", "22.04", "3.19.1"
}

// detectRelease reads /etc/os-release, falling back to /etc/alpine-release for
// minimal Alpine images that ship no os-release. Both files are always opened so
// the set of paths this package reads is deterministic (see PackageManifestPaths).
func detectRelease(root fs.FS) osRelease {
	rel := parseOSRelease(root)
	alpine := readAlpineRelease(root)
	if rel.id == "" && alpine != "" {
		rel.id, rel.versionID = "alpine", alpine
	}
	if rel.id == "alpine" && rel.versionID == "" {
		rel.versionID = alpine
	}
	return rel
}

// parseOSRelease reads the shell-style key=value pairs of /etc/os-release,
// falling back to /usr/lib/os-release as os-release(5) specifies. The fallback is
// not academic: on Debian, Ubuntu and distroless images /etc/os-release is a
// symlink to ../usr/lib/os-release, and the image scanner never follows symlinks
// out of a layer tar — so without it every Ubuntu image would be stamped
// "Debian", queried against the union of every Debian release and keyed under
// pkg:deb/debian.
func parseOSRelease(root fs.FS) osRelease {
	f, err := root.Open(osReleasePath)
	if err != nil {
		if f, err = root.Open(usrOSReleasePath); err != nil {
			return osRelease{}
		}
	}
	defer func() { _ = f.Close() }()

	var rel osRelease
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, value, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"'`)
		switch key {
		case "ID":
			rel.id = strings.ToLower(value)
		case "ID_LIKE":
			rel.idLike = strings.ToLower(value)
		case "VERSION_ID":
			rel.versionID = value
		}
	}
	_ = sc.Err()
	return rel
}

// readAlpineRelease reads /etc/alpine-release, a bare version string ("3.19.1").
func readAlpineRelease(root fs.FS) string {
	data, err := fs.ReadFile(root, alpineReleasePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// debianEcosystem maps a detected release to the OSV ecosystem for dpkg packages.
//
// Ubuntu is a separate OSV ecosystem, not a Debian release: its version strings
// (3.0.2-0ubuntu1.15) sort below nearly every Debian fixed-version, so labelling
// an Ubuntu image "Debian" reports it as unpatched against advisories that do not
// describe it. Derivatives are routed by ID_LIKE.
//
// An undetectable release falls back to the unqualified ecosystem: that is
// over-inclusive (it is the union of all releases) but it keeps coverage, and it
// is rare — a dpkg-managed image without /etc/os-release is close to nonexistent.
// This is a property of the "Debian" ecosystem specifically and does NOT
// generalise: OSV publishes no unqualified "Alpine" ecosystem, so the equivalent
// Alpine fallback loses coverage entirely (see alpineEcosystem).
func debianEcosystem(rel osRelease) string {
	switch family(rel) {
	case "ubuntu":
		// Delegated so the LTS qualifier is decided in exactly one place — OSV
		// keys LTS releases as "Ubuntu:20.04:LTS" and the bare form unions in
		// other releases' advisories. See ubuntuEcosystem.
		return ubuntuEcosystem(rel.versionID)
	case "debian":
		// Debian releases are OSV-keyed by major only ("12"); testing/sid carry
		// no VERSION_ID and fall through to the unqualified fallback.
		if major, _, _ := strings.Cut(rel.versionID, "."); major != "" {
			return "Debian:" + major
		}
	}
	return "Debian"
}

// alpineUnqualified is what alpineEcosystem returns when it cannot resolve a
// release. It is NOT a working ecosystem: OSV publishes Alpine advisories only
// under "Alpine:v<major>.<minor>", and a query for bare "Alpine" returns zero
// results. Any apk package stamped with it is silently uncovered, which is why
// InventoryPackages warns when it stamps packages with it.
const alpineUnqualified = "Alpine"

// alpineEcosystem maps a detected release to the OSV ecosystem for apk packages.
// Alpine is keyed by "v<major>.<minor>"; every other path is the zero-coverage
// fallback described on alpineUnqualified.
func alpineEcosystem(rel osRelease) string {
	if rel.id != "alpine" {
		return alpineUnqualified
	}
	major, rest, ok := strings.Cut(rel.versionID, ".")
	if !ok || major == "" {
		return alpineUnqualified
	}
	minor, _, _ := strings.Cut(rest, ".")
	// Edge builds carry suffixed versions ("3.22.0_alpha20240101"); keep digits only.
	minor = strings.TrimRight(minor, "abcdefghijklmnopqrstuvwxyz_-")
	if minor == "" {
		return alpineUnqualified
	}
	return "Alpine:v" + major + "." + minor
}

// apkEcosystem maps a detected release to the OSV ecosystem for apk packages.
// Wolfi and Chainguard OS use apk but are not Alpine: their package versions and
// advisories are their own, and OSV publishes them as the rolling, unqualified
// "Wolfi" and "Chainguard" ecosystems. Stamped "Alpine" they matched nothing.
func apkEcosystem(rel osRelease) string {
	switch rel.id {
	case "wolfi":
		return "Wolfi"
	case "chainguard":
		return "Chainguard"
	}
	return alpineEcosystem(rel)
}

// rpmEcosystem is the ecosystem an rpm database's packages are stamped with,
// "" unless the release is an rpm distribution: a Debian or Alpine image that
// happens to carry an rpm database (the rpm tool installed for packaging work)
// does not run those packages as its OS.
func rpmEcosystem(rel osRelease) string {
	eco := InventoryEcosystem(rel.id, rel.versionID)
	if purlEcosystemType[ecosystemFamily(eco)].typ != "rpm" {
		return ""
	}
	return eco
}

// releaseEcosystem is the OS ecosystem a release's packages would be stamped
// with, whichever package manager it uses; "" for a distribution with none.
func releaseEcosystem(rel osRelease) string {
	switch f := family(rel); {
	case f == "debian" || f == "ubuntu":
		return debianEcosystem(rel)
	case rel.id == "alpine" || rel.id == "wolfi" || rel.id == "chainguard":
		return apkEcosystem(rel)
	}
	return InventoryEcosystem(rel.id, rel.versionID)
}

// family resolves the distro family, preferring ID and falling back to ID_LIKE so
// derivatives (raspbian → debian, linuxmint → ubuntu) land on the right ecosystem.
func family(rel osRelease) string {
	if rel.id == "debian" || rel.id == "ubuntu" {
		return rel.id
	}
	for _, like := range strings.Fields(rel.idLike) {
		if like == "ubuntu" || like == "debian" {
			return like
		}
	}
	return rel.id
}

// dpkgPackages reads the dpkg database: /var/lib/dpkg/status on a full Debian or
// Ubuntu install, plus one control paragraph per package under
// /var/lib/dpkg/status.d/ on distroless images, which ship no status file.
func dpkgPackages(root fs.FS, ecosystem string) []InstalledPackage {
	var out []InstalledPackage
	if f, err := root.Open(dpkgStatusPath); err == nil {
		out = parseDpkgStatus(f, ecosystem, dpkgStatusPath)
		_ = f.Close()
	}
	entries, err := fs.ReadDir(root, dpkgStatusDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		p := path.Join(dpkgStatusDir, e.Name())
		if e.IsDir() || ClassifyManifest(p, e.Type(), 0) != KindDpkgStatusD {
			continue
		}
		f, err := root.Open(p)
		if err != nil {
			continue
		}
		out = append(out, parseDpkgStatus(f, ecosystem, p)...)
		_ = f.Close()
	}
	return out
}

// parseDpkgStatus reads dpkg control paragraphs. Package and Version identify the
// binary; Source names the source package it was built from — "openssl", or
// "gcc-defaults (1.203)" when the source version differs from the binary's — and
// is absent when the two share a name. Debian and Ubuntu advisories are keyed by
// that source package (see distro.AdvisoryQuery), so it is carried on every
// package rather than left for a caller to guess.
//
// A paragraph whose Status is not "installed" (removed with its config files
// left behind, half-configured) is not installed software and is skipped.
// Distroless status.d paragraphs carry no Status and are all installed.
func parseDpkgStatus(r io.Reader, ecosystem, source string) []InstalledPackage {
	var out []InstalledPackage
	var name, version, src, status string
	flush := func() {
		if name != "" && version != "" && dpkgInstalled(status) {
			p := InstalledPackage{Ecosystem: ecosystem, Name: name, Version: version, Source: source}
			p.SourceName, p.SourceVersion = dpkgSource(name, version, src)
			out = append(out, p)
		}
		name, version, src, status = "", "", "", ""
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimSpace(value)
		switch key {
		case "":
			if line == "" {
				flush()
			}
		case "Package":
			name = value
		case "Version":
			version = value
		case "Source":
			src = value
		case "Status":
			status = value
		}
	}
	flush()
	_ = sc.Err()
	return out
}

// dpkgInstalled reads a Status field ("install ok installed"): its last word is
// the package's state.
func dpkgInstalled(status string) bool {
	fields := strings.Fields(status)
	return len(fields) == 0 || fields[len(fields)-1] == "installed"
}

// dpkgSource resolves a paragraph's source package. An absent Source field means
// the source shares the binary's name and version; the source version is
// returned only when it differs from the binary's.
func dpkgSource(name, version, field string) (srcName, srcVersion string) {
	if field == "" {
		return name, ""
	}
	srcName, rest, ok := strings.Cut(field, "(")
	if !ok {
		return field, ""
	}
	srcVersion = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ")"))
	if srcVersion == version {
		srcVersion = ""
	}
	return strings.TrimSpace(srcName), srcVersion
}

// apkPackages parses /lib/apk/db/installed (Alpine). Records are paragraph-
// separated with single-letter fields: P=name, V=version, o=origin. The origin is
// the source package (aport) a subpackage was built from — libcrypto3 and
// libssl3 come from openssl — and is what Alpine's advisories are keyed by; it
// always shares the subpackage's version. No origin means the package is its own.
//
// Wolfi and Chainguard images are usrmerged: lib is a symlink to usr/lib, so
// the database is only a regular file at usr/lib/apk/db/installed — and the
// image scanner never follows symlinks.
func apkPackages(root fs.FS, ecosystem string) []InstalledPackage {
	dbPath := apkInstalledPath
	f, err := root.Open(dbPath)
	if err != nil {
		dbPath = usrApkInstalledPath
		if f, err = root.Open(dbPath); err != nil {
			return nil
		}
	}
	defer func() { _ = f.Close() }()

	var out []InstalledPackage
	var name, version, origin string
	flush := func() {
		if name != "" && version != "" {
			if origin == "" {
				origin = name
			}
			out = append(out, InstalledPackage{
				Ecosystem: ecosystem, Name: name, Version: version, Source: dbPath, SourceName: origin,
			})
		}
		name, version, origin = "", "", ""
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "P:"):
			name = strings.TrimPrefix(line, "P:")
		case strings.HasPrefix(line, "V:"):
			version = strings.TrimPrefix(line, "V:")
		case strings.HasPrefix(line, "o:"):
			origin = strings.TrimPrefix(line, "o:")
		}
	}
	flush()
	_ = sc.Err()
	return out
}

// nodePackages parses a package-lock.json for npm dependencies (v2/v3 lockfile
// "packages" map). Best-effort — malformed JSON yields no packages.
func nodePackages(root fs.FS) []InstalledPackage {
	data, err := fs.ReadFile(root, nodeLockPath)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var out []InstalledPackage
	for path, p := range lock.Packages {
		if path == "" || p.Version == "" {
			continue // "" is the root project entry
		}
		name := path
		if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
			name = path[i+len("node_modules/"):]
		}
		out = append(out, InstalledPackage{
			Ecosystem: "npm", Name: name, Version: p.Version, Source: nodeLockPath,
		})
	}
	return out
}

// pythonPackages parses requirements.txt pinned dependencies (name==version).
func pythonPackages(root fs.FS) []InstalledPackage {
	f, err := root.Open(pyRequirementsPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var out []InstalledPackage
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, version, ok := strings.Cut(line, "==")
		if !ok {
			continue
		}
		out = append(out, InstalledPackage{
			Ecosystem: "PyPI", Name: strings.TrimSpace(name),
			Version: strings.TrimSpace(version), Source: pyRequirementsPath,
		})
	}
	_ = sc.Err()
	return out
}
