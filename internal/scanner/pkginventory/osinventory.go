package pkginventory

import (
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
)

// This file is the producer of VM software inventory: an OS inventory API (AWS
// SSM Inventory, GCP OS Config) that reports the installed package list
// directly, with no disk to read. It shares the image scanner's package
// identity — the same InstalledPackage, PURL and packageAsset — so a package
// found on a VM through SSM, inside a container image, and in a repo SBOM is ONE
// graph node.

// InventoryEcosystem maps a VM's OS identity, as an inventory API reports it, to
// the ecosystem coordinate its packages are stamped with (see internal/distro).
//
// distro is a lowercase os-release style ID ("ubuntu", "debian", "amzn",
// "rhel", "rocky", "almalinux", "centos", "sles", "opensuse-leap", "ol"),
// version its VERSION_ID.
//
// An empty ecosystem means the platform has no package identity at all
// (Windows, macOS, an unrecognised distro): the caller records no inventory.
// Whether the packages can support a CVE verdict is a separate question —
// CVEGap.
func InventoryEcosystem(distro, version string) string {
	major, _, _ := strings.Cut(version, ".")
	switch strings.ToLower(distro) {
	case "ubuntu":
		return ubuntuEcosystem(version)
	case "debian":
		return qualified("Debian", major) // unqualified is a real (over-inclusive) OSV ecosystem; see debianEcosystem
	case "almalinux":
		return qualified("AlmaLinux", major)
	case "rocky":
		return qualified("Rocky Linux", major)
	case "rhel":
		return qualified("Red Hat", major)
	case "ol", "oracle":
		return qualified("Oracle Linux", major)
	case "centos":
		return qualified("CentOS", major)
	case "amzn":
		// Amazon Linux 1 reports its YYYY.MM release ("2018.03"); 2 and 2023
		// report their own name.
		if strings.HasPrefix(major, "20") && major != "2023" {
			return "Amazon Linux:1"
		}
		return qualified("Amazon Linux", major)
	case "sles", "suse", "sled":
		// SUSE's OSV ecosystems are per product and service pack
		// ("SUSE:Linux Enterprise Server 15 SP5"); the release is kept whole and
		// the OSV client selects the matching products (internal/intel/osv).
		return qualified("SUSE", version)
	case "opensuse-leap", "opensuse":
		if version == "" {
			return "openSUSE"
		}
		return "openSUSE:Leap " + version
	case "opensuse-tumbleweed":
		return "openSUSE:Tumbleweed"
	}
	return ""
}

func qualified(family, release string) string {
	if release == "" {
		return family
	}
	return family + ":" + release
}

// CVEGap says why a VM's packages cannot support a CVE verdict either way — a
// clean-looking VM with zero CVE findings is only clean when it returns "". The
// values are asset.CVEGap*.
//
// sourceNames reports whether the inventory carries each package's SOURCE
// package name. Debian, Ubuntu, Rocky Linux and SUSE publish advisories against
// source packages (openssl), while an inventory lists binaries (libssl3): queried
// by binary name, only the binaries that share their source's name can match,
// and the host looks cleaner than it is.
//
// enabled is the deployment's switched-on advisory sources: a family whose
// source is off is matched against nothing, which is not the same as clean.
func CVEGap(ecosystem string, sourceNames bool, enabled distro.Sources, now time.Time) string {
	fam, ok := distro.FamilyOf(ecosystem)
	if !ok {
		return asset.CVEGapNoAdvisorySource
	}
	if l, ok := distro.EndOfLife(ecosystem); ok && l.Final && l.Past(now) {
		return asset.CVEGapEOLDistro
	}
	switch {
	case fam.Source == "":
		return asset.CVEGapNoAdvisorySource
	case !enabled[fam.Source]:
		return asset.CVEGapAdvisorySourceDisabled
	case distro.Release(ecosystem) == "" && fam.Name != "Debian" && !fam.Rolling:
		return asset.CVEGapUnknownRelease
	case fam.SourceKeyed && !sourceNames:
		return asset.CVEGapNoSourceNames
	}
	return ""
}

// OSCVEGap says why a scanned root's OS packages cannot support a CVE verdict
// (asset.CVEGap*), and the ecosystem they belong to; "" when they can, or when
// the root has no OS at all — no os-release and no package database (scratch,
// a static binary). detail is the precise reason, when there is one.
//
// The packages decide it through CVEGap: an end-of-life release, an
// unresolved release or a switched-off feed is a gap for a dpkg, apk and rpm
// root alike. Two degraded inputs are gaps of their own, never a clean root:
//   - OS packages with no os-release: their ecosystem is a fallback (dpkg's is
//     unqualified "Debian", the union of every release), not a reading;
//   - os-release naming a distribution, but no OS packages — an rpm database
//     that could not be read, an image that ships no database the scanner
//     reads (Ubuntu Chiseled without its manifest), a dpkg or apk database
//     that parsed to nothing. That image would read exactly like a patched one.
func OSCVEGap(root fs.FS, pkgs []InstalledPackage, enabled distro.Sources, now time.Time) (ecosystem, gap, detail string) {
	var osPkgs []InstalledPackage
	for _, p := range pkgs {
		if _, ok := distro.FamilyOf(p.Ecosystem); ok {
			osPkgs = append(osPkgs, p)
		}
	}
	rel := detectRelease(root)
	if len(osPkgs) > 0 {
		eco := osPkgs[0].Ecosystem
		if rel.id == "" {
			return eco, asset.CVEGapUnknownRelease, "the root carries OS packages but no readable os-release"
		}
		return eco, CVEGap(eco, HasSourceNames(osPkgs), enabled, now), ""
	}
	dbPath := rpmDBPath(root)
	if rel.id == "" {
		if dbPath != "" {
			return "", asset.CVEGapUnknownRelease, ""
		}
		return "", "", ""
	}
	eco := releaseEcosystem(rel)
	if _, known := distro.FamilyOf(eco); !known {
		return "", asset.CVEGapNoAdvisorySource, fmt.Sprintf("distribution %q has no advisory source", rel.id)
	}
	if dbPath != "" && rpmEcosystem(rel) != "" {
		// Read again for the reason: this is the failure path only, and the
		// inventory that failed does not carry its error.
		if _, err := rpmPackages(root, eco); err != nil {
			detail = err.Error()
		}
		return eco, asset.CVEGapPackageDBUnread, detail
	}
	return eco, asset.CVEGapPackageDBUnread,
		fmt.Sprintf("os-release names %q, but no OS package database the scanner reads yielded any packages", rel.id)
}

// HasSourceNames reports whether an inventory carries source package names.
// "Any", not "all": rpm reports none for synthetic packages (gpg-pubkey), and a
// list where the producer supplied them for real packages has them.
func HasSourceNames(pkgs []InstalledPackage) bool {
	for _, p := range pkgs {
		if p.SourceName != "" {
			return true
		}
	}
	return false
}

// SourceRPMName extracts the source package name from an rpm SOURCERPM value
// ("openssl-3-3.0.8-150500.5.3.1.src.rpm" → "openssl-3"), which is what SSM
// Inventory reports as an rpm package's PackageId. The name is everything before
// the last two '-'-separated fields (version and release, which cannot contain
// '-'). Anything else — "(none)", a dpkg "<name>_<version>_<arch>.deb" id — is "".
func SourceRPMName(srpm string) string {
	base, ok := strings.CutSuffix(strings.TrimSpace(srpm), ".src.rpm")
	if !ok {
		return ""
	}
	i := strings.LastIndexByte(base, '-')
	if i <= 0 {
		return ""
	}
	j := strings.LastIndexByte(base[:i], '-')
	if j <= 0 {
		return ""
	}
	return base[:j]
}

// InventoryPackage builds one package from an inventory API record. RPM-based
// inventories report version, release and epoch separately; OSV and the purl
// want the single EVR string rpm itself compares ("1:1.0.2k-24.amzn2"). Debian
// inventories report the full dpkg version in version and nothing in release,
// which passes through unchanged. A zero/absent epoch is dropped, as rpm does.
func InventoryPackage(ecosystem, name, version, release, epoch, source string) (InstalledPackage, bool) {
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if name == "" || version == "" {
		return InstalledPackage{}, false
	}
	if release = strings.TrimSpace(release); release != "" && !strings.HasSuffix(version, "-"+release) {
		version += "-" + release
	}
	if epoch = strings.TrimSpace(epoch); epoch != "" && epoch != "0" && epoch != "(none)" && !strings.Contains(version, ":") {
		version = epoch + ":" + version
	}
	return InstalledPackage{Ecosystem: ecosystem, Name: name, Version: version, Source: source}, true
}

// InventoryGraph shapes a VM's inventory into package assets + runs_package
// edges, one per distinct purl.
//
// Every package keeps its ecosystem coordinate, matchable or not: the OSV client
// excludes, per package, an ecosystem OSV does not serve (internal/intel/osv),
// and the distro advisory feeds read the Amazon Linux and Oracle Linux ones.
func InventoryGraph(assetID, assetType string, pkgs []InstalledPackage, now time.Time) ([]asset.Asset, []asset.Edge) {
	seen := make(map[string]bool, len(pkgs))
	assets := make([]asset.Asset, 0, len(pkgs))
	edges := make([]asset.Edge, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Ecosystem == "" || p.Name == "" || p.Version == "" {
			continue
		}
		purl := PURL(p)
		if seen[purl] {
			continue
		}
		seen[purl] = true
		assets = append(assets, packageAsset(p, purl, assetType, now))
		edges = append(edges, asset.Edge{
			SrcID: assetID, SrcType: assetType,
			DstID: purl, DstType: "package",
			EdgeType: "runs_package",
		})
	}
	return assets, edges
}
