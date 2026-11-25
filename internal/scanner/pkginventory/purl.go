package pkginventory

import (
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// purlEcosystemType maps an OSV ecosystem to its purl type. OS ecosystems
// (Debian/Ubuntu/Alpine) use their distro-scoped purl form; language ecosystems
// use the SBOM collector's purl shape so an identical dependency discovered on a
// VM through its OS inventory, in a container image and in a repo SBOM all
// collapse to ONE node.
//
// Keyed on the ecosystem FAMILY, not the OSV ecosystem string: OSV distro
// ecosystems are release-qualified ("Debian:12", "Alpine:v3.19") but the purl —
// which is the package asset's node id — deliberately is not. Two hosts on
// different Debian releases carrying the same package version are running the
// same package, and re-keying nodes per release would fork the graph and orphan
// every package asset already in ClickHouse.
var purlEcosystemType = map[string]struct {
	typ   string
	scope string // distro namespace for OS packages ("" for language packages)
}{
	"Debian":     {typ: "deb", scope: "debian"},
	"Ubuntu":     {typ: "deb", scope: "ubuntu"},
	"Alpine":     {typ: "apk", scope: "alpine"},
	"Wolfi":      {typ: "apk", scope: "wolfi"},
	"Chainguard": {typ: "apk", scope: "chainguard"},
	// RPM families, minted alike by the OS inventory producers (osinventory.go)
	// and the image scanner's rpm database reader (rpm.go). Without them
	// an RPM package would fall to the pkg:generic fallback and "Red Hat"
	// lowercased to a namespace with a SPACE in it, which is not a well-formed purl.
	"Red Hat":      {typ: "rpm", scope: "redhat"},
	"Rocky Linux":  {typ: "rpm", scope: "rocky"},
	"AlmaLinux":    {typ: "rpm", scope: "almalinux"},
	"Amazon Linux": {typ: "rpm", scope: "amazon"},
	"SUSE":         {typ: "rpm", scope: "suse"},
	"openSUSE":     {typ: "rpm", scope: "opensuse"},
	"CentOS":       {typ: "rpm", scope: "centos"},
	"Oracle Linux": {typ: "rpm", scope: "oracle"},
	"npm":          {typ: "npm"},
	"PyPI":         {typ: "pypi"},
	"Go":           {typ: "golang"},
	"Maven":        {typ: "maven"},
	"crates.io":    {typ: "cargo"},
	"RubyGems":     {typ: "gem"},
}

// ecosystemFamily strips OSV's release qualifier ("Debian:12" → "Debian").
// Language ecosystems carry no qualifier and pass through unchanged.
func ecosystemFamily(ecosystem string) string {
	family, _, _ := strings.Cut(ecosystem, ":")
	return family
}

// PURL builds the stable package URL that is the package asset's node id.
// Unknown ecosystems fall back to pkg:generic/<ecosystem-lowercased>/… so every
// package still gets a stable id — an unmapped ecosystem is degraded coverage,
// never a dropped package.
//
// internal/scanner/imagevuln mints its node ids through this function too, and
// it has to stay that way: the purl is the node key, so any divergence forks one
// package into two graph nodes and makes "where is this package used" answer for
// images or for VMs but never for both. TestPURLMatchesImageScanner drives the
// image scanner and the filesystem walk over a shared fixture.
func PURL(p InstalledPackage) string {
	if m, ok := purlEcosystemType[ecosystemFamily(p.Ecosystem)]; ok {
		name, version := PURLName(m.typ, p.Name), PURLVersion(m.typ, p.Version)
		if m.scope != "" {
			return fmt.Sprintf("pkg:%s/%s/%s@%s", m.typ, m.scope, name, version)
		}
		return fmt.Sprintf("pkg:%s/%s@%s", m.typ, name, version)
	}
	return fmt.Sprintf("pkg:generic/%s/%s@%s", strings.ToLower(p.Ecosystem), strings.ToLower(p.Name), p.Version)
}

// PURLName canonicalises a package name into the form the repo SBOM collector
// emits for the same package, because the purl is the node id and only
// identical strings collapse to one node. Rules are matched to how each
// ecosystem's own tooling normalises names, not derived from the purl spec:
//
//   - deb/apk names are lowercase by distro policy, so lowercasing is a no-op;
//   - golang module paths are lowercased by GitHub's dependency graph, even
//     when the real module path is capitalised (e.g. azure-sdk-for-go);
//   - pypi names are PEP 503 normalised (lowercase, runs of -_. collapsed to
//     one dash);
//   - everything else keeps its case — npm and RubyGems names are real,
//     case-sensitive node ids in the graph, and lowercasing them would fork
//     the package.
func PURLName(purlType, name string) string {
	switch purlType {
	case "deb", "apk", "golang":
		return strings.ToLower(name)
	case "pypi":
		return pep503(name)
	}
	return name
}

// pep503 normalises a Python distribution name: lowercase, with every run of
// -, _ and . collapsed to a single dash.
func pep503(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	dashed := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !dashed {
				b.WriteByte('-')
			}
			dashed = true
			continue
		}
		dashed = false
		b.WriteRune(r)
	}
	return b.String()
}

// PURLVersion encodes a version the way the SBOM collector's purls encode it.
//
// Only golang is touched, and deliberately so: Go's +incompatible versions
// reach the graph percent-encoded (pkg:golang/…@3.12.0%2Bincompatible),
// because that is what GitHub's dependency graph emits and the collector
// copies the locator verbatim. Applying the same encoding to deb would rewrite
// existing package node ids — Debian versions carry a literal + (e.g.
// 3.118+deb11u1) — and orphan every finding on them.
func PURLVersion(purlType, version string) string {
	if purlType == "golang" {
		return strings.ReplaceAll(version, "+", "%2B")
	}
	return version
}

// vmProviders maps a scanned workload's asset type to the cloud it belongs to.
//
// Provider is descriptive on a package node, never a key: package assets are
// keyed by purl and are already written by three producers that each stamp a
// different provider (the repo SBOM collector writes github, the image scanner
// writes kubernetes). An asset type absent here yields an empty provider rather
// than a guess.
var vmProviders = map[string]asset.Provider{
	"ec2_instance": asset.ProviderAWS,
	"gce_instance": asset.ProviderGCP,
	"azure_vm":     asset.ProviderAzure,
}

// packageAsset shapes a package node identical to the SBOM collector's
// (internal/collect/github/sbom.go) and the image scanner's: id=purl, metadata
// carrying the OSV coordinates the OSV refresh reads. Sharing the shape is what
// makes a VM-sourced package and a repo-sourced package with the same purl one node.
func packageAsset(p InstalledPackage, purl, assetType string, now time.Time) asset.Asset {
	a := asset.Asset{
		ID:       purl,
		Name:     p.Name,
		Type:     "package",
		Provider: vmProviders[assetType],
		Region:   "global",
		Metadata: map[string]string{
			"ecosystem": p.Ecosystem,
			"package":   p.Name,
			"version":   p.Version,
			"origin":    assetType,
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}
	if p.SourceName != "" {
		a.Metadata[MetaSourcePackage] = p.SourceName
	}
	if p.SourceVersion != "" {
		a.Metadata[MetaSourceVersion] = p.SourceVersion
	}
	return a
}

// MetaSourcePackage is the package asset's source package name, when its
// producer reported one, and MetaSourceVersion the source version when it
// differs from the binary's. The OSV refresh queries source-keyed ecosystems by
// them (distro.AdvisoryQuery).
const (
	MetaSourcePackage = "source_package"
	MetaSourceVersion = "source_version"
)
