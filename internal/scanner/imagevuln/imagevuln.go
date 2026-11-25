// Package imagevuln gives container images a CVE axis. k8s pods are
// inventoried as container_image assets (internal/collect/kubernetes) and
// graph-linked to their pods (runs_image), but without resolving an image to
// its installed packages a k8s finding has no CVE and so no KEV/EPSS/
// exploitability signal and can never reach must_fix.
//
// Given an image's root filesystem this scanner inventories the installed OS +
// language packages (reusing internal/scanner/pkginventory's manifest parsers),
// matches them against OSV (reusing internal/intel/osv), and emits a
// supply_chain/package finding per (package, CVE) — IDENTICAL in shape to the
// SBOM/OSV feed (internal/jobs/osv.go), so KEV/EPSS escalation and the
// must-fix reachability path light up for images exactly as they already do
// for repo dependencies — plus a package asset and a container_image →
// package `runs_package` edge so the must-fix traversal can walk
// package ← runs_package ← container_image ← runs_image ← k8s_pod → internet.
//
// The image filesystem is supplied through the ImageSource seam:
// RegistryImageSource streams an image out of its registry (registry.go) and
// is the production path; LocalImageSource scans an already-extracted rootfs
// or a test fixture with no registry calls.
//
// Language packages are found as INSTALLED ARTIFACTS at any depth
// (node_modules/<pkg>/package.json, <dist>.dist-info/METADATA,
// specifications/<gem>.gemspec) plus the module list Go links into every
// binary; on a distroless image the Go binary is the only inventory there is.
// Lockfiles are not searched at depth, because a nested lockfile describes a
// build that may never have been installed. The shared inventory still reads a
// package-lock.json and requirements.txt at the rootfs root, so those findings
// are declared dependencies, not proven installed ones.
package imagevuln

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ImageSource produces a read-only filesystem view of a container image's merged
// root filesystem. Implementations pull the image by digest from its registry and
// return an fs.FS over it — with cleanup releasing any temp storage.
//
// A source that streams rather than materialises a rootfs may resolve some
// packages while it reads and expose them via pkginventory.PreInventoried instead of
// as files; RegistryImageSource does exactly that for Go binaries, which would
// otherwise have to be retained whole.
type ImageSource interface {
	// Open returns a read-only filesystem for the image's merged rootfs plus a
	// cleanup func. ref is the pullable reference (name:tag), digest the
	// sha256:… content digest that uniquely identifies the image.
	Open(ctx context.Context, ref, digest string) (root fs.FS, cleanup func(), err error)
}

// LocalImageSource scans an already-extracted image rootfs (a manually unpacked
// image, a container's live rootfs, or a test fixture). It performs no registry
// calls.
type LocalImageSource struct{ Root string }

// Open confines the scan to Root with os.Root: image content is untrusted, and
// os.DirFS follows an absolute or ../ symlink out of the rootfs onto the
// worker's own filesystem.
func (s LocalImageSource) Open(_ context.Context, _, _ string) (fs.FS, func(), error) {
	r, err := os.OpenRoot(s.Root)
	if err != nil {
		return nil, nil, fmt.Errorf("LocalImageSource: %w", err)
	}
	return r.FS(), func() { _ = r.Close() }, nil
}

// PartialInventory is implemented by an image view that may not have read the
// whole image. A non-empty IncompleteReason means packages are missing — most
// likely the OS base layer's — so the scan must report a gap rather than a
// clean match over what it did read.
type PartialInventory interface {
	IncompleteReason() string
	// LanguageGap says which LANGUAGE packages were not inventoried (a Go
	// probe budget spent, an oversized or hardlinked manifest), "" for none.
	// It never affects the OS gap.
	LanguageGap() string
}

// partialNotes are the view's incomplete reason and language gap, both "" for
// a view that is always whole (a mounted rootfs).
func partialNotes(root fs.FS) (incomplete, languageGap string) {
	if p, ok := root.(PartialInventory); ok {
		return p.IncompleteReason(), p.LanguageGap()
	}
	return "", ""
}

// Package identifies one installed package in OSV ecosystem terms.
type Package struct {
	Ecosystem string // OSV ecosystem: "Debian", "Alpine", "npm", "PyPI", …
	Name      string
	Version   string
}

// Vuln is one check id (osv.Hit) matched on a queried package, reduced to what a
// finding needs.
type Vuln struct {
	// CheckID is the finding's check id: ONE CVE of the advisory (a bundle of
	// several is one Vuln per CVE, so KEV and EPSS see each), the advisory id when
	// it names no CVE, and always the id of a MAL-* advisory.
	CheckID string
	// Advisory is every advisory naming CheckID, comma-separated, as a reference.
	Advisory string
	// CVE is a MAL-* advisory's CVE alias, kept for KEV/EPSS; "" otherwise.
	CVE          string
	Title        string
	Description  string
	Severity     finding.Severity
	FixedVersion string
}

// VulnQuerier matches installed packages to known advisories. An adapter over
// internal/intel/osv.Client satisfies it (see internal/jobs/imagevuln.go), so
// image CVE matching reuses the OSV/KEV/EPSS path with no new feed.
type VulnQuerier interface {
	VulnsFor(ctx context.Context, pkgs []Package) (map[Package][]Vuln, error)
}

// Scanner resolves a container image to its installed packages, matches them
// against known advisories, and emits supply-chain findings + package assets +
// runs_package edges keyed to the image.
type Scanner struct {
	source   ImageSource
	vulns    VulnQuerier
	advisory distro.Sources
}

func New(source ImageSource, vulns VulnQuerier) *Scanner {
	return &Scanner{source: source, vulns: vulns}
}

// WithAdvisorySources declares the deployment's switched-on advisory feeds
// beyond OSV. Amazon Linux and Oracle Linux packages are matched by ALAS and
// ELSA from their package nodes (internal/jobs/distro_advisories.go), not by
// this scanner, so whether those feeds are on decides only the image's
// coverage gap. Unset, they are off: an Amazon Linux image then reports its
// packages unmatched rather than clean.
func (s *Scanner) WithAdvisorySources(enabled distro.Sources) *Scanner {
	s.advisory = enabled
	return s
}

// Name identifies this scanner in finding attribution.
func (s *Scanner) Name() string { return "imagevuln" }

// Result is the output of scanning one image: findings to record and the
// package assets + runs_package edges to ingest so the graph links the image to
// its vulnerable dependencies.
type Result struct {
	Findings []finding.Finding
	Assets   []asset.Asset
	Edges    []asset.Edge
	// Base is what the scan learned about the image's base (baseimage.go).
	Base BaseIdentity
	// OSCVEGap is the image's OS coverage gap (asset.CVEGap*), "" when its OS
	// packages are matched in full — the caller then resolves any coverage
	// finding an earlier scan left open (OSCoverageFindingID).
	OSCVEGap string
	// LanguageGap is why some language packages were not inventoried, "" when
	// none were missed — the caller then resolves LanguageCoverageFindingID.
	LanguageGap string
}

// imageAssetID mirrors the container_image asset ID minted by the kubernetes
// collector (internal/collect/kubernetes): "image/<sha256:hex>". Keeping the
// two in lockstep is what lets the runs_package edge join to the real image node.
func imageAssetID(digest string) string { return "image/" + digest }

// OSCoverageFindingID is the id of an image's OS coverage finding.
func OSCoverageFindingID(digest string) string {
	return dbutil.DeterministicID(osCoverageCheckID, imageAssetID(digest))
}

// ScanImage inventories the image's packages, matches them against OSV, and
// returns the findings + package assets + runs_package edges. digest is the
// sha256:… content digest (also the container_image asset key); ref is the
// pullable reference used for the registry pull and for display.
func (s *Scanner) ScanImage(ctx context.Context, digest, ref string) (Result, error) {
	if digest == "" {
		return Result{}, fmt.Errorf("ScanImage: digest is required")
	}
	root, cleanup, err := s.source.Open(ctx, ref, digest)
	if err != nil {
		return Result{}, fmt.Errorf("ScanImage: open image %s: %w", digest, err)
	}
	defer cleanup()

	// Reuse pkginventory's manifest parsers — identical OS/language package DB
	// formats, deduped to one node per purl here.
	inv := pkginventory.InventoryPackages(ctx, root)
	installed := inv.Packages
	bins, queries := advisoryQueries(installed)

	now := time.Now()
	imgID := imageAssetID(digest)
	eco, gap, detail := pkginventory.OSCVEGap(root, installed, s.enabledSources(), now)
	incomplete, langGap := partialNotes(root)
	langGap = joinNotes(langGap, inv.LanguageGap) // a mounted rootfs's walk has the same probe budget
	if incomplete != "" {
		// Overrides whatever OSCVEGap concluded from the layers that were read:
		// a release-less "Debian" or a zero-package root is exactly what a
		// walk that lost its base layer looks like.
		gap, detail = asset.CVEGapScanIncomplete, incomplete
	}
	res := Result{OSCVEGap: gap, LanguageGap: langGap}
	if langGap != "" {
		res.Findings = append(res.Findings, languageCoverageFinding(imgID, ref, langGap, now))
	}
	res.Base = identifyBase(root, eco)
	if gap != "" {
		res.Findings = append(res.Findings, osCoverageFinding(imgID, ref, eco, gap, detail, now))
	}

	logger := log.FromContext(ctx)
	if len(bins) == 0 {
		logger.Info().Str("digest", digest).Str("os_cve_gap", gap).Str("base_source", res.Base.Source).
			Msg("imagevuln: no packages resolved")
		return res, nil
	}

	affected := map[Package][]Vuln{}
	if s.vulns != nil && len(queries) > 0 {
		affected, err = s.vulns.VulnsFor(ctx, queries)
		if err != nil {
			return Result{}, fmt.Errorf("ScanImage: query vulns for %s: %w", digest, err)
		}
	}

	for _, b := range bins {
		res.Assets = append(res.Assets, packageAsset(b.pkg, b.purl, ref, now))
		res.Edges = append(res.Edges, asset.Edge{
			SrcID: imgID, SrcType: "container_image",
			DstID: b.purl, DstType: "package",
			EdgeType: "runs_package",
		})
		for _, v := range affected[b.query] {
			res.Findings = append(res.Findings, imageVulnFinding(b.pkg, b.purl, v, now))
		}
	}

	logger.Info().
		Str("digest", digest).
		Int("packages", len(bins)).
		Int("findings", len(res.Findings)).
		Str("os_cve_gap", gap).
		Str("base_source", res.Base.Source).
		Str("base_os", res.Base.OS).
		Msg("imagevuln scan complete")
	return res, nil
}

// enabledSources is the advisory feeds the image's packages are matched by:
// OSV inline when this scanner has a querier, the rest as declared.
func (s *Scanner) enabledSources() distro.Sources {
	out := distro.Sources{}
	for src, on := range s.advisory {
		out[src] = on
	}
	out[distro.SourceOSV] = s.vulns != nil
	return out
}

// osCoverageCheckID names the image-level finding that says its OS packages
// cannot support a CVE verdict.
const osCoverageCheckID = "imagevuln-os-packages-unmatchable"

// osCoverageFinding records, on the container_image node, that the image's OS
// packages could not be matched in full (asset.CVEGap* in gap): an rpm database
// that could not be read, an end-of-life release, an unresolvable release.
// Without it such an image shows no OS-package CVEs and reads exactly like a
// patched one. detail is the precise reason the database was not read.
//
// A digest is immutable, but the finding is not permanent: a later scan that
// matches the image in full (a scanner that reads its database, a feed switched
// back on) resolves it — see Result.OSCVEGap.
func osCoverageFinding(imgID, ref, ecosystem, gap, detail string, now time.Time) finding.Finding {
	release := ecosystem
	if release == "" {
		release = "an unidentified release"
	}
	desc := fmt.Sprintf("The image runs %s, and its OS packages cannot be matched against an advisory "+
		"source in full (package_cve_gap=%s). Its absence of OS-package CVE findings is absence of "+
		"matching, not absence of vulnerabilities.", release, gap)
	meta := map[string]string{
		asset.MetaPackageCVEGap:    gap,
		asset.MetaPackageEcosystem: ecosystem,
		"image_ref":                ref,
	}
	if detail != "" {
		desc += "\n\nReason: " + detail
		meta["package_cve_gap_reason"] = detail
	}
	return finding.Finding{
		ID:           dbutil.DeterministicID(osCoverageCheckID, imgID),
		Source:       "supply_chain",
		Type:         "coverage",
		Severity:     finding.SeverityLow,
		Title:        fmt.Sprintf("OS packages of %s are not CVE-matched (%s)", ref, gap),
		Description:  desc,
		Remediation:  osCoverageRemediation[gap],
		ResourceType: "container_image",
		ResourceID:   imgID,
		ResourceName: ref,
		Region:       "global",
		CheckID:      osCoverageCheckID,
		DetectedAt:   now,
		Metadata:     meta,
	}
}

// osCoverageRemediation is what closes each gap for an image.
var osCoverageRemediation = map[string]string{
	asset.CVEGapPackageDBUnread: "The image's OS package database could not be read (see the reason): an rpm " +
		"database that is corrupt, in an unsupported format, larger than the scanner reads or has uncommitted " +
		"writes, or a distribution image that ships no dpkg/apk/rpm database the scanner reads (Ubuntu Chiseled, " +
		"for example). Rebuild the image so its package database is present and closed cleanly, or scan it with " +
		"a tool that reads it.",
	asset.CVEGapScanIncomplete: "The image's layers could not be read in full (see the reason): it exceeds the " +
		"scanner's size caps or a layer is corrupt. Layers are read newest-first, so the OS base layer is the " +
		"one most likely missing. Shrink the image, or repair or re-push the corrupt layer.",
	asset.CVEGapEOLDistro:      "Rebuild the image on a supported release: no advisories are published for this one any more.",
	asset.CVEGapUnknownRelease: "The image carries no readable os-release, so no release-scoped advisory set applies. Rebuild it from a base image that ships /etc/os-release.",
	asset.CVEGapNoSourceNames:  "The image's package database reports no source packages, which this distribution's advisories are keyed by.",
	asset.CVEGapAdvisorySourceDisabled: "The advisory feed for this distribution is switched off (INTEL_OSV_DISABLED, " +
		"INTEL_ALAS_DISABLED, INTEL_ELSA_DISABLED or OFFLINE_MODE); its OS packages are matched against nothing.",
	asset.CVEGapNoAdvisorySource: "No advisory source covers this distribution.",
}

// scanFailedCheckID names the image-level finding that says a running image
// could not be scanned at all.
const scanFailedCheckID = "imagevuln-scan-failed"

// ScanFailedFindingID is the id of an image's scan-failure finding.
func ScanFailedFindingID(digest string) string {
	return dbutil.DeterministicID(scanFailedCheckID, imageAssetID(digest))
}

// ScanFailedFinding records, on the container_image node, that the image could
// not be scanned (reason is the scan error). Without it an unscannable image
// shows no package CVEs and reads exactly like a clean one. A later clean scan
// resolves it.
//
// noManifests (the scan error is ErrNoManifests) is a different fact with the
// same consequence: the image was read in full and carries nothing the scanner
// can inventory, so there is no access to grant and nothing to re-push.
func ScanFailedFinding(digest, ref, reason string, noManifests bool, now time.Time) finding.Finding {
	f := scanFailedFinding(digest, ref, reason, now)
	if noManifests {
		f.Title = fmt.Sprintf("Container image %s has no package inventory the scanner can read", ref)
		f.Description = "The image was pulled and read in full, but it carries no package database or package " +
			"manifest the scanner recognises — a scratch, busybox or pause image, or a static binary that is not " +
			"Go. None of its contents can be matched to CVEs, so its absence of package findings says nothing " +
			"either way.\n\nReason: " + reason
		f.Remediation = "There is no access to grant. If this image needs CVE coverage, build it from a base " +
			"that ships a package database, or ship its binary as a Go build with module information; " +
			"otherwise accept the gap."
		f.Metadata["scan_outcome"] = "no_manifests"
	}
	return f
}

func scanFailedFinding(digest, ref, reason string, now time.Time) finding.Finding {
	imgID := imageAssetID(digest)
	return finding.Finding{
		ID:     ScanFailedFindingID(digest),
		Source: "supply_chain",
		Type:   "coverage",
		// Low, like the OS coverage finding: it is a visibility gap, not a
		// vulnerability, and the packages last seen in the image keep their own
		// findings (the sweep keeps their edges fresh).
		Severity: finding.SeverityLow,
		Title:    fmt.Sprintf("Container image %s could not be scanned", ref),
		Description: "The image could not be pulled or read, so its packages are not inventoried by this scan. " +
			"Its absence of new package CVE findings is absence of scanning, not absence of vulnerabilities; " +
			"the packages found by its last successful scan stay attached to it.\n\nReason: " + reason,
		Remediation: "Fix the cause in the reason: grant the worker pull access to the registry (an AWS " +
			"connector for private ECR, application-default credentials for GCR/Artifact Registry), allow a " +
			"private registry's subnet with IMAGE_REGISTRY_ALLOW_PRIVATE, or re-push a corrupt image.",
		ResourceType: "container_image",
		ResourceID:   imgID,
		ResourceName: ref,
		Region:       "global",
		CheckID:      scanFailedCheckID,
		DetectedAt:   now,
		Metadata:     map[string]string{"image_ref": ref, "scan_error": reason, "scan_outcome": "failed"},
	}
}

// joinNotes joins two "; "-separated notes, either possibly empty.
func joinNotes(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// languageCoverageCheckID names the image-level finding that says some of its
// language packages were not inventoried.
const languageCoverageCheckID = "imagevuln-language-packages-incomplete"

// LanguageCoverageFindingID is the id of an image's language-coverage finding.
func LanguageCoverageFindingID(digest string) string {
	return dbutil.DeterministicID(languageCoverageCheckID, imageAssetID(digest))
}

// languageCoverageFinding records that some of the image's language packages
// (Go modules, npm, PyPI, gems) were not inventoried, and why. It is separate
// from the OS coverage finding: the OS packages may be matched in full while a
// Go binary past the probe budget is not, and neither fact may hide the other.
func languageCoverageFinding(imgID, ref, reason string, now time.Time) finding.Finding {
	return finding.Finding{
		ID:       dbutil.DeterministicID(languageCoverageCheckID, imgID),
		Source:   "supply_chain",
		Type:     "coverage",
		Severity: finding.SeverityLow,
		Title:    fmt.Sprintf("Some language packages of %s are not inventoried", ref),
		Description: "Part of the image's language package inventory could not be read, so those packages " +
			"are not matched against advisories. Their absence of findings is absence of inventory, not " +
			"absence of vulnerabilities.\n\nReason: " + reason,
		Remediation: "Shrink the image (fewer or smaller executables and manifests), or scan it with a tool " +
			"without these limits.",
		ResourceType: "container_image",
		ResourceID:   imgID,
		ResourceName: ref,
		Region:       "global",
		CheckID:      languageCoverageCheckID,
		DetectedAt:   now,
		Metadata:     map[string]string{"image_ref": ref, "language_gap_reason": reason},
	}
}

// binary is one installed package node and the advisory query that covers it.
type binary struct {
	pkg   pkginventory.InstalledPackage
	purl  string
	query Package
}

// advisoryQueries dedups the inventory to one node per purl and maps each to the
// coordinate advisories are looked up by. Debian, Ubuntu and Alpine key their
// advisories by SOURCE package (distro.AdvisoryQuery): libssl3 is asked as
// openssl, and every binary built from one source shares one query, so its
// advisories land on all of them.
//
// Only OSV's packages are queried here. An Amazon Linux or Oracle Linux binary
// keeps its node and edge but no query (a zero query matches nothing): the
// distro advisory refresh matches it from the node, exactly as for a VM.
func advisoryQueries(installed []pkginventory.InstalledPackage) ([]binary, []Package) {
	var (
		bins    []binary
		queries []Package
		seen    = map[string]bool{}
		asked   = map[Package]bool{}
	)
	for _, p := range installed {
		if p.Ecosystem == "" || p.Name == "" || p.Version == "" {
			continue
		}
		purl := purlFor(Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version})
		if seen[purl] {
			continue
		}
		seen[purl] = true
		if !distro.MatchedByOSV(p.Ecosystem) {
			bins = append(bins, binary{pkg: p, purl: purl})
			continue
		}
		name, version := distro.AdvisoryQuery(p.Ecosystem, p.Name, p.Version, p.SourceName, p.SourceVersion)
		q := Package{Ecosystem: p.Ecosystem, Name: name, Version: version}
		if !asked[q] {
			asked[q] = true
			queries = append(queries, q)
		}
		bins = append(bins, binary{pkg: p, purl: purl, query: q})
	}
	return bins, queries
}

// packageAsset shapes a package node identical to the SBOM collector's
// (internal/collect/github/sbom.go): id=purl, metadata carries the OSV
// coordinates the OSV refresh reads — including the source package, which the
// refresh queries source-keyed distributions by. Sharing the shape means an
// image-sourced package and a repo-sourced package with the same purl collapse
// to one node.
func packageAsset(p pkginventory.InstalledPackage, purl, ref string, now time.Time) asset.Asset {
	a := asset.Asset{
		ID:       purl,
		Name:     p.Name,
		Type:     "package",
		Provider: asset.ProviderKubernetes,
		Region:   "global",
		Metadata: map[string]string{
			"ecosystem": p.Ecosystem,
			"package":   p.Name,
			"version":   p.Version,
			"image_ref": ref,
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}
	if p.SourceName != "" {
		a.Metadata[pkginventory.MetaSourcePackage] = p.SourceName
	}
	if p.SourceVersion != "" {
		a.Metadata[pkginventory.MetaSourceVersion] = p.SourceVersion
	}
	return a
}

// imageVulnFinding shapes one advisory hit into a finding IDENTICAL in source /
// resource / check_id to the SBOM feed's supplyChainFinding (internal/jobs/osv.go),
// so it flows through the same enrich + KEV/EPSS + must-fix path and dedups by
// deterministic ID with any SBOM finding on the same purl+CVE.
//
// The check id arrives decided (osv.Hits, via the adapter): a CVE so the KEV
// refresh can match and escalate it, EXCEPT for a MAL-* (OpenSSF
// malicious-packages) advisory, which always keeps its own ID regardless of any
// CVE alias — isMaliciousPackage (internal/app/enrich/sources_supply_chain.go)
// gates on the "MAL-" prefix regardless of which producer emitted the finding.
func imageVulnFinding(p pkginventory.InstalledPackage, purl string, v Vuln, now time.Time) finding.Finding {
	malicious := strings.HasPrefix(v.CheckID, "MAL-")
	checkID := v.CheckID
	remediation := "No fixed version published yet; review the advisory."
	if v.FixedVersion != "" {
		remediation = fmt.Sprintf("Rebuild the image on a base/layer that ships %s %s or later.", p.Name, v.FixedVersion)
	}
	if malicious {
		remediation = fmt.Sprintf(
			"Rebuild without %s immediately — there is no fixed version, the published package is malicious. "+
				"Treat every image and container that ran it as compromised: rotate the credentials and tokens "+
				"reachable from those workloads, then audit for outbound exfiltration.",
			p.Name)
	}
	metadata := map[string]string{
		"ecosystem": p.Ecosystem,
		"package":   p.Name,
		"version":   p.Version,
		"origin":    "container_image",
		"advisory":  v.Advisory,
	}
	if p.SourceName != "" && p.SourceName != p.Name {
		metadata[pkginventory.MetaSourcePackage] = p.SourceName
	}
	if malicious && v.CVE != "" {
		// Preserved even though it lost the CheckID slot above, so KEV
		// (internal/intel/kev) and EPSS (internal/app/enrich/sources_epss.go)
		// can still match this finding by its CVE alias via their
		// Metadata["cve"] fallback — a confirmed-malicious package is not
		// exempt from also being a tracked, possibly actively-exploited CVE.
		metadata["cve"] = v.CVE
	}
	return finding.Finding{
		ID:           dbutil.DeterministicID(checkID, purl),
		Source:       "supply_chain",
		Type:         "vulnerable_dependency",
		Severity:     v.Severity,
		Title:        v.Title,
		Description:  v.Description,
		ResourceType: "package",
		ResourceID:   purl,
		ResourceName: p.Name,
		Region:       "global",
		CheckID:      checkID,
		Remediation:  remediation,
		DetectedAt:   now,
		Metadata:     metadata,
	}
}

// purlFor is the package node id: pkginventory.PURL, the one implementation every
// package producer shares, so a package found in an image, on a VM and in a repo
// SBOM is one node.
func purlFor(p Package) string {
	return pkginventory.PURL(pkginventory.InstalledPackage{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version})
}
