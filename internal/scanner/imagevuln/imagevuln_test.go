package imagevuln

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// fixtureSource serves a test-fixture rootfs from any fs.FS (an in-memory MapFS
// here), exercising the same ImageSource seam LocalImageSource and the live
// registry puller implement.
type fixtureSource struct{ fsys fs.FS }

func (s fixtureSource) Open(context.Context, string, string) (fs.FS, func(), error) {
	return s.fsys, func() {}, nil
}

// fakeVulns returns canned advisories per package.
type fakeVulns struct {
	byPkg map[Package][]Vuln
	got   []Package
}

func (f *fakeVulns) VulnsFor(_ context.Context, pkgs []Package) (map[Package][]Vuln, error) {
	f.got = pkgs
	out := map[Package][]Vuln{}
	for _, p := range pkgs {
		if v, ok := f.byPkg[p]; ok {
			out[p] = v
		}
	}
	return out, nil
}

// dpkgFixture is a minimal /var/lib/dpkg/status with two packages.
const dpkgFixture = `Package: openssl
Version: 1.1.1n-0+deb11u3
Status: install ok installed

Package: bash
Version: 5.1-2+deb11u1
Status: install ok installed
`

func newFixtureFS() fstest.MapFS {
	return fstest.MapFS{
		// Debian testing/sid: an os-release with no VERSION_ID, so the packages
		// keep the unqualified "Debian" ecosystem as a reading, not a fallback.
		"etc/os-release":      {Data: []byte("ID=debian\n")},
		"var/lib/dpkg/status": {Data: []byte(dpkgFixture)},
		"requirements.txt":    {Data: []byte("requests==2.19.0\n")},
	}
}

func TestScanImage_EmitsFindingsAssetsEdges(t *testing.T) {
	opensslPkg := Package{Ecosystem: "Debian", Name: "openssl", Version: "1.1.1n-0+deb11u3"}
	reqPkg := Package{Ecosystem: "PyPI", Name: "requests", Version: "2.19.0"}
	vulns := &fakeVulns{byPkg: map[Package][]Vuln{
		opensslPkg: {{CheckID: "CVE-2022-0778", Advisory: "OSV-1", Title: "openssl DoS", Severity: finding.SeverityHigh, FixedVersion: "1.1.1o"}},
		reqPkg:     {{CheckID: "CVE-2018-18074", Advisory: "GHSA-x", Title: "requests creds leak", Severity: finding.SeverityMedium}},
	}}

	sc := New(fixtureSource{newFixtureFS()}, vulns)
	res, err := sc.ScanImage(context.Background(), "sha256:abc123", "gcr.io/proj/app:1.2.3")
	require.NoError(t, err)

	// Three distinct packages inventoried (openssl, bash, requests); every one
	// gets a package asset + a runs_package edge from the image node.
	require.Len(t, res.Assets, 3)
	require.Len(t, res.Edges, 3)
	for _, e := range res.Edges {
		require.Equal(t, "runs_package", e.EdgeType)
		require.Equal(t, "image/sha256:abc123", e.SrcID)
		require.Equal(t, "container_image", e.SrcType)
		require.Equal(t, "package", e.DstType)
	}

	// Two of the three packages are vulnerable → two findings.
	require.Len(t, res.Findings, 2)
	byCheck := map[string]finding.Finding{}
	for _, f := range res.Findings {
		byCheck[f.CheckID] = f
	}

	f := byCheck["CVE-2022-0778"]
	require.Equal(t, "supply_chain", f.Source)
	require.Equal(t, "package", f.ResourceType)
	require.Equal(t, "pkg:deb/debian/openssl@1.1.1n-0+deb11u3", f.ResourceID)
	require.Equal(t, finding.SeverityHigh, f.Severity)
	// ID matches the SBOM feed's DeterministicID(checkID, purl) so image + repo
	// findings on the same purl+CVE collapse to one row.
	require.Equal(t, dbutil.DeterministicID("CVE-2022-0778", f.ResourceID), f.ID)
	require.Contains(t, f.Remediation, "1.1.1o")

	// The runs_package edge dst matches the finding resource — the join that lets
	// the must-fix traversal reach the running pod.
	var linked bool
	for _, e := range res.Edges {
		if e.DstID == f.ResourceID {
			linked = true
		}
	}
	require.True(t, linked, "finding resource must be a runs_package edge target")
}

func TestScanImage_NoVulnQuerier_StillEmitsInventory(t *testing.T) {
	sc := New(fixtureSource{newFixtureFS()}, nil)
	res, err := sc.ScanImage(context.Background(), "sha256:def", "img:tag")
	require.NoError(t, err)
	require.Len(t, res.Assets, 3)
	require.Len(t, res.Edges, 3)
	require.Len(t, res.Findings, 1, "no CVE findings — and one saying nothing was matched")
	require.Equal(t, asset.CVEGapAdvisorySourceDisabled, res.Findings[0].Metadata[asset.MetaPackageCVEGap])
	require.Equal(t, "image/sha256:def", res.Findings[0].ResourceID)
}

// An image whose OS packages cannot be matched in full must not read like a
// patched one: an rpm database that cannot be read, a feed that is off and an
// end-of-life release each get a coverage finding on the container_image node.
func TestScanImage_OSPackagesUnmatchableIsAFinding(t *testing.T) {
	alas := distro.Sources{distro.SourceALAS: true}
	tests := []struct {
		name       string
		fsys       fstest.MapFS
		advisory   distro.Sources
		wantGap    string
		wantEco    string
		wantReason string
	}{
		{"rocky image: rpm database in no known format", fstest.MapFS{
			"etc/os-release":           {Data: []byte("ID=\"rocky\"\nVERSION_ID=\"9.3\"\n")},
			"var/lib/rpm/rpmdb.sqlite": {Data: []byte("not a database")},
			"requirements.txt":         {Data: []byte("requests==2.19.0\n")},
		}, nil, asset.CVEGapPackageDBUnread, "Rocky Linux:9", "unsupported database format"},
		{"ubi8 minimal whose database was not retained", fstest.MapFS{
			"usr/lib/os-release":   {Data: []byte("ID=\"rhel\"\nVERSION_ID=\"8.9\"\n")},
			"var/lib/rpm/Packages": {Data: nil},
		}, nil, asset.CVEGapPackageDBUnread, "Red Hat:8", "is empty"},
		{"amazon linux 2 is past its final end of life", fstest.MapFS{
			"etc/os-release":       {Data: []byte("ID=\"amzn\"\nVERSION_ID=\"2\"\n")},
			"var/lib/rpm/Packages": {Data: []byte(rpmFixture(t, "amazonlinux2.Packages.gz"))},
		}, alas, asset.CVEGapEOLDistro, "Amazon Linux:2", ""},
		{"amazon linux 2023 with no feed declared", fstest.MapFS{
			"etc/os-release":           {Data: []byte("ID=\"amzn\"\nVERSION_ID=\"2023\"\n")},
			"var/lib/rpm/rpmdb.sqlite": {Data: []byte(rpmFixture(t, "amazonlinux2023.rpmdb.sqlite.gz"))},
		}, nil, asset.CVEGapAdvisorySourceDisabled, "Amazon Linux:2023", ""},
		{"debian 10 is past its final end of life", fstest.MapFS{
			"usr/lib/os-release":  {Data: []byte("ID=debian\nVERSION_ID=\"10\"\n")},
			"var/lib/dpkg/status": {Data: []byte("Package: openssl\nVersion: 1.1.1n-0+deb10u6\n")},
		}, nil, asset.CVEGapEOLDistro, "Debian:10", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := New(fixtureSource{tt.fsys}, &fakeVulns{}).WithAdvisorySources(tt.advisory).
				ScanImage(context.Background(), "sha256:os", "img:1")
			require.NoError(t, err)
			require.Len(t, res.Findings, 1)
			f := res.Findings[0]
			require.Equal(t, "coverage", f.Type)
			require.Equal(t, "container_image", f.ResourceType)
			require.Equal(t, "image/sha256:os", f.ResourceID, "on the image node the k8s collector minted")
			require.Equal(t, OSCoverageFindingID("sha256:os"), f.ID)
			require.Equal(t, tt.wantGap, f.Metadata[asset.MetaPackageCVEGap])
			require.Equal(t, tt.wantGap, res.OSCVEGap)
			require.Equal(t, tt.wantEco, f.Metadata[asset.MetaPackageEcosystem])
			require.Contains(t, f.Metadata["package_cve_gap_reason"], tt.wantReason)
			require.Contains(t, f.Description, tt.wantReason)
			require.NotEmpty(t, f.Remediation)
		})
	}

	clean, err := New(fixtureSource{fstest.MapFS{
		"usr/lib/os-release":  {Data: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
		"var/lib/dpkg/status": {Data: []byte("Package: openssl\nVersion: 3.0.11-1~deb12u2\n")},
	}}, &fakeVulns{}).ScanImage(context.Background(), "sha256:ok", "img:2")
	require.NoError(t, err)
	require.Empty(t, clean.Findings, "a matchable image gets no coverage finding")
	require.Empty(t, clean.OSCVEGap)
}

// A UBI image is inventoried from its rpm database and matched against OSV by
// binary name (Red Hat publishes per binary), with the same purl, ecosystem and
// source_package an SSM-inventoried RHEL VM's packages carry.
func TestScanImage_RPMImageMatchedByOSV(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/os-release":           {Data: []byte("ID=\"rhel\"\nVERSION_ID=\"9.8\"\n")},
		"var/lib/rpm/rpmdb.sqlite": {Data: []byte(rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz"))},
	}
	ssl := Package{Ecosystem: "Red Hat:9", Name: "openssl-libs", Version: "1:3.5.8-1.el9_8"}
	vulns := &fakeVulns{byPkg: map[Package][]Vuln{
		ssl: {{CheckID: "CVE-2026-0001", Advisory: "RHSA-2026:0001", Severity: finding.SeverityHigh}},
	}}
	res, err := New(fixtureSource{fsys}, vulns).ScanImage(context.Background(), "sha256:ubi", "ubi9-minimal")
	require.NoError(t, err)
	require.Empty(t, res.OSCVEGap)
	require.Len(t, vulns.got, 4)
	require.Contains(t, vulns.got, ssl)

	require.Len(t, res.Findings, 1)
	require.Equal(t, "pkg:rpm/redhat/openssl-libs@1:3.5.8-1.el9_8", res.Findings[0].ResourceID)
	for _, a := range res.Assets {
		if a.Name == "openssl-libs" {
			require.Equal(t, "openssl", a.Metadata[pkginventory.MetaSourcePackage])
		}
	}
}

// Amazon Linux packages are not OSV's: they become nodes and edges for the
// ALAS refresh to match, exactly like an SSM-inventoried Amazon Linux VM, and
// OSV is never asked about them (it would fail the whole lookup).
func TestScanImage_AmazonLinuxRoutedToALAS(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/os-release":           {Data: []byte("ID=\"amzn\"\nVERSION_ID=\"2023\"\n")},
		"var/lib/rpm/rpmdb.sqlite": {Data: []byte(rpmFixture(t, "amazonlinux2023.rpmdb.sqlite.gz"))},
		"requirements.txt":         {Data: []byte("requests==2.19.0\n")},
	}
	vulns := &fakeVulns{}
	res, err := New(fixtureSource{fsys}, vulns).
		WithAdvisorySources(distro.Sources{distro.SourceALAS: true}).
		ScanImage(context.Background(), "sha256:al", "amazonlinux:2023")
	require.NoError(t, err)
	require.Empty(t, res.OSCVEGap, "ALAS is on and 2023 is supported: the image is matchable")
	require.Equal(t, []Package{{Ecosystem: "PyPI", Name: "requests", Version: "2.19.0"}}, vulns.got)

	ids := map[string]bool{}
	for _, a := range res.Assets {
		ids[a.ID] = true
		if a.Name == "openssl-libs" {
			require.Equal(t, "Amazon Linux:2023", a.Metadata["ecosystem"])
			require.Equal(t, "1:3.5.8-1.amzn2023.0.1", a.Metadata["version"])
		}
	}
	require.True(t, ids["pkg:rpm/amazon/openssl-libs@1:3.5.8-1.amzn2023.0.1"],
		"the node id an SSM-inventoried Amazon Linux VM mints for the same package")
	require.Len(t, res.Edges, 5, "four rpm packages and one PyPI package, each linked to the image")
}

func TestScanImage_DedupsPackages(t *testing.T) {
	fsys := fstest.MapFS{
		"var/lib/dpkg/status": {Data: []byte(dpkgFixture + "\n" + dpkgFixture)}, // same pkgs twice
	}
	sc := New(fixtureSource{fsys}, &fakeVulns{})
	res, err := sc.ScanImage(context.Background(), "sha256:dup", "img")
	require.NoError(t, err)
	require.Len(t, res.Assets, 2, "duplicate package entries collapse to one asset each")
}

func TestScanImage_EmptyDigest(t *testing.T) {
	sc := New(fixtureSource{newFixtureFS()}, nil)
	_, err := sc.ScanImage(context.Background(), "", "img")
	require.Error(t, err)
}

// TestImageVulnFinding_MaliciousPackageKeepsOwnIDEvenWithCVEAlias is the
// direct regression test for a bug found in the SBOM-feed sibling of
// this function (supplyChainFinding, internal/jobs/osv.go): a MAL-*
// (OpenSSF malicious-packages) advisory that also carries a CVE alias must
// keep its own ID as CheckID, not the CVE — isMaliciousPackage
// (internal/app/enrich/sources_supply_chain.go) gates purely on a "MAL-"
// CheckID prefix, so preferring the CVE alias here would silently defeat
// that check for any malicious package found IN A CONTAINER IMAGE, exactly
// as it did for the SBOM feed before that fix. The CVE alias must still be
// preserved in Metadata["cve"] so KEV/EPSS matching by CVE isn't lost.
func TestImageVulnFinding_MaliciousPackageKeepsOwnIDEvenWithCVEAlias(t *testing.T) {
	p := pkginventory.InstalledPackage{Name: "nx", Ecosystem: "npm", Version: "21.5.2"}
	f := imageVulnFinding(p, "pkg:npm/nx@21.5.2", Vuln{CheckID: "MAL-2025-41443", CVE: "CVE-2025-10894"}, time.Now())

	require.Equal(t, "MAL-2025-41443", f.CheckID,
		"a MAL advisory found in an image must keep its own ID as CheckID even when it also carries a CVE alias")
	require.Equal(t, "CVE-2025-10894", f.Metadata["cve"],
		"the CVE alias must still be preserved for KEV/EPSS matching, even though it lost the CheckID slot")
	require.Contains(t, f.Remediation, "Rebuild without nx")
	require.Contains(t, f.Remediation, "rotate")
}

// TestImageVulnFinding_OrdinaryCVEStillPrefersAlias is the regression guard
// for the untouched half of the fix: an ordinary (non-malicious) advisory
// found in an image must still prefer its CVE alias as CheckID, unchanged.
func TestImageVulnFinding_OrdinaryCVEStillPrefersAlias(t *testing.T) {
	p := pkginventory.InstalledPackage{Name: "openssl", Ecosystem: "Debian", Version: "1.1.1"}
	f := imageVulnFinding(p, "pkg:deb/debian/openssl@1.1.1", Vuln{CheckID: "CVE-2022-9999", Advisory: "DEBIAN-CVE-2022-9999"}, time.Now())

	require.Equal(t, "CVE-2022-9999", f.CheckID, "an ordinary advisory still prefers its CVE alias, unchanged")
	require.NotContains(t, f.Metadata, "cve", "the cve metadata fallback is only needed for the malicious carve-out")
}

func TestPurlFor(t *testing.T) {
	cases := map[Package]string{
		{Ecosystem: "Debian", Name: "OpenSSL", Version: "1.0"}: "pkg:deb/debian/openssl@1.0",
		{Ecosystem: "Alpine", Name: "musl", Version: "1.2"}:    "pkg:apk/alpine/musl@1.2",
		{Ecosystem: "npm", Name: "lodash", Version: "4.0"}:     "pkg:npm/lodash@4.0",
		{Ecosystem: "PyPI", Name: "Flask", Version: "2.0"}:     "pkg:pypi/flask@2.0",
		{Ecosystem: "Weird", Name: "x", Version: "1"}:          "pkg:generic/weird/x@1",
		// OSV's release qualifier must NOT leak into the purl: the purl is the
		// package asset's node id, and re-keying it per release would fork the
		// graph and orphan every package asset already in ClickHouse.
		{Ecosystem: "Debian:12", Name: "OpenSSL", Version: "1.0"}:  "pkg:deb/debian/openssl@1.0",
		{Ecosystem: "Ubuntu:22.04", Name: "openssl", Version: "3"}: "pkg:deb/ubuntu/openssl@3",
		{Ecosystem: "Alpine:v3.19", Name: "musl", Version: "1.2"}:  "pkg:apk/alpine/musl@1.2",
		// rpm families share the SSM inventory's node ids.
		{Ecosystem: "Red Hat:9", Name: "openssl-libs", Version: "1:3.0.7-24.el9"}: "pkg:rpm/redhat/openssl-libs@1:3.0.7-24.el9",
	}
	for p, want := range cases {
		require.Equal(t, want, purlFor(p))
	}
}

// Debian, Ubuntu and Alpine advisories are keyed by SOURCE package: libssl3 in
// "Debian:12" matches 0 OSV advisories, openssl 54. The image is asked once per
// source, at the source version, and each advisory lands on every binary built
// from it.
func TestScanImage_QueriesBySourcePackage(t *testing.T) {
	status := "Package: libssl3\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n\n" +
		"Package: openssl\nVersion: 3.0.11-1~deb12u2\n\n" +
		"Package: bash\nSource: bash (5.2.15-2)\nVersion: 5.2.15-2+b2\n"
	fsys := fstest.MapFS{
		"usr/lib/os-release":  {Data: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
		"var/lib/dpkg/status": {Data: []byte(status)},
	}
	openssl := Package{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1~deb12u2"}
	bash := Package{Ecosystem: "Debian:12", Name: "bash", Version: "5.2.15-2"}
	vulns := &fakeVulns{byPkg: map[Package][]Vuln{
		openssl: {{CheckID: "CVE-2023-5678", Advisory: "DEBIAN-CVE-2023-5678", Severity: finding.SeverityMedium, FixedVersion: "3.0.13-1~deb12u1"}},
	}}

	res, err := New(fixtureSource{fsys}, vulns).ScanImage(context.Background(), "sha256:src", "debian:12")
	require.NoError(t, err)
	require.ElementsMatch(t, []Package{openssl, bash}, vulns.got,
		"one query per source package, at the source version — never libssl3, never the binNMU version")

	var purls []string
	for _, f := range res.Findings {
		require.Equal(t, "CVE-2023-5678", f.CheckID)
		purls = append(purls, f.ResourceID)
	}
	require.ElementsMatch(t, []string{
		"pkg:deb/debian/libssl3@3.0.11-1~deb12u2",
		"pkg:deb/debian/openssl@3.0.11-1~deb12u2",
	}, purls, "the advisory lands on every binary of the source, keyed by the binary's own purl")

	meta := map[string]map[string]string{}
	for _, a := range res.Assets {
		meta[a.Name] = a.Metadata
	}
	require.Equal(t, "openssl", meta["libssl3"][pkginventory.MetaSourcePackage],
		"the node carries its source, so the daily OSV refresh asks by it too")
	require.Equal(t, "5.2.15-2", meta["bash"][pkginventory.MetaSourceVersion])
	require.NotContains(t, meta["libssl3"], pkginventory.MetaSourceVersion)
}

// An extracted image is untrusted content: its absolute /etc/os-release
// symlink must not resolve against the worker's own filesystem, which would
// stamp the image with the worker's distribution.
func TestLocalImageSource_DoesNotFollowSymlinksOutOfTheRoot(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o600))
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	require.NoError(t, os.Symlink(filepath.Join(outside, "os-release"), filepath.Join(root, "etc", "os-release")))

	fsys, cleanup, err := LocalImageSource{Root: root}.Open(context.Background(), "", "")
	require.NoError(t, err)
	defer cleanup()
	_, err = fsys.Open("etc/os-release")
	require.Error(t, err)
}
