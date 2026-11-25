package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/intel/osv"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

type fakeOSVQuerier struct {
	affected   map[osv.Package][]osv.Vuln
	incomplete map[osv.Package]bool
	queried    []osv.Package
	err        error
}

func (f *fakeOSVQuerier) Query(_ context.Context, pkgs []osv.Package) (map[osv.Package][]osv.Vuln, map[osv.Package]bool, error) {
	f.queried = append(f.queried, pkgs...)
	return f.affected, f.incomplete, f.err
}

type fakePackageStore struct {
	assets []asset.Asset
	err    error
}

func (f *fakePackageStore) ScanLivePackages(_ context.Context, fn func([]asset.PackageCoord) error) (asset.PackageScan, error) {
	listedAt := time.Now()
	if f.err != nil {
		return asset.PackageScan{}, f.err
	}
	var out []asset.PackageCoord
	for _, a := range f.assets {
		if a.Type == "package" {
			out = append(out, asset.PackageCoord{ID: a.ID, Metadata: a.Metadata, FirstSeen: a.FirstDiscoveredAt})
		}
	}
	if len(out) > 0 {
		if err := fn(out); err != nil {
			return asset.PackageScan{}, err
		}
	}
	live := make(map[string]bool, len(out))
	for _, c := range out {
		live[c.ID] = true
	}
	return asset.PackageScan{ListedAt: listedAt, LiveIDs: live}, nil
}

// hitOf is the single hit of a one-CVE (or CVE-less) advisory.
func hitOf(v osv.Vuln) osv.Hit { return osv.Hits([]osv.Vuln{v})[0] }

func pkgAsset(purl, eco, name, version string) asset.Asset {
	return asset.Asset{
		ID: purl, Name: name, Type: "package", Provider: asset.ProviderGitHub,
		Metadata: map[string]string{"ecosystem": eco, "package": name, "version": version},
	}
}

func TestOSVWorker_RecordsSupplyChainFindings(t *testing.T) {
	lodash := osv.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	store := &fakeFindingStore{}
	w := &OSVWorker{
		querier: &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{
			lodash: {{
				ID:       "GHSA-35jh-r3h4-6jhm",
				Aliases:  []string{"CVE-2021-23337"},
				Summary:  "Command injection in lodash",
				Severity: finding.SeverityHigh,
			}},
		}},
		assets: &fakePackageStore{assets: []asset.Asset{
			pkgAsset("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20"),
			{ID: "org/repo", Type: "github_repo"}, // not a package, never queried
		}},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Len(t, store.recorded, 1)
	got := store.recorded[0]
	require.Equal(t, "supply_chain", got.Source)
	require.Equal(t, "vulnerable_dependency", got.Type)
	require.Equal(t, "CVE-2021-23337", got.CheckID, "CVE alias preferred for KEV matching")
	require.Equal(t, finding.SeverityHigh, got.Severity)
	require.Equal(t, "pkg:npm/lodash@4.17.20", got.ResourceID)
	require.Equal(t, "package", got.ResourceType)
	require.NotEmpty(t, got.ID)
}

func TestOSVWorker_ReconcilesResolvedAdvisories(t *testing.T) {
	// lodash@4.17.20 is re-scanned this run and the OSV query now returns NO
	// advisory (patched/withdrawn). Its previously-open finding on that purl must
	// resolve as fixed; a finding that is not on a package node (an image's
	// coverage finding) is neither re-scanned nor package-gone and is left alone.
	scannedPurl := "pkg:npm/lodash@4.17.20"
	staleID := dbutil.DeterministicID("CVE-2021-23337", scannedPurl)
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: staleID, Source: "supply_chain", ResourceType: "package", ResourceID: scannedPurl, CheckID: "CVE-2021-23337"},
		{ID: "other", Source: "supply_chain", ResourceType: "container_image", ResourceID: "sha256:abc", CheckID: "imagevuln-os-packages-unmatchable"},
	}}
	w := &OSVWorker{
		querier: &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{}}, // no hits → advisory gone
		assets: &fakePackageStore{assets: []asset.Asset{
			pkgAsset(scannedPurl, "npm", "lodash", "4.17.20"),
		}},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Len(t, store.resolved, 1, "the withdrawn advisory on a re-scanned package resolves")
	require.Equal(t, staleID, store.resolved[0].ID)
	require.Equal(t, finding.ReasonFixed, store.reasons[staleID])
}

// A package that left the live inventory (no fresh edge points at it) resolves
// its findings as resource_gone — never fixed, which would claim someone
// remediated it — while a re-scanned package that lost its advisory is fixed.
func TestOSVWorker_PackageLeftInventoryResolvesGoneNotFixed(t *testing.T) {
	livePurl, gonePurl := "pkg:npm/lodash@4.17.20", "pkg:deb/debian/openssl@3.0.11-1"
	fixedID := dbutil.DeterministicID("CVE-2021-23337", livePurl)
	goneID := dbutil.DeterministicID("CVE-2024-5535", gonePurl)
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: fixedID, Source: "supply_chain", ResourceType: "package", ResourceID: livePurl, CheckID: "CVE-2021-23337",
			LastObservedAt: time.Now().Add(-24 * time.Hour)},
		{ID: goneID, Source: "supply_chain", ResourceType: "package", ResourceID: gonePurl, CheckID: "CVE-2024-5535",
			LastObservedAt: time.Now().Add(-72 * time.Hour)},
	}}
	w := &OSVWorker{
		querier:    &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{}},
		assets:     &fakePackageStore{assets: []asset.Asset{pkgAsset(livePurl, "npm", "lodash", "4.17.20")}},
		findings:   store,
		departures: goneEvidence(gonePurl).readers(),
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Equal(t, map[string]finding.ResolutionReason{
		fixedID: finding.ReasonFixed,
		goneID:  finding.ReasonResourceGone,
	}, store.reasons)
}

// The departure reconcile runs even when no package needs a fresh OSV query:
// here the only live package is on an ecosystem OSV does not serve, so the
// refresh takes its nothing-to-scan path.
func TestOSVWorker_PackageLeftInventoryResolvesGoneWithNothingToScan(t *testing.T) {
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: "gone", Source: "supply_chain", ResourceType: "package", ResourceID: "pkg:npm/left@1.0.0", CheckID: "CVE-2024-0001"},
	}}
	q := &fakeOSVQuerier{}
	w := &OSVWorker{
		querier: q,
		assets: &fakePackageStore{assets: []asset.Asset{
			pkgAsset("pkg:rpm/amazon/bash@5.2.15-1.amzn2023", "Amazon Linux:2023", "bash", "5.2.15-1.amzn2023"),
		}},
		findings:   store,
		departures: goneEvidence("pkg:npm/left@1.0.0").readers(),
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Empty(t, q.queried)
	require.Equal(t, map[string]finding.ResolutionReason{"gone": finding.ReasonResourceGone}, store.reasons)
}

// Fail closed: a listing that errors, an empty listing, and a finding its
// producer re-observed after the listing began are all "not known to be gone"
// — none of them resolves anything.
// A producer outage lapses a running host's edges exactly like a removal does.
// Without positive evidence — the host re-read without the package, or its
// scope swept without the host — the package's findings stay open.
func TestOSVWorker_PackageLapsedDuringProducerOutageStaysOpen(t *testing.T) {
	purl := "pkg:rpm/amzn/openssl@1.0.1?arch=x86_64"
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: "f", Source: "supply_chain", ResourceType: "package", ResourceID: purl, CheckID: "CVE-2024-0001",
			LastObservedAt: lapsedAt},
	}}
	w := &OSVWorker{
		querier:  &fakeOSVQuerier{},
		assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset("pkg:npm/other@1.0.0", "npm", "other", "1.0.0")}},
		findings: store,
		departures: (&fakeDepartures{runners: []asset.PackageRunner{unobserved(purl, "i-1")},
			assets: map[string]asset.Asset{"i-1": vm("i-1", "", depNow)}}).readers(),
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Empty(t, store.resolved, "an SSM outage on a running host is not a departure")
}

// An upgrade is the remediation: the host was re-read and runs the same
// package at a new version, so the old purl's findings resolve as fixed.
func TestOSVWorker_PackageUpgradedResolvesFixed(t *testing.T) {
	old, upgraded := "pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.21"
	newer := osv.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}
	for _, tc := range []struct {
		name       string
		incomplete bool
		want       map[string]finding.ResolutionReason
	}{
		{"newer version read in full", false, map[string]finding.ResolutionReason{"f": finding.ReasonFixed}},
		// The newer version's advisory read was incomplete this run: its
		// missing finding is unread, not cured — withheld until it is read.
		{"newer version read incompletely", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeFindingStore{list: []finding.Finding{
				{ID: "f", Source: "supply_chain", ResourceType: "package", ResourceID: old, CheckID: "CVE-2024-0001",
					LastObservedAt: lapsedAt},
			}}
			q := &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{}}
			if tc.incomplete {
				q.incomplete = map[osv.Package]bool{newer: true}
			}
			w := &OSVWorker{
				querier:  q,
				assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset(upgraded, "npm", "lodash", "4.17.21")}},
				findings: store,
				departures: (&fakeDepartures{runners: []asset.PackageRunner{supersededBy(old, "repo")},
					assets: map[string]asset.Asset{"repo": vm("repo", "", depNow)},
					edges:  map[string][]asset.Edge{"repo": {runsPackage("repo", upgraded)}}}).readers(),
			}
			require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
			if tc.want == nil {
				require.Empty(t, store.resolved)
				return
			}
			require.Equal(t, tc.want, store.reasons)
		})
	}
}

func TestOSVWorker_DegradedInventoryResolvesNothing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		assets   *fakePackageStore
		observed time.Time
		wantErr  bool
	}{
		{name: "listing read error", assets: &fakePackageStore{err: errors.New("clickhouse: timeout")}, wantErr: true},
		{name: "empty live inventory", assets: &fakePackageStore{}},
		{name: "observed after the listing began",
			assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset("pkg:npm/a@1.0.0", "npm", "a", "1.0.0")}},
			observed: time.Now().Add(time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeFindingStore{list: []finding.Finding{{ID: "f", Source: "supply_chain", ResourceType: "package",
				ResourceID: "pkg:npm/elsewhere@1.0.0", CheckID: "CVE-2024-0001", LastObservedAt: tc.observed}}}
			w := &OSVWorker{querier: &fakeOSVQuerier{}, assets: tc.assets, findings: store}
			err := w.Work(context.Background(), &river.Job[RefreshOSVArgs]{})
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Empty(t, store.resolved)
		})
	}
}

func TestOSVWorker_ReconcileSkipsIncompletePackages(t *testing.T) {
	// lodash was re-scanned but its advisory hydration was INCOMPLETE this run
	// (transient OSV miss), so `found` is a lower bound — the reconcile must NOT
	// resolve its open finding, or a still-valid vuln would silently disappear.
	pkg := osv.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	scannedPurl := "pkg:npm/lodash@4.17.20"
	staleID := dbutil.DeterministicID("CVE-2021-23337", scannedPurl)
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: staleID, Source: "supply_chain", ResourceID: scannedPurl, CheckID: "CVE-2021-23337"},
	}}
	w := &OSVWorker{
		querier: &fakeOSVQuerier{
			affected:   map[osv.Package][]osv.Vuln{},    // no hits returned...
			incomplete: map[osv.Package]bool{pkg: true}, // ...but hydration was incomplete
		},
		assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset(scannedPurl, "npm", "lodash", "4.17.20")}},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Empty(t, store.resolved, "an incomplete-hydrate package must not have its findings resolved")
}

func TestOSVWorker_DeterministicFindingID(t *testing.T) {
	pkg := osv.Package{Ecosystem: "npm", Name: "a", Version: "1.0.0"}
	vuln := osv.Vuln{ID: "GHSA-x"}
	store := &fakeFindingStore{}
	w := &OSVWorker{
		querier:  &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{pkg: {vuln}}},
		assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset("pkg:npm/a@1.0.0", "npm", "a", "1.0.0")}},
		findings: store,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Len(t, store.recorded, 2)
	require.Equal(t, store.recorded[0].ID, store.recorded[1].ID, "re-refresh upserts the same row")
	require.Equal(t, "GHSA-x", store.recorded[0].CheckID, "advisory id used when no CVE alias")
}

func TestOSVWorker_EmptyInventory_NoQuery(t *testing.T) {
	q := &fakeOSVQuerier{}
	w := &OSVWorker{querier: q, assets: &fakePackageStore{}, findings: &fakeFindingStore{}}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Empty(t, q.queried)
}

func TestOSVWorker_SkipsAssetsWithoutCoordinates(t *testing.T) {
	q := &fakeOSVQuerier{}
	w := &OSVWorker{
		querier: q,
		assets: &fakePackageStore{assets: []asset.Asset{
			{ID: "pkg:weird/x@1", Type: "package", Metadata: map[string]string{"version": "1"}},
		}},
		findings: &fakeFindingStore{},
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Empty(t, q.queried)
}

func TestOSVWorker_QueryError(t *testing.T) {
	w := &OSVWorker{
		querier:  &fakeOSVQuerier{err: errors.New("osv down")},
		assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset("pkg:npm/a@1.0.0", "npm", "a", "1.0.0")}},
		findings: &fakeFindingStore{},
	}
	err := w.Work(context.Background(), &river.Job[RefreshOSVArgs]{})
	require.ErrorContains(t, err, "osv down")
}

func TestSupplyChainFinding_Remediation(t *testing.T) {
	pkg := osv.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	noFix := supplyChainFinding(pkg, "pkg:npm/lodash@4.17.20", pkg.Name, hitOf(osv.Vuln{ID: "GHSA-x"}), time.Now())
	require.Contains(t, noFix.Remediation, "No fixed version")
	require.Equal(t, "GHSA-x in lodash", noFix.Title, "title falls back to check id")
}

// The fixed version of a source-keyed advisory is the SOURCE package's; the
// remediation must not pair a binary's name with it as if it were the
// binary's own version.
func TestUpgradeRemediation(t *testing.T) {
	require.Equal(t, "Upgrade lodash to 4.17.21 or later.", upgradeRemediation("lodash", "lodash", "4.17.21"))
	require.Equal(t, "Upgrade libssl3 to the build from source package openssl 3.0.11-1~deb12u2 or later.",
		upgradeRemediation("libssl3", "openssl", "3.0.11-1~deb12u2"))
}

// A malicious package is not remediated by upgrading: the advisory says the
// published artefact contains hostile code, so there is no fixed version to move
// to and anything that installed it must be treated as compromised. The generic
// "no fixed version published yet; review the advisory" reads as "wait for one",
// which is the opposite of the required action.
func TestSupplyChainFinding_MaliciousPackageRemediationIsContainment(t *testing.T) {
	pkg := osv.Package{Name: "fs", Ecosystem: "npm"}
	f := supplyChainFinding(pkg, "pkg:npm/fs@1.0.0", pkg.Name,
		hitOf(osv.Vuln{ID: "MAL-2025-21003", Summary: "Malicious code in fs (npm)"}), time.Now())

	require.Contains(t, f.Remediation, "Remove fs")
	require.Contains(t, f.Remediation, "rotate")
	require.NotContains(t, f.Remediation, "Upgrade")
	require.NotContains(t, f.Remediation, "No fixed version published yet")
	require.Equal(t, "MAL-2025-21003", f.CheckID,
		"a MAL advisory has no CVE alias, so its own ID is the check id and stays greppable")
}

// TestSupplyChainFinding_MaliciousPackageKeepsOwnIDEvenWithCVEAlias guards the
// MAL-* carve-out: OpenSSF malicious-packages advisories that are ALSO the
// highest-profile, most-publicized campaigns
// routinely carry a CVE alias (e.g. the real nx/s1ngularity compromise,
// MAL-2025-41443, aliases CVE-2025-10894). Preferring the CVE alias as
// CheckID here would silently defeat isMaliciousPackage
// (internal/app/enrich/sources_supply_chain.go), which gates purely on a
// "MAL-" prefix — reinstating the exact must-fix/score-floor demotion that
// predicate exists to prevent, on precisely the incidents that matter most.
func TestSupplyChainFinding_MaliciousPackageKeepsOwnIDEvenWithCVEAlias(t *testing.T) {
	pkg := osv.Package{Name: "nx", Ecosystem: "npm"}
	f := supplyChainFinding(pkg, "pkg:npm/nx@21.5.2", pkg.Name,
		hitOf(osv.Vuln{ID: "MAL-2025-41443", Aliases: []string{"GHSA-cxm3-wv7p-598c", "CVE-2025-10894"}}), time.Now())

	require.Equal(t, "MAL-2025-41443", f.CheckID,
		"a MAL advisory must keep its own ID as CheckID even when it also carries a CVE alias")
	require.Equal(t, "CVE-2025-10894", f.Metadata["cve"],
		"the CVE alias must still be preserved for KEV/EPSS matching (kev.findingCVE's Metadata[\"cve\"] fallback), even though it lost the CheckID slot")
}

// TestSupplyChainFinding_OrdinaryCVEStillPrefersAlias is the other half of that
// guard: an ordinary (non-malicious) advisory
// must still prefer its CVE alias as CheckID, so KEV/EPSS matching by CVE is
// unaffected by the malicious-package carve-out above.
func TestSupplyChainFinding_OrdinaryCVEStillPrefersAlias(t *testing.T) {
	pkg := osv.Package{Name: "lodash", Ecosystem: "npm"}
	f := supplyChainFinding(pkg, "pkg:npm/lodash@4.17.20", pkg.Name,
		hitOf(osv.Vuln{ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"}}), time.Now())

	require.Equal(t, "CVE-2021-23337", f.CheckID, "an ordinary advisory still prefers its CVE alias, unchanged")
}

// Amazon Linux, Oracle Linux and CentOS coordinates are never sent to OSV: one
// such query fails OSV's whole batch, and the distro feeds own the first two.
func TestOSVWorker_SkipsEcosystemsOSVDoesNotServe(t *testing.T) {
	q := &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{}}
	w := &OSVWorker{
		querier: q,
		assets: &fakePackageStore{assets: []asset.Asset{
			pkgAsset("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20"),
			pkgAsset("pkg:rpm/amazon/bash@4.2.46-34.amzn2", "Amazon Linux:2", "bash", "4.2.46-34.amzn2"),
			pkgAsset("pkg:rpm/oracle/bash@4.4.20-4.el8", "Oracle Linux:8", "bash", "4.4.20-4.el8"),
			pkgAsset("pkg:rpm/centos/bash@4.2.46-34.el7", "CentOS:7", "bash", "4.2.46-34.el7"),
			pkgAsset("pkg:rpm/redhat/bash@5.1.8-6.el9", "Red Hat:9", "bash", "5.1.8-6.el9"),
		}},
		findings: &fakeFindingStore{},
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.ElementsMatch(t, []osv.Package{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "Red Hat:9", Name: "bash", Version: "5.1.8-6.el9"},
	}, q.queried)
}

// A source-keyed distribution is queried by source package, and the advisory
// lands on EVERY binary built from it — libopenssl3 is as vulnerable as openssl-3.
func TestOSVWorker_SourceKeyedQueryFansOutToEveryBinary(t *testing.T) {
	src := osv.Package{Ecosystem: "SUSE:15.5", Name: "openssl-3", Version: "3.0.8-150500.5.1"}
	q := &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{
		src: {{ID: "SUSE-SU-2023:2620-1", Upstream: []string{"CVE-2023-2650"}, Severity: finding.SeverityMedium}},
	}}
	bin := func(name string) asset.Asset {
		a := pkgAsset("pkg:rpm/suse/"+name+"@3.0.8-150500.5.1", "SUSE:15.5", name, "3.0.8-150500.5.1")
		a.Metadata[pkginventory.MetaSourcePackage] = "openssl-3"
		return a
	}
	store := &fakeFindingStore{}
	w := &OSVWorker{querier: q, assets: &fakePackageStore{assets: []asset.Asset{bin("libopenssl3"), bin("openssl-3")}}, findings: store}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Equal(t, []osv.Package{src}, q.queried, "one query for the source package")
	require.Len(t, store.recorded, 2)
	var purls []string
	for _, f := range store.recorded {
		require.Equal(t, "CVE-2023-2650", f.CheckID)
		purls = append(purls, f.ResourceID)
	}
	require.ElementsMatch(t, []string{"pkg:rpm/suse/libopenssl3@3.0.8-150500.5.1", "pkg:rpm/suse/openssl-3@3.0.8-150500.5.1"}, purls)
}

// A distro advisory bundling several CVEs is one finding per CVE × binary, so
// KEV and EPSS see the second CVE too. The per-CVE record naming the same CVE
// (DEBIAN-CVE-*) merges into the same finding — one row whatever order OSV
// answers in, at the highest severity, citing both advisories.
func TestOSVWorker_OneFindingPerCVE(t *testing.T) {
	src := osv.Package{Ecosystem: "Debian:12", Name: "glibc", Version: "2.36-9"}
	dsa := osv.Vuln{ID: "DSA-5611-1", Upstream: []string{"CVE-2023-6246", "CVE-2023-6779", "CVE-2023-6780"},
		Summary: "glibc - security update", Severity: finding.SeverityMedium}
	perCVE := osv.Vuln{ID: "DEBIAN-CVE-2023-6246", Upstream: []string{"CVE-2023-6246"}, Severity: finding.SeverityHigh}
	bin := func(name string) asset.Asset {
		a := pkgAsset("pkg:deb/debian/"+name+"@2.36-9", "Debian:12", name, "2.36-9")
		a.Metadata[pkginventory.MetaSourcePackage] = "glibc"
		return a
	}
	for _, order := range [][]osv.Vuln{{dsa, perCVE}, {perCVE, dsa}} {
		store := &fakeFindingStore{}
		w := &OSVWorker{
			querier:  &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{src: order}},
			assets:   &fakePackageStore{assets: []asset.Asset{bin("libc6"), bin("libc-bin")}},
			findings: store,
		}
		require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
		require.Len(t, store.recorded, 6, "3 CVEs × 2 binaries")

		byID := map[string]finding.Finding{}
		for _, f := range store.recorded {
			byID[f.ID] = f
		}
		require.Len(t, byID, 6, "no two findings share an id")
		f := byID[dbutil.DeterministicID("CVE-2023-6779", "pkg:deb/debian/libc6@2.36-9")]
		require.Equal(t, "CVE-2023-6779", f.CheckID, "the second CVE of the bundle is its own finding")
		require.Equal(t, "DSA-5611-1", f.Metadata["advisory"])
		require.Equal(t, "CVE-2023-6779 in glibc (DSA-5611-1)", f.Title, "named for the advisory's package, identically by every producer")
		require.Equal(t, "libc6", f.ResourceName)

		first := byID[dbutil.DeterministicID("CVE-2023-6246", "pkg:deb/debian/libc6@2.36-9")]
		require.Equal(t, finding.SeverityHigh, first.Severity, "highest severity across merged advisories")
		require.Equal(t, "DEBIAN-CVE-2023-6246,DSA-5611-1", first.Metadata["advisory"])
		require.Equal(t, "CVE-2023-6246 in glibc", first.Title, "described by the most specific record")
	}
}

// Debian records are versioned by SOURCE version: a binNMU bash 5.2.15-2+b2 is
// asked as source bash 5.2.15-2, and the image scanner's libssl3 node as openssl.
func TestOSVWorker_DebianQueriesSourceNameAndVersion(t *testing.T) {
	q := &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{}}
	bash := pkgAsset("pkg:deb/debian/bash@5.2.15-2+b2", "Debian:12", "bash", "5.2.15-2+b2")
	bash.Metadata[pkginventory.MetaSourcePackage] = "bash"
	bash.Metadata[pkginventory.MetaSourceVersion] = "5.2.15-2"
	libssl := pkgAsset("pkg:deb/debian/libssl3@3.0.11-1~deb12u2", "Debian:12", "libssl3", "3.0.11-1~deb12u2")
	libssl.Metadata[pkginventory.MetaSourcePackage] = "openssl"
	w := &OSVWorker{querier: q, assets: &fakePackageStore{assets: []asset.Asset{bash, libssl}}, findings: &fakeFindingStore{}}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.ElementsMatch(t, []osv.Package{
		{Ecosystem: "Debian:12", Name: "bash", Version: "5.2.15-2"},
		{Ecosystem: "Debian:12", Name: "openssl", Version: "3.0.11-1~deb12u2"},
	}, q.queried)
}

// A source-keyed node with no source name (dpkg via SSM, GCP OS Config, or an
// image-scanned node last rewritten by one of those) is still asked by binary
// name, which can only under-match: an absent advisory there is not a fix, and
// the reconcile must not resolve the finding the image scanner raised.
func TestOSVWorker_ReconcileSkipsSourceKeyedPackagesWithoutSourceName(t *testing.T) {
	purl := "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10"
	openID := dbutil.DeterministicID("CVE-2023-0464", purl)
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: openID, Source: "supply_chain", ResourceID: purl, CheckID: "CVE-2023-0464"},
	}}
	q := &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{}}
	w := &OSVWorker{
		querier:  q,
		assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset(purl, "Ubuntu:22.04:LTS", "libssl3", "3.0.2-0ubuntu1.10")}},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Equal(t, []osv.Package{{Ecosystem: "Ubuntu:22.04:LTS", Name: "libssl3", Version: "3.0.2-0ubuntu1.10"}}, q.queried,
		"still asked: a binary that shares its source's name does match")
	require.Empty(t, store.resolved, "a binary-name answer for a source-keyed distro is a lower bound")
}
