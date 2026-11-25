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
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/intel/updateinfo"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

type fakeDistroFetcher struct {
	advs    map[string][]updateinfo.Advisory // ecosystem → advisories
	errs    map[string]error
	fetched []string
}

func (f *fakeDistroFetcher) Fetch(_ context.Context, src updateinfo.Source) ([]updateinfo.Advisory, error) {
	f.fetched = append(f.fetched, src.Ecosystem)
	if err := f.errs[src.Ecosystem]; err != nil {
		return nil, err
	}
	return f.advs[src.Ecosystem], nil
}

var (
	al2023Src = updateinfo.Source{Feed: distro.SourceALAS, Ecosystem: "Amazon Linux:2023",
		URLPrefix: "https://alas.aws.amazon.com/AL2023/", URLSuffix: ".html"}
	ol9Src = updateinfo.Source{Feed: distro.SourceELSA, Ecosystem: "Oracle Linux:9",
		URLPrefix: "https://linux.oracle.com/errata/", URLSuffix: ".html"}
	al2Src = updateinfo.Source{Feed: distro.SourceALAS, Ecosystem: "Amazon Linux:2"}

	opensslALAS = updateinfo.Advisory{
		ID: "ALAS2023-2026-2136", Title: "Amazon Linux 2023 - ALAS2023-2026-2136: Important priority package update for openssl",
		Severity: finding.SeverityHigh, CVEs: []string{"CVE-2026-14457", "CVE-2026-54874"},
		Fixed: map[string]string{"openssl-libs": "1:3.5.8-1.amzn2023.0.1", "openssl": "1:3.5.8-1.amzn2023.0.1"},
	}
)

func TestMatchDistroAdvisories(t *testing.T) {
	now := time.Now()
	older := distroPkg{purl: "pkg:rpm/amazon/openssl-libs@1:3.5.5-1.amzn2023.0.3", name: "openssl-libs", version: "1:3.5.5-1.amzn2023.0.3"}
	patched := distroPkg{purl: "pkg:rpm/amazon/openssl-libs@1:3.5.8-1.amzn2023.0.1", name: "openssl-libs", version: "1:3.5.8-1.amzn2023.0.1"}
	newer := distroPkg{purl: "pkg:rpm/amazon/openssl-libs@1:3.5.9-1.amzn2023.0.1", name: "openssl-libs", version: "1:3.5.9-1.amzn2023.0.1"}
	// Epoch 0 installed vs epoch 1 fixed: older, whatever the version digits say.
	noEpoch := distroPkg{purl: "pkg:rpm/amazon/openssl@3.9.0-1.amzn2023", name: "openssl", version: "3.9.0-1.amzn2023"}
	unrelated := distroPkg{purl: "pkg:rpm/amazon/bash@5.2.15-1.amzn2023", name: "bash", version: "5.2.15-1.amzn2023"}

	got := matchDistroAdvisories(al2023Src, []distroPkg{older, patched, newer, noEpoch, unrelated}, []updateinfo.Advisory{opensslALAS}, now)
	require.Len(t, got, 4, "two CVEs × the two installs below the fix")

	byID := map[string]finding.Finding{}
	for _, f := range got {
		byID[f.ID] = f
	}
	f, ok := byID[dbutil.DeterministicID("CVE-2026-54874", older.purl)]
	require.True(t, ok, "one finding per CVE, so KEV/EPSS see the second CVE too")
	require.Equal(t, "supply_chain", f.Source, "the OSV finding shape, so vm_vuln regroups it unchanged")
	require.Equal(t, "vulnerable_dependency", f.Type)
	require.Equal(t, "package", f.ResourceType)
	require.Equal(t, older.purl, f.ResourceID)
	require.Equal(t, "CVE-2026-54874", f.CheckID)
	require.Equal(t, finding.SeverityHigh, f.Severity)
	require.Equal(t, "ALAS2023-2026-2136", f.Metadata["advisory"])
	require.Equal(t, distro.SourceALAS, f.Metadata["advisory_source"])
	require.Equal(t, "https://alas.aws.amazon.com/AL2023/ALAS2023-2026-2136.html", f.Metadata["advisory_url"])
	require.Equal(t, "CVE-2026-54874", f.Metadata["cve"])
	require.Contains(t, f.Remediation, "1:3.5.8-1.amzn2023.0.1")
	_, ok = byID[dbutil.DeterministicID("CVE-2026-14457", noEpoch.purl)]
	require.True(t, ok, "a missing epoch is 0, older than the fix's epoch 1")
}

// Kernel lines share package names: a UEKR7 (5.15) fix must not flag a host on
// UEKR6 (5.4) — its version sorts below the fix, but it is not on that line.
func TestMatchDistroAdvisories_KernelStreamIsScoped(t *testing.T) {
	ol8 := updateinfo.Source{Feed: distro.SourceELSA, Ecosystem: "Oracle Linux:8", URLPrefix: "https://linux.oracle.com/errata/", URLSuffix: ".html"}
	uek7 := updateinfo.Advisory{ID: "ELSA-2026-1", CVEs: []string{"CVE-2026-0001"}, Stream: "5.15",
		Fixed: map[string]string{"kernel-uek": "5.15.0-300.el8uek"}}
	onLine := distroPkg{purl: "pkg:rpm/oracle/kernel-uek@5.15.0-200.el8uek", name: "kernel-uek", version: "5.15.0-200.el8uek"}
	otherLine := distroPkg{purl: "pkg:rpm/oracle/kernel-uek@5.4.17-2136.el8uek", name: "kernel-uek", version: "5.4.17-2136.el8uek"}

	got := matchDistroAdvisories(ol8, []distroPkg{onLine, otherLine}, []updateinfo.Advisory{uek7}, time.Now())
	require.Len(t, got, 1)
	require.Equal(t, onLine.purl, got[0].ResourceID)
}

func TestMatchDistroAdvisories_SameCVETwiceKeepsNewestFixAndWorstSeverity(t *testing.T) {
	pkg := distroPkg{purl: "pkg:rpm/oracle/kernel@5.14.0-1.el9", name: "kernel", version: "5.14.0-1.el9"}
	advs := []updateinfo.Advisory{
		{ID: "ELSA-1", Severity: finding.SeverityMedium, CVEs: []string{"CVE-1"}, Fixed: map[string]string{"kernel": "5.14.0-2.el9"}},
		{ID: "ELSA-2", Severity: finding.SeverityCritical, CVEs: []string{"CVE-1"}, Fixed: map[string]string{"kernel": "5.14.0-9.el9"}},
		{ID: "ELSA-3", Severity: finding.SeverityLow, Fixed: map[string]string{"kernel": "5.14.0-3.el9"}},
	}
	got := matchDistroAdvisories(ol9Src, []distroPkg{pkg}, advs, time.Now())
	require.Len(t, got, 2)
	for _, f := range got {
		switch f.CheckID {
		case "CVE-1":
			require.Equal(t, "ELSA-2", f.Metadata["advisory"])
			require.Equal(t, finding.SeverityCritical, f.Severity)
		case "ELSA-3":
			require.Empty(t, f.Metadata["cve"], "an advisory with no CVE keys on its own id")
		default:
			t.Fatalf("unexpected check %s", f.CheckID)
		}
	}
}

func distroWorker(fetcher DistroAdvisoryFetcher, store *fakeFindingStore, pkgs ...asset.Asset) *DistroAdvisoryWorker {
	return &DistroAdvisoryWorker{
		fetcher:  fetcher,
		sources:  []updateinfo.Source{al2Src, al2023Src, ol9Src},
		assets:   &fakePackageStore{assets: pkgs},
		findings: store,
	}
}

func TestDistroAdvisoryWorker_RecordsAndOnlyFetchesInstalledReleases(t *testing.T) {
	fetcher := &fakeDistroFetcher{advs: map[string][]updateinfo.Advisory{"Amazon Linux:2023": {opensslALAS}}}
	store := &fakeFindingStore{}
	w := distroWorker(fetcher, store,
		pkgAsset("pkg:rpm/amazon/openssl-libs@1:3.5.5-1.amzn2023.0.3", "Amazon Linux:2023", "openssl-libs", "1:3.5.5-1.amzn2023.0.3"),
		pkgAsset("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20"),
	)
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshDistroAdvisoriesArgs]{}))
	require.Equal(t, []string{"Amazon Linux:2023"}, fetcher.fetched, "no host runs AL2 or OL9: nothing downloaded for them")
	require.Len(t, store.recorded, 2)
}

// A patched host's finding resolves — but only on a release whose feed was read
// in full this run. A feed outage must never read as "patched".
func TestDistroAdvisoryWorker_ReconcileSkipsFailedReleases(t *testing.T) {
	alPurl := "pkg:rpm/amazon/openssl-libs@1:3.5.8-1.amzn2023.0.1" // now patched
	olPurl := "pkg:rpm/oracle/openssl-libs@1:3.0.7-24.el9"
	alStale := finding.Finding{ID: dbutil.DeterministicID("CVE-2026-54874", alPurl), Source: "supply_chain", ResourceID: alPurl,
		CheckID: "CVE-2026-54874", Metadata: map[string]string{"advisory_source": distro.SourceALAS}}
	olOpen := finding.Finding{ID: dbutil.DeterministicID("CVE-2024-5535", olPurl), Source: "supply_chain", ResourceID: olPurl,
		CheckID: "CVE-2024-5535", Metadata: map[string]string{"advisory_source": distro.SourceELSA}}
	osvOwned := finding.Finding{ID: "osv", Source: "supply_chain", ResourceID: alPurl, CheckID: "CVE-0000-0001"}
	store := &fakeFindingStore{list: []finding.Finding{alStale, olOpen, osvOwned}}
	fetcher := &fakeDistroFetcher{
		advs: map[string][]updateinfo.Advisory{"Amazon Linux:2023": {opensslALAS}},
		errs: map[string]error{"Oracle Linux:9": errors.New("yum.oracle.com unreachable")},
	}
	w := distroWorker(fetcher, store,
		pkgAsset(alPurl, "Amazon Linux:2023", "openssl-libs", "1:3.5.8-1.amzn2023.0.1"),
		pkgAsset(olPurl, "Oracle Linux:9", "openssl-libs", "1:3.0.7-24.el9"),
	)
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshDistroAdvisoriesArgs]{}), "one release failing is logged, not fatal")
	require.Empty(t, store.recorded)
	require.Len(t, store.resolved, 1)
	require.Equal(t, alStale.ID, store.resolved[0].ID, "the OL9 finding stays open (feed unread); the OSV-owned one is not this feed's")
}

// A package that left the live inventory resolves this feed's findings on it as
// resource_gone, not fixed — whether or not its release's feed was read — and
// leaves other sources' findings to the OSV refresh. A listing error resolves
// nothing.
func TestDistroAdvisoryWorker_PackageLeftInventoryResolvesGone(t *testing.T) {
	livePurl := "pkg:rpm/amazon/bash@5.2.15-1.amzn2023"
	gonePurl := "pkg:rpm/oracle/openssl-libs@1:3.0.7-24.el9"
	gone := finding.Finding{ID: "gone", Source: "supply_chain", ResourceType: "package", ResourceID: gonePurl,
		CheckID: "CVE-2024-5535", Metadata: map[string]string{"advisory_source": distro.SourceELSA}}
	osvOwned := finding.Finding{ID: "osv", Source: "supply_chain", ResourceType: "package", ResourceID: gonePurl, CheckID: "CVE-0000-0001"}
	fetcher := &fakeDistroFetcher{errs: map[string]error{"Oracle Linux:9": errors.New("unreachable")}}

	store := &fakeFindingStore{list: []finding.Finding{gone, osvOwned}}
	w := distroWorker(fetcher, store, pkgAsset(livePurl, "Amazon Linux:2023", "bash", "5.2.15-1.amzn2023"))
	w.departures = goneEvidence(gonePurl).readers()
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshDistroAdvisoriesArgs]{}))
	require.Equal(t, map[string]finding.ResolutionReason{"gone": finding.ReasonResourceGone}, store.reasons)

	store = &fakeFindingStore{list: []finding.Finding{gone}}
	w = distroWorker(fetcher, store)
	w.assets = &fakePackageStore{err: errors.New("clickhouse: timeout")}
	require.Error(t, w.Work(context.Background(), &river.Job[RefreshDistroAdvisoriesArgs]{}))
	require.Empty(t, store.resolved)
}

func TestDistroAdvisoryWorker_EveryFeedFailingIsAnError(t *testing.T) {
	fetcher := &fakeDistroFetcher{errs: map[string]error{"Amazon Linux:2023": errors.New("down")}}
	store := &fakeFindingStore{}
	w := distroWorker(fetcher, store,
		pkgAsset("pkg:rpm/amazon/bash@5.2.15-1.amzn2023", "Amazon Linux:2023", "bash", "5.2.15-1.amzn2023"))
	require.Error(t, w.Work(context.Background(), &river.Job[RefreshDistroAdvisoriesArgs]{}), "retry rather than complete as if checked")
	require.Empty(t, store.resolved)
}
