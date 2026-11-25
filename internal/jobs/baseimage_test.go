package jobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
)

type fakeBaseInventory struct {
	images  []asset.Asset
	bases   []asset.ImageBase
	edges   []asset.Edge
	edgeErr error
}

func (f *fakeBaseInventory) ListByType(_ context.Context, typ string, _ int) ([]asset.Asset, error) {
	if typ != "container_image" {
		return nil, nil
	}
	return f.images, nil
}

func (f *fakeBaseInventory) ImageBases(context.Context) ([]asset.ImageBase, error) {
	return f.bases, nil
}

func (f *fakeBaseInventory) EdgesTo(_ context.Context, dstIDs []string) ([]asset.Edge, error) {
	want := map[string]bool{}
	for _, id := range dstIDs {
		want[id] = true
	}
	var out []asset.Edge
	for _, e := range f.edges {
		if want[e.DstID] {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeBaseInventory) EdgesOutBatch(_ context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error) {
	if f.edgeErr != nil {
		return nil, f.edgeErr
	}
	want := map[string]bool{}
	for _, id := range srcIDs {
		want[id] = true
	}
	var out []asset.Edge
	for _, e := range f.edges {
		if want[e.SrcID] && e.EdgeType == edgeType {
			out = append(out, e)
		}
	}
	return out, nil
}

type fakeCoverage struct{ counts map[string]int }

func (f *fakeCoverage) ObserveBaseImageCoverage(c map[string]int) { f.counts = c }

func liveImage(id string) asset.Asset {
	return asset.Asset{ID: id, Name: "registry.example/" + strings.TrimPrefix(id, "image/"), Type: "container_image",
		Provider: asset.ProviderKubernetes, Region: "prod-cluster", LastSeen: time.Now()}
}

func runsImage(workload, img string) asset.Edge {
	return asset.Edge{SrcID: workload, SrcType: "k8s_pod", DstID: img, DstType: "container_image", EdgeType: "runs_image"}
}

func imgPkg(img, purl string) asset.Edge {
	return asset.Edge{SrcID: img, SrcType: "container_image", DstID: purl, DstType: "package", EdgeType: "runs_package"}
}

const (
	debOpenSSL  = "pkg:deb/debian/openssl@1.1.1w-0+deb11u1"
	pyRequests  = "pkg:pypi/requests@2.19.0"
	debLibc     = "pkg:deb/debian/libc6@2.41-12"
	debBash     = "pkg:deb/debian/bash@5.2.37-2"
	osReleaseSr = imagevuln.BaseSourceOSRelease
)

// baseFixture is a small estate: two running Debian 11 images (one behind an
// exposed pod, one owned by a repo), a Debian 13 image that names its base, an
// unidentified image, an unscanned one, an image nothing runs and a stale one.
func baseFixture() (*fakeBaseInventory, *fakeVMVulnFindings) {
	stale := liveImage("image/sha256:stale")
	stale.LastSeen = time.Now().Add(-72 * time.Hour)
	inv := &fakeBaseInventory{
		images: []asset.Asset{
			liveImage("image/sha256:a"), liveImage("image/sha256:b"), liveImage("image/sha256:c"),
			liveImage("image/sha256:unknown"), liveImage("image/sha256:unscanned"), liveImage("image/sha256:idle"), stale,
		},
		bases: []asset.ImageBase{
			{ImageID: "image/sha256:a", BaseImageSource: osReleaseSr, BaseOS: "Debian:11"},
			{ImageID: "image/sha256:b", BaseImageSource: osReleaseSr, BaseOS: "Debian:11"},
			{ImageID: "image/sha256:c", BaseImage: "docker.io/library/debian:trixie-slim", BaseImageSource: imagevuln.BaseSourceAnnotation, BaseOS: "Debian:13"},
			{ImageID: "image/sha256:unknown", BaseImageSource: imagevuln.BaseSourceUnknown},
			{ImageID: "image/sha256:idle", BaseImageSource: osReleaseSr, BaseOS: "Debian:10"},
			{ImageID: "image/sha256:stale", BaseImageSource: osReleaseSr, BaseOS: "Debian:10"},
		},
		edges: []asset.Edge{
			runsImage("pod-a", "image/sha256:a"), runsImage("pod-b", "image/sha256:b"), runsImage("pod-c", "image/sha256:c"),
			runsImage("pod-u", "image/sha256:unknown"), runsImage("pod-n", "image/sha256:unscanned"),
			runsImage("pod-s", "image/sha256:stale"),
			{SrcID: "pod-a", SrcType: "k8s_pod", DstID: "internet", EdgeType: "exposed_to_internet"},
			imgPkg("image/sha256:a", debOpenSSL), imgPkg("image/sha256:a", pyRequests),
			imgPkg("image/sha256:b", debOpenSSL), imgPkg("image/sha256:b", debBash),
			imgPkg("image/sha256:c", debLibc),
			{SrcID: "image/sha256:b", SrcType: "container_image", DstID: "acme/api", DstType: "github_repo",
				EdgeType: "defined_in", Properties: map[string]string{"path": "deploy/values.yaml"}},
		},
	}
	fs := &fakeVMVulnFindings{byResource: map[string][]finding.Finding{
		debOpenSSL: {{ID: "f-openssl", Source: "supply_chain", ResourceType: "package", ResourceID: debOpenSSL,
			CheckID: "CVE-2024-5535", Severity: finding.SeverityHigh, KnownExploited: true,
			Metadata: map[string]string{"ecosystem": "Debian:11"}}},
		pyRequests: {{ID: "f-requests", Source: "supply_chain", ResourceType: "package", ResourceID: pyRequests,
			CheckID: "CVE-2018-18074", Severity: finding.SeverityMedium, Metadata: map[string]string{"ecosystem": "PyPI"}}},
	}}
	return inv, fs
}

func TestBaseImageWorker_GroupsByBaseAndGradesEOL(t *testing.T) {
	inv, fs := baseFixture()
	cov := &fakeCoverage{}
	w := &BaseImageWorker{assets: inv, findings: fs, catalogue: imagevuln.DefaultCatalogue(), metrics: cov}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshBaseImagesArgs]{}))

	eol := map[string]finding.Finding{}
	var groups []finding.Finding
	for _, f := range fs.recorded {
		require.Equal(t, baseImageSource, f.Source, "never cspm: the sync reconcile would close it")
		switch f.CheckID {
		case "container-image-os-end-of-life":
			eol[f.ResourceID] = f
		case baseImageGroupCheckID:
			groups = append(groups, f)
		default:
			t.Fatalf("unexpected check %s", f.CheckID)
		}
	}

	// Debian 11 (LTS ended 2026-08-31) on both running images; never on the
	// idle or stale Debian 10 images (nothing runs them), never on unknowns.
	require.Len(t, eol, 2)
	require.Equal(t, finding.SeverityHigh, eol["image/sha256:a"].Severity, "a workload running it is exposed")
	require.Equal(t, finding.SeverityMedium, eol["image/sha256:b"].Severity)
	require.Equal(t, "Debian:11", eol["image/sha256:b"].Metadata["os_release"])

	// One root-cause finding: the Debian 11 base. The trixie-slim base has no
	// base-layer CVE and is supported, so there is nothing to fix on it.
	require.Len(t, groups, 1)
	g := groups[0]
	require.Equal(t, "os:Debian:11", g.Metadata["base_group"])
	require.Equal(t, "image/sha256:a", g.ResourceID, "sits on the exposed member")
	require.Equal(t, "container_image", g.ResourceType)
	require.Equal(t, "2", g.Metadata["running_images"])
	require.Equal(t, "image/sha256:a,image/sha256:b", g.Metadata["affected_image_ids"])
	require.Equal(t, "2", g.Metadata["workloads"])
	require.Equal(t, "1", g.Metadata["exposed_workloads"])
	require.Equal(t, "1", g.Metadata["base_layer_cves"], "one CVE across two images is one CVE")
	require.Equal(t, "1", g.Metadata["base_layer_kev"])
	require.Equal(t, "1", g.Metadata["app_layer_cves"])
	require.Equal(t, "0", g.Metadata["app_layer_kev"])
	require.Equal(t, "python", g.Metadata["app_runtime"])
	require.Equal(t, "gcr.io/distroless/python3-debian13", g.Metadata["recommended_base"])
	require.Equal(t, "true", g.Metadata["past_end_of_life"])
	require.Equal(t, "acme/api", g.Metadata["owner_repos"])
	require.Equal(t, finding.SeverityHigh, g.Severity, "KEV in the base layer behind an exposed workload")
	require.Contains(t, g.Title, "Base Debian:11: 2 running images, 1 base-layer CVEs (1 KEV), end of life")
	require.Contains(t, g.Remediation, "acme/api — final stage of the image's Dockerfile (the image is declared in deploy/values.yaml):\n-FROM <current Debian:11 base>\n+FROM gcr.io/distroless/python3-debian13")
	require.Contains(t, g.Remediation, "debian:13-slim")
	require.Contains(t, g.Remediation, "does not open the pull request")
	require.Contains(t, g.Description, "Attribution heuristic")

	require.Equal(t, map[string]int{
		obs.BaseIdentityAnnotation: 1, obs.BaseIdentityOSRelease: 2,
		obs.BaseIdentityUnknown: 1, obs.BaseIdentityUnscanned: 1,
	}, cov.counts, "running images only: the idle and stale ones are not counted")
}

// An unreadable edge read fails the run: an image whose exposure or packages
// were not read must not be graded as unexposed or clean.
func TestBaseImageWorker_ReadFailureFailsTheRun(t *testing.T) {
	inv, fs := baseFixture()
	inv.edgeErr = errors.New("clickhouse: timeout")
	w := &BaseImageWorker{assets: inv, findings: fs, catalogue: imagevuln.DefaultCatalogue()}
	require.Error(t, w.Work(context.Background(), &river.Job[RefreshBaseImagesArgs]{}))
	require.Empty(t, fs.recorded)
	require.Empty(t, fs.resolved)
}

func TestBaseImageWorker_Reconcile(t *testing.T) {
	inv, fs := baseFixture()
	inv.images = append(inv.images, liveImage("image/sha256:noinv"))
	inv.bases = append(inv.bases, asset.ImageBase{ImageID: "image/sha256:noinv", BaseImageSource: osReleaseSr, BaseOS: "Alpine:v3.22"})
	inv.edges = append(inv.edges, runsImage("pod-x", "image/sha256:noinv"))
	// Retired images: deleted by a complete sweep (recorded below). old-api's repository (registry.example/sha256, tag dropped)
	// now runs image c on a new base:
	// a rebuild, the remediation the root-cause finding asked for.
	retired := liveImage("image/sha256:retired")
	retired.Name, retired.LastSeen = "registry.example/retired:1", time.Now().Add(-72*time.Hour)
	oldAPI := liveImage("image/sha256:old-api")
	oldAPI.Name, oldAPI.LastSeen = "registry.example/sha256:v1", time.Now().Add(-72*time.Hour)
	// A cluster whose connector went down: everything in its scope lapsed together.
	quiet := liveImage("image/sha256:quiet")
	quiet.Region, quiet.LastSeen = "dark-cluster", time.Now().Add(-72*time.Hour)
	inv.images = append(inv.images, retired, oldAPI, quiet)
	inv.bases = append(inv.bases,
		asset.ImageBase{ImageID: "image/sha256:retired", BaseImageSource: osReleaseSr, BaseOS: "Debian:8"},
		asset.ImageBase{ImageID: "image/sha256:old-api", BaseImageSource: osReleaseSr, BaseOS: "Debian:12"},
		asset.ImageBase{ImageID: "image/sha256:quiet", BaseImageSource: osReleaseSr, BaseOS: "Debian:9"},
	)
	// The sync recorded the retired images deleted by complete sweeps; the
	// quiet cluster's image has no such record.
	goneAt := time.Now().Add(-70 * time.Hour)
	deletions := &fakeDepartures{deleted: map[string]time.Time{"image/sha256:retired": goneAt, "image/sha256:old-api": goneAt}}

	open := func(id, check, resource string, meta map[string]string) finding.Finding {
		return finding.Finding{ID: id, Source: baseImageSource, CheckID: check, ResourceType: "container_image", ResourceID: resource, Metadata: meta}
	}
	const eolCheck = "container-image-os-end-of-life"
	fs.open = []finding.Finding{
		open("eol-gone", eolCheck, "image/sha256:retired", nil),
		open("eol-unscanned", eolCheck, "image/sha256:unscanned", nil),
		open("eol-fixed", eolCheck, "image/sha256:c", nil), // Debian 13: supported
		open("grp-gone", baseImageGroupCheckID, "image/sha256:retired",
			map[string]string{"base_group": "os:Debian:8", "affected_image_ids": "image/sha256:retired"}),
		open("grp-fixed", baseImageGroupCheckID, "image/sha256:c",
			map[string]string{"base_group": "image:debian:trixie-slim", "affected_image_ids": "image/sha256:c"}),
		open("grp-member-unscanned", baseImageGroupCheckID, "image/sha256:c",
			map[string]string{"base_group": "os:Debian:12", "affected_image_ids": "image/sha256:unscanned"}),
		open("grp-no-inventory", baseImageGroupCheckID, "image/sha256:noinv",
			map[string]string{"base_group": "os:Alpine:v3.22", "affected_image_ids": "image/sha256:noinv"}),
		open("eol-quiet", eolCheck, "image/sha256:quiet", nil),
		open("grp-quiet", baseImageGroupCheckID, "image/sha256:quiet",
			map[string]string{"base_group": "os:Debian:9", "affected_image_ids": "image/sha256:quiet"}),
		open("eol-unlisted", eolCheck, "image/sha256:never-listed", nil),
		open("grp-rebuilt", baseImageGroupCheckID, "image/sha256:old-api",
			map[string]string{"base_group": "os:Debian:12", "affected_image_ids": "image/sha256:old-api"}),
	}
	w := &BaseImageWorker{assets: inv, findings: fs, catalogue: imagevuln.DefaultCatalogue(), deletions: deletions}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshBaseImagesArgs]{}))

	require.ElementsMatch(t, []string{"eol-gone", "grp-gone"}, fs.resolved[finding.ReasonResourceGone])
	require.ElementsMatch(t, []string{"eol-fixed", "grp-fixed", "grp-rebuilt"}, fs.resolved[finding.ReasonFixed],
		"an unscanned member, an unknown identity, a member with no package edges, or an image that merely "+
			"stopped being collected withholds resolution; a rebuild on another base is the fix")
}

// A retired base is judged on every image ever listed on it, not the capped
// affected_image_ids: one surviving member past the cap keeps it open.
func TestBaseImageWorker_RetiredGroupUsesFullMembership(t *testing.T) {
	const group = "os:Debian:7"
	build := func(survivor bool) (*fakeBaseInventory, *fakeVMVulnFindings, *fakeDepartures) {
		inv, fs := baseFixture()
		dep := &fakeDepartures{deleted: map[string]time.Time{}}
		var listed []string
		for i := range maxListedImages + 10 {
			id := fmt.Sprintf("image/sha256:old-%02d", i)
			img := liveImage(id)
			img.Name, img.LastSeen = "registry.example/legacy:"+id, time.Now().Add(-72*time.Hour)
			inv.images = append(inv.images, img)
			inv.bases = append(inv.bases, asset.ImageBase{ImageID: id, BaseImageSource: osReleaseSr, BaseOS: "Debian:7"})
			if !survivor || i < maxListedImages+5 {
				dep.deleted[id] = time.Now().Add(-70 * time.Hour)
			}
			if i < maxListedImages {
				listed = append(listed, id)
			}
		}
		fs.open = []finding.Finding{{ID: "grp", Source: baseImageSource, CheckID: baseImageGroupCheckID,
			ResourceType: "container_image", ResourceID: listed[0],
			Metadata: map[string]string{"base_group": group, "affected_image_ids": strings.Join(listed, ",")}}}
		return inv, fs, dep
	}

	inv, fs, dep := build(true)
	w := &BaseImageWorker{assets: inv, findings: fs, catalogue: imagevuln.DefaultCatalogue(), deletions: dep}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshBaseImagesArgs]{}))
	require.Empty(t, fs.resolved, "a member past the listed cap is not proven gone")

	inv, fs, dep = build(false)
	w = &BaseImageWorker{assets: inv, findings: fs, catalogue: imagevuln.DefaultCatalogue(), deletions: dep}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshBaseImagesArgs]{}))
	require.Equal(t, []string{"grp"}, fs.resolved[finding.ReasonResourceGone])
}

// The root-cause finding keeps the member it already sits on while that member
// stays eligible, instead of moving to whichever id sorts first.
func TestBaseImageWorker_RepresentativeIsSticky(t *testing.T) {
	inv, fs := baseFixture()
	var edges []asset.Edge
	for _, e := range inv.edges {
		if e.EdgeType != "exposed_to_internet" {
			edges = append(edges, e)
		}
	}
	inv.edges = edges
	groupID := baseGroupFindingID("os:Debian:11")
	fs.open = []finding.Finding{{ID: groupID, Source: baseImageSource, CheckID: baseImageGroupCheckID,
		ResourceType: "container_image", ResourceID: "image/sha256:b",
		Metadata: map[string]string{"base_group": "os:Debian:11", "affected_image_ids": "image/sha256:a,image/sha256:b"}}}
	w := &BaseImageWorker{assets: inv, findings: fs, catalogue: imagevuln.DefaultCatalogue()}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshBaseImagesArgs]{}))
	var got finding.Finding
	for _, f := range fs.recorded {
		if f.ID == groupID {
			got = f
		}
	}
	require.Equal(t, "image/sha256:b", got.ResourceID)
}

func TestGroupKeyOf(t *testing.T) {
	tests := []struct {
		base asset.ImageBase
		key  string
		ok   bool
	}{
		{asset.ImageBase{BaseImageSource: imagevuln.BaseSourceAnnotation, BaseImage: "docker.io/library/Debian:12@sha256:abc", BaseOS: "Debian:12"}, "image:debian:12", true},
		{asset.ImageBase{BaseImageSource: imagevuln.BaseSourceAnnotation, BaseImage: "gcr.io/distroless/base-debian12"}, "image:gcr.io/distroless/base-debian12", true},
		{asset.ImageBase{BaseImageSource: imagevuln.BaseSourceAnnotation, BaseImage: "library/alpine:3.22"}, "image:alpine:3.22", true},
		{asset.ImageBase{BaseImageSource: osReleaseSr, BaseOS: "Ubuntu:22.04:LTS"}, "os:Ubuntu:22.04:LTS", true},
		{asset.ImageBase{BaseImageSource: imagevuln.BaseSourceUnknown}, "", false},
	}
	for _, tt := range tests {
		key, ok := groupKeyOf(tt.base)
		require.Equal(t, tt.ok, ok, tt.base)
		require.Equal(t, tt.key, key, tt.base)
	}
}

func TestGroupSeverity(t *testing.T) {
	tests := []struct {
		name string
		s    groupStats
		eol  bool
		want finding.Severity
	}{
		{"base KEV behind an exposed workload", groupStats{baseCVEs: 3, baseKEV: 1, exposedWorkloads: 2}, false, finding.SeverityHigh},
		{"end of life behind an exposed workload", groupStats{exposedWorkloads: 1}, true, finding.SeverityHigh},
		{"base KEV, nothing exposed", groupStats{baseCVEs: 1, baseKEV: 1}, false, finding.SeverityMedium},
		{"end of life, nothing exposed", groupStats{}, true, finding.SeverityMedium},
		{"critical base CVEs only", groupStats{baseCVEs: 4, baseCritHigh: 2, exposedWorkloads: 3}, false, finding.SeverityMedium},
		{"low-grade base CVEs", groupStats{baseCVEs: 9, exposedWorkloads: 3}, false, finding.SeverityLow},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, groupSeverity(tt.s, tt.eol), tt.name)
	}
}

func TestIsBaseLayerPackage(t *testing.T) {
	require.True(t, isBaseLayerPackage(debOpenSSL, finding.Finding{Metadata: map[string]string{"ecosystem": "Debian:12"}}))
	require.True(t, isBaseLayerPackage("pkg:rpm/redhat/openssl-libs@3.0.7", finding.Finding{}), "purl type when the ecosystem is absent")
	require.True(t, isBaseLayerPackage("pkg:generic/red hat:9/openssl@1", finding.Finding{Metadata: map[string]string{"ecosystem": "Red Hat:9"}}))
	require.False(t, isBaseLayerPackage(pyRequests, finding.Finding{Metadata: map[string]string{"ecosystem": "PyPI"}}))
	require.False(t, isBaseLayerPackage("pkg:golang/golang.org/x/net@v0.17.0", finding.Finding{Metadata: map[string]string{"ecosystem": "Go"}}))
}
