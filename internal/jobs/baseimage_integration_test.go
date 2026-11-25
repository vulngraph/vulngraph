//go:build integration

package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
)

// The base-image job end to end against ClickHouse: the identity table, the
// freshness-gated edge reads and the package-finding lookup feed one
// end-of-life finding per running image and one root-cause finding per base.
func TestBaseImageWorker_ClickHouse(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, chDSN, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	assets := asset.NewService(asset.NewCHRepo(ch))
	findings := finding.NewService(finding.NewCHRepo(ch))

	p := "it-baseimg-" + time.Now().Format("150405.000000")
	imgA, imgB := "image/sha256:"+p+"-a", "image/sha256:"+p+"-b"
	podA, podB := p+"/pod-a", p+"/pod-b"
	purl := "pkg:deb/debian/" + p + "-openssl@1.1.1w-0+deb11u1"
	t.Cleanup(func() {
		bg := context.Background()
		_ = ch.Exec(bg, "ALTER TABLE assets DELETE WHERE id IN (?, ?)", imgA, imgB)
		_ = ch.Exec(bg, "ALTER TABLE graph_edges DELETE WHERE src_id LIKE ? OR dst_id LIKE ?", p+"%", "%"+p+"%")
		_ = ch.Exec(bg, "ALTER TABLE image_bases DELETE WHERE image_id IN (?, ?)", imgA, imgB)
		_ = ch.Exec(bg, "ALTER TABLE findings DELETE WHERE resource_id IN (?, ?, ?)", imgA, imgB, purl)
	})

	now := time.Now().Truncate(time.Second)
	img := func(id string) asset.Asset {
		return asset.Asset{ID: id, Name: "registry.example/" + p, Type: "container_image", Provider: asset.ProviderKubernetes,
			Region: "it-cluster", Metadata: map[string]string{"image_id": id[len("image/"):]}, DiscoveredAt: now, LastSeen: now}
	}
	require.NoError(t, assets.Ingest(ctx, []asset.Asset{img(imgA), img(imgB)}, []asset.Edge{
		runsImage(podA, imgA), runsImage(podB, imgB),
		{SrcID: podA, SrcType: "k8s_pod", DstID: "internet", DstType: "internet", EdgeType: "exposed_to_internet"},
		imgPkg(imgA, purl), imgPkg(imgB, purl),
	}))
	require.NoError(t, assets.RecordImageBases(ctx, []asset.ImageBase{
		{ImageID: imgA, BaseImageSource: imagevuln.BaseSourceOSRelease, BaseOS: "Debian:11", ScannedAt: now},
		{ImageID: imgB, BaseImageSource: imagevuln.BaseSourceOSRelease, BaseOS: "Debian:11", ScannedAt: now},
	}))
	require.NoError(t, findings.RecordObserved(ctx, []finding.Finding{{
		ID: p + "-pkg", Source: "supply_chain", Type: "vulnerable_dependency", Severity: finding.SeverityHigh,
		ResourceType: "package", ResourceID: purl, ResourceName: "openssl", Region: "global",
		CheckID: "CVE-2024-5535", DetectedAt: now, Metadata: map[string]string{"ecosystem": "Debian:11"},
	}}))

	w := &BaseImageWorker{assets: assets, findings: findings, catalogue: imagevuln.DefaultCatalogue()}
	require.NoError(t, w.Work(ctx, &river.Job[RefreshBaseImagesArgs]{}))

	got, err := findings.ByResourceIDs(ctx, []string{imgA, imgB})
	require.NoError(t, err)
	byCheck := map[string][]finding.Finding{}
	for _, f := range got {
		if f.Source == baseImageSource {
			byCheck[f.CheckID] = append(byCheck[f.CheckID], f)
		}
	}
	require.Len(t, byCheck["container-image-os-end-of-life"], 2, "both running Debian 11 images")
	require.Len(t, byCheck[baseImageGroupCheckID], 1, "one root cause for the shared base")
	g := byCheck[baseImageGroupCheckID][0]
	require.Equal(t, imgA, g.ResourceID, "on the exposed member")
	require.Equal(t, "2", g.Metadata["running_images"])
	require.Equal(t, "1", g.Metadata["base_layer_cves"])
	require.Equal(t, "1", g.Metadata["exposed_workloads"])
}
