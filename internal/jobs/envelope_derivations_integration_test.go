//go:build integration

package jobs

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestEnvelopeDerivedState(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("isolated derived-state replay")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	chA, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 8)
	require.NoError(t, err)
	defer chA.Close()
	chB, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 8)
	require.NoError(t, err)
	defer chB.Close()
	a := asset.NewService(asset.NewCHRepo(chA))
	b := asset.NewService(asset.NewCHRepo(chB))
	findings := finding.NewService(finding.NewCHRepo(chA))
	base := asset.Asset{ID: "derived-barrier", Type: "ec2_instance", Name: "revision-0", Provider: asset.ProviderAWS, RiskScore: 5,
		DiscoveredAt: time.Now().Add(-time.Minute), LastSeen: time.Now(), Metadata: map[string]string{"revision": "0", "untouched": "value"}}
	require.NoError(t, a.Ingest(ctx, []asset.Asset{base}, nil))
	old, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	// A different process/service commits the new observation after derivation
	// started, before it publishes. No sleeps or scheduler luck are involved.
	base.Name = "revision-1"
	base.Metadata["revision"] = "1"
	base.LastSeen = time.Now()
	require.NoError(t, b.Ingest(ctx, []asset.Asset{base}, nil))
	require.ErrorContains(t, a.PublishFindingRisk(ctx, old, map[string]uint8{"": 60}), "reserved")
	require.NoError(t, a.PublishFindingRisk(ctx, old, map[string]uint8{base.ID: 60}))
	assertAsset := func(score uint8) {
		got, e := b.Get(ctx, base.ID)
		require.NoError(t, e)
		require.Equal(t, base.Name, got.Name)
		require.Equal(t, base.Metadata, got.Metadata)
		require.Equal(t, score, got.RiskScore)
		require.WithinDuration(t, base.LastSeen, got.LastSeen, time.Nanosecond)
	}
	assertAsset(60)
	page, err := b.List(ctx, asset.Filter{MinScore: 60, Limit: 25})
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, base.ID, page[0].ID)
	// Same generation/content is immutable and replayable without join fanout.
	require.NoError(t, a.PublishFindingRisk(ctx, old, map[string]uint8{base.ID: 60}))
	page, err = b.List(ctx, asset.Filter{MinScore: 60, Limit: 25})
	require.NoError(t, err)
	require.Len(t, page, 1)
	// Rows from an interrupted generation are invisible until its marker.
	incomplete, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, chA.Batch(ctx, "INSERT INTO asset_finding_risk (generation,digest,id,risk_score)", func(batch driver.Batch) error {
		return batch.Append(incomplete, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", base.ID, uint8(80))
	}))
	assertAsset(60)
	newer, err := b.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, b.PublishFindingRisk(ctx, newer, map[string]uint8{}))
	assertAsset(5)
	require.NoError(t, a.PublishFindingRisk(ctx, old, map[string]uint8{base.ID: 60}))
	assertAsset(5)
	page, err = b.List(ctx, asset.Filter{MinScore: 60, Limit: 25})
	require.NoError(t, err)
	require.Empty(t, page)
	// The production severity rollup publishes current unresolved risk, and
	// resolves it without replacing the collector's own base contribution.
	f := finding.Finding{ID: "derived-finding", Source: "envelope", ResourceID: base.ID, Type: "misconfiguration", Severity: finding.SeverityCritical, Title: "observed", DetectedAt: time.Now()}
	require.NoError(t, findings.Record(ctx, []finding.Finding{f}))
	require.NoError(t, scoreAssetsFromFindings(ctx, findings, a))
	assertAsset(80)
	require.NoError(t, findings.Resolve(ctx, []finding.Finding{f}, finding.ReasonFixed))
	require.NoError(t, scoreAssetsFromFindings(ctx, findings, a))
	assertAsset(5)
	manifest := asset.Asset{ID: "derived-manifest", Name: "new-declaration", Type: "declared_k8s_workload", Provider: asset.ProviderGitHub,
		DiscoveredAt: time.Now().Add(-time.Minute), LastSeen: time.Now(), Metadata: map[string]string{"manifest_key": "deployment/default/app", "live_type": "k8s_deployment", "namespace": "default", "opaque": "keep"}}
	require.NoError(t, b.Ingest(ctx, []asset.Asset{manifest}, nil))
	v1, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	annotation := asset.Annotation{ID: manifest.ID, Source: asset.ManifestDriftSource, InputKey: "deployment/default/app\x00k8s_deployment\x00default", Metadata: map[string]string{"drift": "declared_not_live"}}
	require.NoError(t, a.WriteAnnotations(ctx, v1, []asset.Annotation{annotation}))
	got, err := b.Get(ctx, manifest.ID)
	require.NoError(t, err)
	require.Equal(t, "keep", got.Metadata["opaque"])
	require.Equal(t, "declared_not_live", got.Metadata["drift"])
	// A changed declaration ignores old interpretation even if its producer
	// finishes later; unrelated metadata and the newest name remain intact.
	manifest.Name = "changed-declaration"
	manifest.Metadata["manifest_key"] = "deployment/default/other"
	require.NoError(t, b.Ingest(ctx, []asset.Asset{manifest}, nil))
	require.NoError(t, a.WriteAnnotations(ctx, v1, []asset.Annotation{annotation}))
	got, err = b.Get(ctx, manifest.ID)
	require.NoError(t, err)
	require.Equal(t, manifest.Name, got.Name)
	require.NotContains(t, got.Metadata, "drift")
	manifest.Metadata["manifest_key"] = "deployment/default/app"
	require.NoError(t, b.Ingest(ctx, []asset.Asset{manifest}, nil))
	v2, err := b.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	clear := annotation
	clear.Metadata = map[string]string{"drift": ""}
	require.NoError(t, b.WriteAnnotations(ctx, v2, []asset.Annotation{clear}))
	require.NoError(t, a.WriteAnnotations(ctx, v1, []asset.Annotation{annotation}))
	got, err = b.Get(ctx, manifest.ID)
	require.NoError(t, err)
	require.NotContains(t, got.Metadata, "drift")
	require.Equal(t, "keep", got.Metadata["opaque"])
	assertAsset(5)
	// The authoritative storage rows never received either derived score or
	// drift, so background merges cannot resurrect a stale copied observation.
	var rawScore uint8
	require.NoError(t, chA.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return rows.Err()
		}
		return rows.Scan(&rawScore)
	}, "SELECT argMax(risk_score,synced_at) FROM assets WHERE id=?", base.ID))
	require.Equal(t, uint8(5), rawScore)
}
