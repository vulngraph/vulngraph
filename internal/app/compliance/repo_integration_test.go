//go:build integration

package compliance

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Samples returns one live asset per (provider, type, reduced evidence), its
// metadata holding only the evidence keys: a key nothing reads is projected
// away, a value evaluability does not read is ” (decodable rule lists are
// one shape), and an undecodable rule list is its own sample.
func TestCHInventory_SamplesOnePerEvidenceShape(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	marker := "compliance_it_" + suffix
	ids := []string{"cmp-it-a-" + suffix, "cmp-it-b-" + suffix, "cmp-it-c-" + suffix}
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id IN (?, ?, ?)", ids[0], ids[1], ids[2]) })
	now := time.Now()
	require.NoError(t, asset.NewService(asset.NewCHRepo(ch)).IngestAssets(ctx, []asset.Asset{
		{ID: ids[0], Provider: asset.ProviderAWS, Type: "security_group", Name: "a", LastSeen: now,
			Metadata: map[string]string{marker: "1", "ingress": `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["10.0.0.0/8"]}]`, "unread": "x"}},
		{ID: ids[1], Provider: asset.ProviderAWS, Type: "security_group", Name: "b", LastSeen: now,
			Metadata: map[string]string{"unread": "y", "ingress": "[]", marker: "2"}},
		{ID: ids[2], Provider: asset.ProviderAWS, Type: "security_group", Name: "c", LastSeen: now,
			Metadata: map[string]string{marker: "1", "ingress": "{not json", "unread": "x"}},
	}))

	samples, err := NewCHInventory(ch).Samples(ctx, EvidenceSpec{Types: []string{"security_group"}, Keys: []string{"ingress", marker}})
	require.NoError(t, err)
	ingress := map[string]int{}
	for _, a := range samples {
		require.Equal(t, "security_group", a.Type)
		if v, ok := a.Metadata[marker]; ok {
			require.Equal(t, asset.ProviderAWS, a.Provider)
			require.NotContains(t, a.Metadata, "unread", "keys nothing reads are projected away")
			require.Empty(t, v, "a value nothing reads is presence only")
			ingress[a.Metadata["ingress"]]++
		}
	}
	require.Equal(t, map[string]int{"[]": 1, "{not json": 1}, ingress)
}

// A probe set's values are kept only on an asset missing one of its keys
// (Evaluable then runs the predicate over the present values); with the whole
// set present they are presence only.
func TestCHInventory_SamplesKeepProbedValues(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	marker := "compliance_it_p_" + suffix
	ids := []string{"cmp-it-p1-" + suffix, "cmp-it-p2-" + suffix, "cmp-it-p3-" + suffix, "cmp-it-p4-" + suffix}
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id IN (?, ?, ?, ?)", ids[0], ids[1], ids[2], ids[3])
	})
	now := time.Now()
	eip := func(id string, md map[string]string) asset.Asset {
		md[marker] = "1"
		return asset.Asset{ID: id, Provider: asset.ProviderAWS, Type: "elastic_ip", Name: id, LastSeen: now, Metadata: md}
	}
	require.NoError(t, asset.NewService(asset.NewCHRepo(ch)).IngestAssets(ctx, []asset.Asset{
		eip(ids[0], map[string]string{"association_id": "a1", "instance_id": "i-1"}),
		eip(ids[1], map[string]string{"association_id": "a2", "instance_id": "i-2"}),
		eip(ids[2], map[string]string{"instance_id": "i-3"}),
		eip(ids[3], map[string]string{"instance_id": "i-4"}),
	}))

	samples, err := NewCHInventory(ch).Samples(ctx, EvidenceSpec{
		Types:  []string{"elastic_ip"},
		Keys:   []string{"association_id", "instance_id", marker},
		Probes: []ProbeSet{{Provider: "aws", Type: "elastic_ip", Keys: []string{"association_id", "instance_id"}}},
	})
	require.NoError(t, err)
	var mine []map[string]string
	for _, a := range samples {
		if _, ok := a.Metadata[marker]; ok {
			mine = append(mine, a.Metadata)
		}
	}
	require.ElementsMatch(t, []map[string]string{
		{"association_id": "", "instance_id": "", marker: ""},
		{"instance_id": "i-3", marker: ""},
		{"instance_id": "i-4", marker: ""},
	}, mine)
}

// An asset re-synced with a different key set is sampled at its LATEST
// version only (argMax per id): a superseded row must not surface an
// evidence key the collector no longer writes.
func TestCHInventory_SamplesLatestVersion(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	marker := "compliance_it_v_" + suffix
	id := "cmp-it-v-" + suffix
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", id) })
	svc := asset.NewService(asset.NewCHRepo(ch))
	now := time.Now()
	require.NoError(t, svc.IngestAssets(ctx, []asset.Asset{{ID: id, Provider: asset.ProviderAWS, Type: "s3_bucket", Name: "v",
		LastSeen: now, Metadata: map[string]string{marker: "1", "stale_key": "x"}}}))
	time.Sleep(1100 * time.Millisecond) // synced_at has second resolution
	require.NoError(t, svc.IngestAssets(ctx, []asset.Asset{{ID: id, Provider: asset.ProviderAWS, Type: "s3_bucket", Name: "v",
		LastSeen: now.Add(time.Second), Metadata: map[string]string{marker: "2"}}}))

	samples, err := NewCHInventory(ch).Samples(ctx, EvidenceSpec{Types: []string{"s3_bucket"}, Keys: []string{marker, "stale_key"}})
	require.NoError(t, err)
	var mine []map[string]string
	for _, a := range samples {
		if _, ok := a.Metadata[marker]; ok {
			mine = append(mine, a.Metadata)
		}
	}
	require.Len(t, mine, 1)
	require.NotContains(t, mine[0], "stale_key")
}

// Two principals with the same key set but different privilege tiers are two
// samples: CIEM evaluability reads the tier value, and one any(metadata) over
// both would answer from whichever row ClickHouse happened to read.
func TestCHInventory_SamplesSplitByPrivilegeTier(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	marker := "compliance_it_t_" + suffix
	ids := []string{"cmp-it-t1-" + suffix, "cmp-it-t2-" + suffix}
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id IN (?, ?)", ids[0], ids[1]) })
	now := time.Now()
	require.NoError(t, asset.NewService(asset.NewCHRepo(ch)).IngestAssets(ctx, []asset.Asset{
		{ID: ids[0], Provider: asset.ProviderAWS, Type: "iam_user", Name: "a", LastSeen: now,
			Metadata: map[string]string{marker: "1", "privilege_tier": "standard", "privilege_tier_source": "ciem"}},
		{ID: ids[1], Provider: asset.ProviderAWS, Type: "iam_user", Name: "b", LastSeen: now,
			Metadata: map[string]string{marker: "2", "privilege_tier": "unknown", "privilege_tier_source": "no_permission_data"}},
	}))

	samples, err := NewCHInventory(ch).Samples(ctx, EvidenceSpec{Types: []string{"iam_user"}, Keys: []string{marker, "privilege_tier"}, ValueKeys: []string{"privilege_tier"}})
	require.NoError(t, err)
	tiers := map[string]bool{}
	for _, a := range samples {
		if _, ok := a.Metadata[marker]; ok {
			tiers[a.Metadata["privilege_tier"]] = true
		}
	}
	require.Equal(t, map[string]bool{"standard": true, "unknown": true}, tiers)
}
