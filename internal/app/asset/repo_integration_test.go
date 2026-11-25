//go:build integration

package asset

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_AssetsEdgesAndBlastRadius(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	// Namespace this run's IDs so concurrent/repeat runs don't collide.
	p := "it-" + time.Now().Format("150405.000000") + "-"
	web, sg, db1 := p+"web", p+"sg", p+"db"
	now := time.Now().Truncate(time.Second)

	assets := []Asset{
		{ID: web, Name: "web", Type: "ec2_instance", Provider: ProviderAWS, Region: "eu-west-1",
			PublicIP: "1.2.3.4", Tags: map[string]string{"env": "prod"}, Metadata: map[string]string{"ami": "ami-1"},
			RiskScore: 70, DiscoveredAt: now, LastSeen: now},
		{ID: sg, Name: "sg", Type: "security_group", Provider: ProviderAWS, DiscoveredAt: now, LastSeen: now},
		{ID: db1, Name: "db", Type: "rds_instance", Provider: ProviderAWS, DiscoveredAt: now, LastSeen: now},
	}
	edges := []Edge{
		{SrcID: web, SrcType: "ec2_instance", DstID: sg, DstType: "security_group", EdgeType: "protected_by"},
		{SrcID: web, SrcType: "ec2_instance", DstID: db1, DstType: "rds_instance", EdgeType: "can_access",
			Properties: map[string]string{"port": "5432"}},
	}
	require.NoError(t, svc.Ingest(ctx, assets, edges))
	t.Cleanup(func() {
		// Best-effort: lightweight mutations clear this run's rows.
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
		_ = ch.Exec(ctx, "ALTER TABLE graph_edges DELETE WHERE src_id LIKE ?", p+"%")
	})

	got, err := svc.Get(ctx, web)
	require.NoError(t, err)
	require.Equal(t, "web", got.Name)
	require.Equal(t, uint8(70), got.RiskScore)
	require.Equal(t, "prod", got.Tags["env"])
	require.Equal(t, "ami-1", got.Metadata["ami"])

	_, err = svc.Get(ctx, p+"absent")
	require.ErrorIs(t, err, ErrNotFound)

	br, err := svc.BlastRadius(ctx, web, 2)
	require.NoError(t, err)
	ids := assetIDs(br)
	require.ElementsMatch(t, []string{web, sg, db1}, ids)
	require.Len(t, br.Edges, 2)
	require.False(t, br.Truncated)

	// Reverse blast radius: db1 is only reached BY web, and reaches nothing.
	out, err := svc.BlastRadiusDir(ctx, db1, 2, DirOut)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{db1}, assetIDs(out), "db reaches nothing outward")
	in, err := svc.BlastRadiusDir(ctx, db1, 2, DirIn)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{db1, web}, assetIDs(in), "web can reach db")

	// List returns the inventory (includes our three).
	all, err := svc.List(ctx, Filter{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(all), 3)

	// ListExternal returns only internet-facing assets — web has a public IP,
	// sg/db do not.
	ext, err := svc.ListExternal(ctx, 0)
	require.NoError(t, err)
	var sawWeb, sawSG bool
	for _, a := range ext {
		if a.ID == web {
			sawWeb = true
		}
		if a.ID == sg {
			sawSG = true
		}
	}
	require.True(t, sawWeb, "web (public IP) is internet-facing")
	require.False(t, sawSG, "security group is not internet-facing")

	// ListByType returns only assets of the requested type.
	byType, err := svc.ListByType(ctx, "rds_instance", 0)
	require.NoError(t, err)
	var sawDB bool
	for _, a := range byType {
		require.Equal(t, "rds_instance", a.Type)
		if a.ID == db1 {
			sawDB = true
		}
	}
	require.True(t, sawDB, "db appears in its type listing")

	// ExistingIDs (the dangling sweep's existence check) must find
	// every live id in a realistic-sized batch and report only the truly absent
	// one missing — a batch existence check that silently drops a live id
	// would auto-resolve findings (e.g. GuardDuty) on a running resource. Pad the batch to the sweep's real page width (200) so a
	// regression that only reproduces at scale (e.g. IN-list truncation) would
	// show up here too.
	batch := make([]string, 0, 200)
	batch = append(batch, web, sg, db1, p+"absent")
	for i := 0; i < 196; i++ {
		batch = append(batch, p+"filler-"+strconv.Itoa(i))
	}
	existing, err := svc.ExistingIDs(ctx, batch)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{web, sg, db1}, existing,
		"every live id in the batch is reported existing, and only the genuinely absent ones are missing")

	// first_discovered_at survives re-collection against
	// real ClickHouse: web's true first observation was `now`; simulate the
	// next sweep re-stamping DiscoveredAt (every real collector does this),
	// and confirm FirstDiscoveredAt does NOT move.
	require.NoError(t, svc.Ingest(ctx, []Asset{{
		ID: web, Name: "web", Type: "ec2_instance", Provider: ProviderAWS,
		DiscoveredAt: now.Add(time.Hour), LastSeen: now.Add(time.Hour),
	}}, nil))
	got, err = svc.Get(ctx, web)
	require.NoError(t, err)
	require.WithinDuration(t, now, got.FirstDiscoveredAt, time.Second,
		"FirstDiscoveredAt must not move on re-collection even though DiscoveredAt/LastSeen do")
}
