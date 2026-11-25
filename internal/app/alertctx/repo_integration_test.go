//go:build integration

package alertctx

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Real ClickHouse: the candidate queries find live assets by id and by
// attribute, and skip dead ephemeral rows. Requires `docker compose up` and
// applied migrations.
func TestCHRepo_Candidates(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	assets := asset.NewService(asset.NewCHRepo(ch))
	repo := NewCHRepo(ch)

	p := "it-alertctx-" + time.Now().Format("150405.000000") + "-"
	now := time.Now().Truncate(time.Second)
	ip := "198.51.100." + time.Now().Format("5")
	host := p + "web.example.com"
	require.NoError(t, assets.Ingest(ctx, []asset.Asset{
		{ID: p + "inst", Name: p + "web", Type: "ec2_instance", Provider: asset.ProviderAWS, PublicIP: ip, Domain: host, DiscoveredAt: now, LastSeen: now},
		{ID: p + "anchor", Name: "anchor", Type: "k8s_pod", Provider: asset.ProviderKubernetes, DiscoveredAt: now, LastSeen: now},
		{ID: p + "deadpod", Name: p + "dead", Type: "k8s_pod", Provider: asset.ProviderKubernetes, PublicIP: ip, DiscoveredAt: now, LastSeen: now.Add(-30 * 24 * time.Hour)},
	}, nil))
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%") })

	live, err := repo.LiveIDs(ctx, []string{p + "inst", p + "deadpod", p + "missing"})
	require.NoError(t, err)
	require.Equal(t, []string{p + "inst"}, live)

	byIP, capped, err := repo.IDsByAttribute(ctx, []string{ip}, nil)
	require.NoError(t, err)
	require.False(t, capped)
	require.Contains(t, byIP, p+"inst")
	require.NotContains(t, byIP, p+"deadpod", "a dead pod must not resolve")

	byName, _, err := repo.IDsByAttribute(ctx, nil, []string{host, "no-such-host.example"})
	require.NoError(t, err)
	require.Equal(t, []string{p + "inst"}, byName)

	// End to end through the service against real rows.
	svc := NewService(repo, assets, fakeBlast{}, fakeFindings{})
	res, err := svc.Context(ctx, []string{p + "inst", ip, host, "10.255.255.254"})
	require.NoError(t, err)
	require.Len(t, res.Identifiers, 4)
	for _, r := range res.Identifiers[:3] {
		require.Equal(t, StatusResolved, r.Status, r.Input)
	}
	require.Equal(t, StatusUnresolved, res.Identifiers[3].Status)
}
