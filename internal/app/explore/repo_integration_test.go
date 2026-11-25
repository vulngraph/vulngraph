//go:build integration

package explore

import (
	"context"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_SeedAndNeighbors(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	p := "ex-" + time.Now().Format("150405.000000") + "-"
	web, sg := p+"web", p+"sg"
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
		_ = ch.Exec(ctx, "ALTER TABLE graph_edges DELETE WHERE src_id LIKE ?", p+"%")
	})

	// Seed two assets + one edge directly.
	require.NoError(t, ch.Batch(ctx, `INSERT INTO assets
		(id, name, type, provider, region, account_id, endpoint, public_ip, private_ip,
		 domain, tags, metadata, risk_score, discovered_at, last_seen, synced_at)`,
		func(b driver.Batch) error {
			_ = b.Append(web, "web", "ec2_instance", "aws", "eu-west-1", "111122223333", "", "1.2.3.4", "", "",
				map[string]string{}, "{}", uint8(0), now, now, now)
			return b.Append(sg, "sg", "security_group", "aws", "eu-west-1", "111122223333", "", "", "", "",
				map[string]string{}, "{}", uint8(0), now, now, now)
		}))
	require.NoError(t, ch.Batch(ctx,
		`INSERT INTO graph_edges (src_id, src_type, dst_id, dst_type, edge_type, properties, synced_at)`,
		func(b driver.Batch) error {
			return b.Append(web, "ec2_instance", sg, "security_group", "protected_by", "{}", now)
		}))

	svc := NewService(repo)

	res, err := svc.Run(ctx, GraphQuerySpec{
		Seed:     NodeMatch{IDs: []string{web}},
		Traverse: []Traverse{{Direction: DirectionOut, MaxHops: 1}},
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{web, sg}, ids(res))
	require.Len(t, res.Edges, 1)
	require.Equal(t, "protected_by", res.Edges[0].EdgeType)

	// account_id is surfaced on result nodes (drives the UI "group by account").
	for _, n := range res.Nodes {
		require.Equal(t, "111122223333", n.AccountID, "node %s should carry its account_id", n.ID)
	}

	// Seed by type/provider match also finds the instance.
	byType, err := svc.Run(ctx, GraphQuerySpec{Seed: NodeMatch{Types: []string{"ec2_instance"}, Provider: "aws"}})
	require.NoError(t, err)
	var found bool
	for _, n := range byType.Nodes {
		if n.ID == web {
			found = true
		}
	}
	require.True(t, found)
}
