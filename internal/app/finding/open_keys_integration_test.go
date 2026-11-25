//go:build integration

package finding

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestOpenKeysByConnector_LatestVersionDecides proves the post-aggregation
// filters read each id's NEWEST version: a finding re-tagged by another
// connector, moved to another region, or resolved since is judged on that
// newest row, never on an older one still on disk. Requires `docker compose up`
// and applied migrations (graph migrate).
func TestOpenKeysByConnector_LatestVersionDecides(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	// synced_at is second-resolution; an injected clock gives each write a
	// distinct version instead of a tie argMax would break arbitrarily.
	clock := time.Now().Truncate(time.Second).Add(-time.Hour)
	tick := func() time.Time { clock = clock.Add(time.Second); return clock }
	repo := NewCHRepo(ch, WithClock(tick))

	suffix := time.Now().Format("150405.000000")
	res := "openkeys-res-" + suffix
	conn, other := "openkeys-conn-"+suffix, "openkeys-other-"+suffix
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res)
	})

	now := time.Now().Truncate(time.Second)
	mk := func(id, source, region, connector string) Finding {
		f := Finding{
			ID: id + "-" + suffix, Source: source, Type: "threat", Severity: SeverityHigh,
			Title: "t", ResourceID: res, Region: region, CheckID: "Recon:EC2/PortProbeUnprotectedPort",
			DetectedAt: now,
		}
		if connector != "" {
			f.Metadata = map[string]string{ProvenanceConnectorKey: connector}
		}
		return f
	}

	open := mk("open", "aws_guardduty", "eu-west-1", conn)
	moved := mk("moved", "aws_guardduty", "eu-west-1", conn)
	retagged := mk("retagged", "aws_guardduty", "eu-west-1", conn)
	resolved := mk("resolved", "aws_guardduty", "eu-west-1", conn)
	require.NoError(t, repo.Upsert(ctx, []Finding{
		open, moved, retagged, resolved,
		mk("other-source", "cspm", "eu-west-1", conn),
		mk("other-conn", "aws_guardduty", "eu-west-1", other),
		mk("untagged", "aws_guardduty", "eu-west-1", ""),
	}))

	// Newer versions of three of them.
	moved.Region = "us-east-1"
	retagged.Metadata = map[string]string{ProvenanceConnectorKey: other}
	resolved.ResolvedAt, resolved.ResolutionReason = now, ReasonProviderClosed
	require.NoError(t, repo.Upsert(ctx, []Finding{moved, retagged, resolved}))

	keys, err := repo.OpenKeysByConnector(ctx, "aws_guardduty", conn)
	require.NoError(t, err)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ID < keys[j].ID })
	require.Equal(t, []OpenKey{
		{ID: moved.ID, Region: "us-east-1", Type: "threat"},
		{ID: open.ID, Region: "eu-west-1", Type: "threat"},
	}, keys)
}
