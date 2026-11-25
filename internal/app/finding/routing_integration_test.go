//go:build integration

package finding

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations.
// The routing context round-trips through finding_enrichment, the owner and
// environment filters select on it, and the summary facets keep "unowned" and
// "not yet resolved" apart.
func TestCHRepo_RoutingContext(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	src := "routing-" + suffix
	res := "res-routing-" + suffix
	team := "team-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE source = ?", src)
	})

	owned := Finding{ID: "owned-" + suffix, Source: src, Type: "x", Severity: SeverityHigh, Title: "owned",
		ResourceID: res, CheckID: "c-owned", DetectedAt: now, EnrichedAt: now, Score: 70,
		OwnerTeam: team, OwnerSource: "codeowners", OwnerConfidence: "high", Environment: "prod"}
	unowned := Finding{ID: "unowned-" + suffix, Source: src, Type: "x", Severity: SeverityLow, Title: "unowned",
		ResourceID: res, CheckID: "c-unowned", DetectedAt: now, EnrichedAt: now, Score: 20,
		OwnerSource: "none", Environment: "unknown"}
	pending := Finding{ID: "pending-" + suffix, Source: src, Type: "x", Severity: SeverityLow, Title: "pending",
		ResourceID: res, CheckID: "c-pending", DetectedAt: now}
	recordEnriched(t, ch, []Finding{owned, unowned})
	require.NoError(t, repo.Upsert(ctx, []Finding{pending}))

	got, err := repo.Get(ctx, owned.ID)
	require.NoError(t, err)
	require.Equal(t, team, got.OwnerTeam)
	require.Equal(t, "codeowners", got.OwnerSource)
	require.Equal(t, "high", got.OwnerConfidence)
	require.Equal(t, "prod", got.Environment)

	ids := func(fs []Finding) []string {
		out := make([]string, 0, len(fs))
		for _, f := range fs {
			out = append(out, f.ID)
		}
		return out
	}

	byTeam, err := repo.List(ctx, Filter{Owner: team})
	require.NoError(t, err)
	require.Equal(t, []string{owned.ID}, ids(byTeam))
	require.Equal(t, "prod", byTeam[0].Environment, "hydration carries the routing context")

	byUnowned, err := repo.List(ctx, Filter{Owner: OwnerUnowned, ResourceID: res})
	require.NoError(t, err)
	require.Equal(t, []string{unowned.ID}, ids(byUnowned), "unowned selects owner_source=none, never the unresolved backlog")

	byEnv, err := repo.List(ctx, Filter{Environment: "prod", ResourceID: res})
	require.NoError(t, err)
	require.Equal(t, []string{owned.ID}, ids(byEnv))

	all, err := repo.List(ctx, Filter{ResourceID: res})
	require.NoError(t, err)
	require.Len(t, all, 3, "without a routing filter the never-enriched finding still lists")

	sum, err := repo.Summary(ctx, Filter{Source: src})
	require.NoError(t, err)
	require.Equal(t, map[string]int{team: 1, OwnerUnowned: 1, "": 1}, sum.ByOwner)
	require.Equal(t, map[string]int{"prod": 1, "unknown": 1, "": 1}, sum.ByEnvironment)

	// A later enrichment that re-stamps the owner wins (argMax over enriched_at).
	moved := owned
	moved.OwnerTeam, moved.EnrichedAt = "other-"+suffix, now.Add(time.Second)
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{EnrichmentOf(moved)}))
	byTeam, err = repo.List(ctx, Filter{Owner: team})
	require.NoError(t, err)
	require.Empty(t, byTeam, "the superseded owner no longer selects the finding")
}
