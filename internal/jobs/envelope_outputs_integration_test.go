//go:build integration

package jobs

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
)

func envelopeNativeCount(t *testing.T, ctx context.Context, graph *graphstore.Service, query string) int64 {
	t.Helper()
	result, err := graph.RunCypher(ctx, query, 10, 10)
	require.NoError(t, err)
	require.Len(t, result.Rows, 1)
	n, ok := result.Rows[0]["n"].(int64)
	require.True(t, ok, "native count must be a measured integer")
	return n
}

func envelopeVerifyNative(t *testing.T, ctx context.Context, graph *graphstore.Service, sizes []int, wave int, baseline int64) int64 {
	t.Helper()
	var resources int64
	for _, n := range sizes {
		resources += int64(n)
	}
	if wave == 4 {
		resources -= int64(len(sizes))
	}
	nodes := envelopeNativeCount(t, ctx, graph, "MATCH (n) RETURN count(n) AS n")
	require.Equal(t, resources+baseline, nodes, "actual native nodes include baseline sentinels and schema rows")
	edges := envelopeNativeCount(t, ctx, graph, "MATCH ()-[e]->() RETURN count(e) AS n")
	require.Equal(t, resources-int64(len(sizes)), edges)
	// ExecutesAs carries risk toward the role, never back toward the source.
	// Each workload must therefore retain its exact independently known base
	// contribution, including after changed findings and graph score refreshes.
	score := 60
	if wave >= 2 {
		score = 80
	}
	wrongScores := envelopeNativeCount(t, ctx, graph, fmt.Sprintf(`MATCH (a:Asset)
 WHERE a.id STARTS WITH 'envelope-' AND a.id <> 'envelope-stable'
 AND ((a.id ENDS WITH '01' AND a.score <> %d) OR (NOT (a.id ENDS WITH '01') AND a.score <> 0))
 RETURN count(a) AS n`, score))
	require.Zero(t, wrongScores, "native workload scores must reflect the current derived generation")
	wrong := envelopeNativeCount(t, ctx, graph, "MATCH (a:Asset)-[:ExecutesAs]->(r:IamRole) WHERE a.account_id <> r.account_id RETURN count(a) AS n")
	require.Zero(t, wrong, "relationships must retain their original account")
	counts, err := graph.RunCypher(ctx, "MATCH (a:Asset)-[e:ExecutesAs]->(r:IamRole) RETURN r.id AS id, count(e) AS edges, count(DISTINCT a.id) AS sources", len(sizes)+10, len(sizes)+10)
	require.NoError(t, err)
	require.Len(t, counts.Rows, len(sizes))
	byRole := make(map[string]int64, len(sizes))
	for c, n := range sizes {
		want := int64(n - 1)
		if wave == 4 {
			want--
		}
		byRole[envelopeID(c, 0)] = want
	}
	for _, row := range counts.Rows {
		id, ok := row["id"].(string)
		require.True(t, ok)
		want, exists := byRole[id]
		require.True(t, exists, id)
		require.Equal(t, want, row["edges"], id)
		require.Equal(t, want, row["sources"], id)
		delete(byRole, id)
	}
	require.Empty(t, byRole)
	return nodes
}

func envelopeVerifyFindings(t *testing.T, ctx context.Context, findings *finding.Service, sizes []int, wave int) {
	t.Helper()
	ids := make([]string, 0, 500)
	wantResources := map[string]string{}
	deleted := map[string]bool{}
	verify := func() {
		got, err := findings.ByIDs(ctx, ids)
		require.NoError(t, err)
		require.Len(t, got, len(ids))
		for _, f := range got {
			require.Equal(t, wantResources[f.ID], f.ResourceID)
			require.Equal(t, deleted[f.ID], f.Resolved(), f.ID)
			severity := finding.SeverityHigh
			if wave >= 2 {
				severity = finding.SeverityCritical
			}
			require.Equal(t, severity, f.Severity, f.ID)
			delete(wantResources, f.ID)
			delete(deleted, f.ID)
		}
		require.Empty(t, wantResources)
		ids = ids[:0]
	}
	for c, n := range sizes {
		for i := 1; i < n; i += 100 {
			resource := envelopeID(c, i)
			id := "finding-" + resource
			ids = append(ids, id)
			wantResources[id] = resource
			deleted[id] = wave == 4 && i == 1
			if len(ids) == 500 {
				verify()
			}
		}
	}
	if len(ids) > 0 {
		verify()
	}
}
