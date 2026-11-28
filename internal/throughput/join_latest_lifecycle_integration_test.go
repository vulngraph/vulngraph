//go:build integration

package throughput

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Unique checks make the expected representative row unambiguous. The oracle
// uses the current observations below, not either SQL implementation.
func latestLifecycleOracle(current []finding.Finding, enrichment map[string]finding.Enrichment) (finding.Summary, []finding.Cluster) {
	s := finding.Summary{BySeverity: map[finding.Severity]int{}, ByBand: map[string]int{}, ByOwner: map[string]int{}, ByEnvironment: map[string]int{}}
	var clusters []finding.Cluster
	for _, f := range current {
		if !f.ResolvedAt.IsZero() {
			continue
		}
		e := enrichment[f.ID]
		owner := e.OwnerTeam
		if e.OwnerSource == "none" {
			owner = "unowned"
		}
		s.Total++
		s.BySeverity[f.Severity]++
		s.ByOwner[owner]++
		s.ByEnvironment[e.Environment]++
		if e.ScoreBand != "" {
			s.ByBand[e.ScoreBand]++
		}
		clusters = append(clusters, finding.Cluster{CheckID: f.CheckID, Title: f.Title, Severity: f.Severity, Source: f.Source, Remediation: f.Remediation, MaxScore: e.Score, WorstBand: e.ScoreBand, Instances: 1, Resources: 1, KnownExploited: e.KnownExploited, LastDetected: f.DetectedAt})
	}
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].CheckID < clusters[j].CheckID })
	return s, clusters
}

func checkLatestRowLifecycle(t *testing.T, ctx context.Context, admin, app *db.CH, experiment string) []string {
	t.Helper()
	candidateMode := "latest_rows"
	if experiment == "latest_enrichment_keys" {
		candidateMode = experiment
	}
	var count uint64
	require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error { require.True(t, rows.Next()); return rows.Scan(&count) }, `SELECT (SELECT count() FROM findings)+(SELECT count() FROM finding_enrichment)`))
	require.Zero(t, count, "lifecycle fixture requires the fresh isolated benchmark database")
	for _, table := range []string{"findings", "finding_enrichment"} {
		require.NoError(t, admin.Exec(ctx, "SYSTEM STOP MERGES "+table))
	}
	defer func() {
		for _, table := range []string{"findings", "finding_enrichment"} {
			require.NoError(t, admin.Exec(ctx, "TRUNCATE TABLE "+table))
		}
	}()
	now := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	version := now
	repo := finding.NewCHRepo(app, finding.WithClock(func() time.Time { return version }))
	current := []finding.Finding{
		{ID: "latest-a", Source: "latest-source", Type: "vulnerability", Severity: finding.SeverityHigh, Title: "A", ResourceID: "r-a", CheckID: "a", Remediation: "fix-a", DetectedAt: now},
		{ID: "latest-b", Source: "latest-source", Type: "vulnerability", Severity: finding.SeverityCritical, Title: "B", ResourceID: "r-b", CheckID: "b", Remediation: "fix-b", DetectedAt: now},
		{ID: "latest-c", Source: "latest-other", Type: "vulnerability", Severity: finding.SeverityLow, Title: "C", ResourceID: "r-c", CheckID: "c", Remediation: "fix-c", DetectedAt: now},
	}
	enrichment := map[string]finding.Enrichment{
		"latest-a": {ID: "latest-a", Score: 20, ScoreBand: "low", OwnerTeam: "alpha", OwnerSource: "tag", Environment: "dev", EnrichedAt: now},
		"latest-b": {ID: "latest-b", Score: 95, ScoreBand: "page", OwnerTeam: "beta", OwnerSource: "tag", Environment: "prod", EnrichedAt: now},
	}
	require.NoError(t, repo.Upsert(ctx, current))
	require.NoError(t, repo.UpsertEnrichment(ctx, []finding.Enrichment{enrichment["latest-a"], enrichment["latest-b"], {ID: "latest-orphan", Score: 100, ScoreBand: "page", EnrichedAt: now}}))
	var steps []string
	check := func(name string) {
		t.Helper()
		wantSummary, wantClusters := latestLifecycleOracle(current, enrichment)
		for _, candidate := range []bool{false, true} {
			var s finding.Summary
			var c []finding.Cluster
			var total int
			var err error
			if candidate {
				s, err = readJoinSummaryCandidate(ctx, app, "", candidateMode)
			} else {
				s, err = readJoinSummaryCandidate(ctx, app, "", "baseline_rows")
			}
			require.NoError(t, err, name)
			require.Equal(t, wantSummary, s, name)
			if candidate {
				c, total, err = readJoinClustersCandidate(ctx, app, "", candidateMode)
			} else {
				c, total, err = readJoinClustersCandidate(ctx, app, "", "baseline_rows")
			}
			require.NoError(t, err, name)
			require.Equal(t, len(wantClusters), total, name)
			sort.Slice(c, func(i, j int) bool { return c[i].CheckID < c[j].CheckID })
			for i := range c {
				c[i].LastDetected = c[i].LastDetected.UTC()
			}
			require.Equal(t, wantClusters, c, name)
		}
		steps = append(steps, name)
	}
	check("initial missing enrichment and orphan")
	newer := enrichment["latest-a"]
	newer.Score = 99
	newer.ScoreBand = "page"
	newer.OwnerTeam = ""
	newer.OwnerSource = "none"
	newer.Environment = "prod"
	newer.KnownExploited = true
	newer.EnrichedAt = now.Add(2 * time.Second)
	require.NoError(t, repo.UpsertEnrichment(ctx, []finding.Enrichment{newer}))
	enrichment[newer.ID] = newer
	check("enrichment-only score ownership and KEV update")
	version = now.Add(3 * time.Second)
	current[1].ResolvedAt = version
	require.NoError(t, repo.Upsert(ctx, []finding.Finding{current[1]}))
	check("latest resolution removes finding")
	version = now.Add(4 * time.Second)
	current[0].Severity = finding.SeverityMedium
	current[0].Title = "updated A"
	require.NoError(t, repo.Upsert(ctx, []finding.Finding{current[0]}))
	check("producer update retains independent enrichment")
	version = now.Add(5 * time.Second)
	current[1].ResolvedAt = time.Time{}
	require.NoError(t, repo.Upsert(ctx, []finding.Finding{current[1]}))
	check("reappearance retains enrichment")
	stale := current[1]
	stale.Severity = finding.SeverityLow
	stale.ResolvedAt = now
	version = now.Add(time.Second)
	require.NoError(t, repo.Upsert(ctx, []finding.Finding{stale}))
	staleEnrichment := newer
	staleEnrichment.Score = 1
	staleEnrichment.ScoreBand = "low"
	staleEnrichment.EnrichedAt = now.Add(time.Second)
	require.NoError(t, repo.UpsertEnrichment(ctx, []finding.Enrichment{staleEnrichment, newer, newer}))
	check("out-of-order producer enrichment and duplicate replay")
	require.NoError(t, admin.Exec(ctx, "SYSTEM START MERGES finding_enrichment"))
	require.NoError(t, admin.Exec(ctx, `ALTER TABLE finding_enrichment DELETE WHERE id='latest-a' SETTINGS mutations_sync=2`))
	delete(enrichment, "latest-a")
	check("removed enrichment returns unknown bucket")
	return steps
}
